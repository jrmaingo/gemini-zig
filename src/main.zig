const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const c = @cImport({
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/net_sockets.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ctr_drbg.h");
    @cInclude("mbedtls/debug.h");
});

const defaultPort: u16 = 1965;

const Request = struct {
    requestBuf: [requestBufLen]u8,
    requestLen: usize,

    const Self = @This();
    const urlPrefix = "gemini://";
    const maxUrlLen = 1024;
    const requestSuffix = "\u{0D}\u{0A}";
    const requestBufLen = maxUrlLen + requestSuffix.len;

    // create the request, handshake must be complete before calling send
    fn init(url: []const u8) Self {
        assert(url.len > 0 and urlPrefix.len + url.len <= maxUrlLen);

        const requestLen = urlPrefix.len + url.len + requestSuffix.len;
        var requestBuf: [requestBufLen]u8 = undefined;

        // TODO handle error
        _ = std.fmt.bufPrint(requestBuf[0..], "{s}{s}{s}", .{ urlPrefix, url, requestSuffix }) catch unreachable;

        return Self{
            .requestBuf = requestBuf,
            .requestLen = requestLen,
        };
    }

    // complete URL for this request
    fn getUrl(self: *const Self) []const u8 {
        const urlLen = self.requestLen - requestSuffix.len;
        return self.requestBuf[0..urlLen];
    }

    // request payload
    fn getBytes(self: *const Self) []const u8 {
        return self.requestBuf[0..self.requestLen];
    }
};

const Response = struct {
    data: [buffer_size]u8,
    bytes_read: usize,

    const Self = @This();
    const buffer_size = 1024;

    fn getSlice(self: *const Self) []const u8 {
        return self.*.data[0..self.*.bytes_read];
    }
};

const GeminiError = error{ Unknown, Closed };

fn debugLog(ctx: ?*anyopaque, level: c_int, file: ?[*:0]const u8, line: c_int, msg: ?[*:0]const u8) callconv(.C) void {
    _ = ctx;
    const logLiteral = "{s}:{} {s}";
    const logParams = .{ file.?, line, msg };
    switch (level) {
        1 => std.log.err(logLiteral, logParams),
        2 => std.log.warn(logLiteral, logParams),
        3 => std.log.info(logLiteral, logParams),
        else => std.log.debug(logLiteral, logParams),
    }
}

fn printCrtInfo(crt: *const c.mbedtls_x509_crt) void {
    var infoBuf = [_:0]u8{0} ** 1024;
    const crt_prefix: [:0]const u8 = "crt info: ";
    var res = c.mbedtls_x509_crt_info(&infoBuf, @sizeOf(@TypeOf(infoBuf)), crt_prefix, crt);
    assert(res > 0);
    std.log.info("{s}", .{infoBuf[0..@intCast(usize, res)]});

    if (crt.*.next) |next| {
        printCrtInfo(next);
    }
}

fn chainLen(ca_chain: ?*const c.mbedtls_x509_crt) i32 {
    if (ca_chain == null) {
        return 0;
    }
    return 1 + chainLen(ca_chain.?.*.next);
}

fn chainContains(ca_chain: *const c.mbedtls_x509_crt, crt: *const c.mbedtls_x509_crt) bool {
    var next: ?*const c.mbedtls_x509_crt = ca_chain;
    while (next) |cur| : (next = cur.*.next) {
        if (cur.sig.len == crt.sig.len and std.mem.eql(u8, cur.sig.p[0..cur.sig.len], crt.sig.p[0..crt.sig.len])) {
            assert(crt.raw.len != 0);
            assert(cur.raw.len == crt.raw.len);
            assert(std.mem.eql(u8, cur.raw.p[0..crt.raw.len], crt.raw.p[0..crt.raw.len]));
            return true;
        }
    }
    return false;
}

fn appendCrt(ca_chain: *c.mbedtls_x509_crt, crt: *c.mbedtls_x509_crt) void {
    // only append self-signed certs
    assert(std.mem.eql(u8, crt.*.issuer_raw.p[0..crt.*.issuer_raw.len], crt.*.subject_raw.p[0..crt.*.subject_raw.len]));
    const oldLen = chainLen(ca_chain);
    const buf = crt.raw;
    var res = c.mbedtls_x509_crt_parse(ca_chain, buf.p, buf.len);
    assert(res == 0);
    assert(chainLen(ca_chain) == oldLen + 1);

    // sanity check
    var flags: u32 = undefined;
    res = c.mbedtls_x509_crt_verify(crt, ca_chain, null, null, &flags, null, null);
    assert(res == 0);
    assert(flags == 0);
}

fn verify(ctx: ?*anyopaque, crt: ?*c.mbedtls_x509_crt, cert_depth: c_int, flags: ?*u32) callconv(.C) c_int {
    // this is the same chain that is used for handshake
    const ca_chain = @ptrCast(*c.mbedtls_x509_crt, @alignCast(@alignOf(*c.mbedtls_x509_crt), ctx.?));

    // crt info
    printCrtInfo(crt.?);

    // cert depth
    std.log.info("depth: {}", .{cert_depth});

    // verify info
    var infoBuf = [_:0]u8{0} ** 1024;
    const flagsVal = flags.?.*;
    const verify_prefix: [:0]const u8 = "verify info: ";
    const res = c.mbedtls_x509_crt_verify_info(&infoBuf, @sizeOf(@TypeOf(infoBuf)), verify_prefix, flagsVal);
    if (res == 0) {
        std.log.info("no verify info string", .{});
    } else if (res > 0) {
        std.log.info("{s}", .{infoBuf[0..@intCast(usize, res)]});
    } else {
        std.log.err("error while writing verify info", .{});
    }

    if (flagsVal == 0) {
        std.log.info("verification succeeded", .{});
    } else if (flagsVal == c.MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
        // TODO we should really ask the user first
        const subjectBuf = crt.?.subject.val;
        const subject = subjectBuf.p[0..subjectBuf.len];
        std.log.warn("trusting self-signed crt for {s}", .{subject});
        // add cert to chain so it passes verification next time
        appendCrt(ca_chain, crt.?);
        // clear flags so it passes verification this time
        flags.?.* = 0;
    } else {
        std.log.err("verify flags: {}", .{flagsVal});
    }

    // only return non-zero on fatal error
    return 0;
}

const TLSContext = struct {
    ssl_ctx: c.mbedtls_ssl_context,
    net_ctx: ?c.mbedtls_net_context,

    const Self = @This();

    fn init(ssl_config: *const c.mbedtls_ssl_config) anyerror!Self {
        var result = Self{
            .ssl_ctx = undefined,
            .net_ctx = null,
        };
        c.mbedtls_ssl_init(&result.ssl_ctx);

        const res = c.mbedtls_ssl_setup(&result.ssl_ctx, ssl_config);
        if (res != 0) {
            return GeminiError.Unknown;
        }

        return result;
    }

    fn connect(self: *Self, c_dest: [:0]const u8, c_port: [:0]const u8) anyerror!void {
        assert(self.*.net_ctx == null);

        // workaround, no easy way to pass in a pointer to an optional struct field
        var net_ctx: c.mbedtls_net_context = undefined;
        c.mbedtls_net_init(&net_ctx);

        self.*.net_ctx = net_ctx;
        var socket = &self.*.net_ctx.?;
        const res = c.mbedtls_net_connect(socket, c_dest, c_port, c.MBEDTLS_NET_PROTO_TCP);
        if (res != 0) {
            std.log.err("socket error: {x}", .{res});
            self.*.net_ctx = null;
            return GeminiError.Unknown;
        }

        c.mbedtls_ssl_set_bio(&self.ssl_ctx, socket, c.mbedtls_net_send, c.mbedtls_net_recv, c.mbedtls_net_recv_timeout);
    }

    // TODO add reset as well once it's needed
    fn handshake(self: *Self) anyerror!void {
        std.log.info("starting handshake...", .{});
        const res = c.mbedtls_ssl_handshake(&self.*.ssl_ctx);
        if (res == 0) {
            std.log.info("handshake success!", .{});
        } else {
            const verify_result = c.mbedtls_ssl_get_verify_result(&self.*.ssl_ctx);
            std.log.err("handshake error: {x}, verify result: {x}", .{ res, verify_result });
            return GeminiError.Unknown;
        }
    }

    fn disconnect(self: *Self) void {
        if (self.*.net_ctx) |*net_ctx| {
            c.mbedtls_net_free(net_ctx);
            self.*.net_ctx = null;
        }
    }

    fn read(self: *Self) anyerror!Response {
        var data = std.mem.zeroes([1024]u8);
        const res = c.mbedtls_ssl_read(&self.*.ssl_ctx, &data, data.len);
        if (res > 0) {
            std.log.info("response received {}\n", .{res});
        } else if (res == c.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            return GeminiError.Closed;
        } else {
            std.log.err("response read error {}\n", .{res});
            return GeminiError.Unknown;
        }

        return Response{
            .bytes_read = @intCast(usize, res),
            .data = data,
        };
    }

    // send the request
    fn send(self: *Self, request: *const Request) anyerror!void {
        std.log.info("sending request to {s}\n", .{request.*.getUrl()});
        const request_data = request.*.getBytes();
        const res = c.mbedtls_ssl_write(&self.*.ssl_ctx, request_data.ptr, request_data.len);
        if (res != request_data.len) {
            std.log.err("request error, only wrote {} bytes\n", .{res});
            return GeminiError.Unknown;
        } else {
            std.log.info("sent request", .{});
        }
    }

    fn destroy(self: *Self) void {
        self.disconnect();
        c.mbedtls_ssl_free(&self.*.ssl_ctx);
    }
};

// just hard-code some max arg value for now
const ArgArray = std.BoundedArray([:0]const u8, 1024);

const Options = struct {
    output_file_path: ?[:0]const u8 = null,
    is_verbose: bool = false,

    // no easy way to define a literal with different sentinel
    const output_file_flag = [_:0]u8{ '-', 'o' };
    const verbose_flag = [_:0]u8{ '-', 'v' };

    fn parseArgs(arg_array: ArgArray) Options {
        var options = Options{};
        for (arg_array.constSlice()) |arg, i| {
            if (std.mem.eql(u8, output_file_flag[0..output_file_flag.len], arg)) {
                // assume that output file is specified
                options.output_file_path = arg_array.get(i + 1);
            } else if (std.mem.eql(u8, verbose_flag[0..verbose_flag.len], arg)) {
                options.is_verbose = true;
            }
        }
        return options;
    }
};

pub fn main() anyerror!void {
    var args = std.process.args();
    var arg_array = try ArgArray.init(0);
    while (args.nextPosix()) |arg| {
        try arg_array.append(arg);
        std.log.info("arg: {s}", .{arg});
    }

    // excludes the domain, no trailing '/'
    // eg. gemini.circumlunar.space
    assert(arg_array.len >= 2);

    const dest = arg_array.pop();
    const options = Options.parseArgs(arg_array);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    var ssl_config: c.mbedtls_ssl_config = undefined;
    c.mbedtls_ssl_config_init(&ssl_config);
    var res = c.mbedtls_ssl_config_defaults(&ssl_config, c.MBEDTLS_SSL_IS_CLIENT, c.MBEDTLS_SSL_TRANSPORT_STREAM, c.MBEDTLS_SSL_PRESET_DEFAULT);
    if (res != 0) {
        return GeminiError.Unknown;
    }
    defer c.mbedtls_ssl_config_free(&ssl_config);

    // TODO hide debug logs by default
    c.mbedtls_debug_set_threshold(1);
    c.mbedtls_ssl_conf_dbg(&ssl_config, debugLog, null);

    // setup rng
    var entropy_ctx: c.mbedtls_entropy_context = undefined;
    c.mbedtls_entropy_init(&entropy_ctx);
    defer c.mbedtls_entropy_free(&entropy_ctx);

    var rng_ctx: c.mbedtls_ctr_drbg_context = undefined;
    c.mbedtls_ctr_drbg_init(&rng_ctx);
    res = c.mbedtls_ctr_drbg_seed(&rng_ctx, c.mbedtls_entropy_func, &entropy_ctx, null, 0);
    if (res != 0) {
        std.log.err("rng seed error: {x}", .{res});
        return GeminiError.Unknown;
    }
    c.mbedtls_ssl_conf_rng(&ssl_config, c.mbedtls_ctr_drbg_random, &rng_ctx);
    defer c.mbedtls_ctr_drbg_free(&rng_ctx);

    // setup ca chain
    // TODO store and load previously trusted certs
    const c_crt_path: [:0]const u8 = "/etc/ssl/certs/";
    var ca_chain: c.mbedtls_x509_crt = undefined;
    c.mbedtls_x509_crt_init(&ca_chain);
    defer c.mbedtls_x509_crt_free(&ca_chain);
    res = c.mbedtls_x509_crt_parse_path(&ca_chain, c_crt_path);
    if (res != 0) {
        return GeminiError.Unknown;
    }
    //printCrtInfo(&ca_chain);
    // TODO do I need a revocation list?
    const ca_crl: ?*c.mbedtls_x509_crl = null;
    c.mbedtls_ssl_conf_ca_chain(&ssl_config, &ca_chain, ca_crl);

    c.mbedtls_ssl_conf_verify(&ssl_config, verify, &ca_chain);

    // create ssl context
    var tls_ctx = try TLSContext.init(&ssl_config);
    defer tls_ctx.destroy();

    // set hostname
    const hostname = std.mem.split(u8, dest, "/").next().?;
    const c_hostname = try std.cstr.addNullByte(allocator, hostname);
    defer allocator.free(c_hostname);
    std.log.info("hostname: {s}", .{c_hostname});
    const c_dest: [:0]const u8 = c_hostname;
    const c_port: [:0]const u8 = "1965";
    res = c.mbedtls_ssl_set_hostname(&tls_ctx.ssl_ctx, c_dest);
    if (res != 0) {
        return GeminiError.Unknown;
    }

    try tls_ctx.connect(c_dest, c_port);
    try tls_ctx.handshake();

    // send request
    const request = Request.init(dest);
    try tls_ctx.send(&request);

    // read response_header
    const response_header = try tls_ctx.read();

    // parse response header
    const status_str = response_header.data[0..2];
    const status = try std.fmt.parseUnsigned(u8, status_str, 10);

    assert(res < 1024);
    const sentinel_index = std.mem.indexOf(u8, response_header.data[0..response_header.bytes_read], Request.requestSuffix);
    if (sentinel_index == null) {
        std.log.err("response missing sentinel\n", .{});
        return GeminiError.Unknown;
    }
    const meta_str = response_header.data[3..sentinel_index.?];
    std.log.info("response code {d}, meta: {s}\n", .{ status, meta_str });

    // TODO cleanup or avoid making it if stdout
    var cwd_path = std.mem.zeroes([1024]u8);
    var cwd = try std.fs.openDirAbsolute(try std.os.getcwd(cwd_path[0..]), .{});
    defer cwd.close();

    const file = if (options.output_file_path) |output_file_path| blk: {
        // TODO support absolute paths too
        break :blk try cwd.createFile(output_file_path, .{});
    } else blk: {
        // TODO separate logging when writing to stdout
        break :blk std.io.getStdOut();
    };
    defer if (options.output_file_path != null) {
        file.close();
    };

    // read reponse body
    var response_size: usize = 0;
    while (tls_ctx.read()) |response_body| {
        response_size += response_body.bytes_read;
        const bytes_written = try file.write(response_body.getSlice());
        assert(bytes_written == response_body.bytes_read);
        if (response_body.bytes_read < response_body.data.len) {
            std.log.info("done reading response body", .{});
            break;
        }
    } else |err| {
        switch (err) {
            GeminiError.Unknown => std.log.err("failed to read response body {}", .{err}),
            GeminiError.Closed => std.log.info("done reading response body {}", .{err}),
            else => unreachable,
        }
        return err;
    }

    std.log.info("done!", .{});
}

test "create request" {
    const dest = "gemini://gemini.circumlunar.space/";
    const request = Request.init(dest);
    try expect(std.mem.eql(u8, dest, request.getUrl()));
}
