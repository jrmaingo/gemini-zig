const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const c = @cImport({
    @cInclude("mbedtls/ssl.h");
    @cInclude("mbedtls/net_sockets.h");
    @cInclude("mbedtls/entropy.h");
    @cInclude("mbedtls/ctr_drbg.h");
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

    fn init(url: []const u8) Self {
        assert(url.len > 0 and urlPrefix.len + url.len <= maxUrlLen);

        const requestLen = urlPrefix.len + url.len + requestSuffix.len;
        var requestBuf: [requestBufLen]u8 = undefined;

        // TODO handle error
        _ = std.fmt.bufPrint(requestBuf[0..], "{}{}{}", .{ urlPrefix, url, requestSuffix }) catch unreachable;

        return Self{
            .requestBuf = requestBuf,
            .requestLen = requestLen,
        };
    }

    fn getUrl(self: *const Self) []const u8 {
        const urlLen = self.requestLen - requestSuffix.len;
        return self.requestBuf[0..urlLen];
    }

    fn getBytes(self: *const Self) []const u8 {
        return self.requestBuf[0..self.requestLen];
    }
};

const GeminiError = error{Unknown};

fn debugLog(ctx: ?*c_void, level: c_int, file: ?[*:0]const u8, line: c_int, msg: ?[*:0]const u8) callconv(.C) void {
    std.log.err("{} {}:{} {}", .{ level, file.?, line, msg });
}

fn printCrtInfo(crt: *const c.mbedtls_x509_crt) void {
    var infoBuf = [_:0]u8{0} ** 1024;
    const crt_prefix: [:0]const u8 = "crt info: ";
    var res = c.mbedtls_x509_crt_info(&infoBuf, @sizeOf(@TypeOf(infoBuf)), crt_prefix, crt);
    assert(res > 0);
    std.log.err("{}", .{infoBuf[0..@intCast(usize, res)]});

    if (crt.*.next) |next| {
        printCrtInfo(next);
    }
}

fn verify(ctx: ?*c_void, crt: ?*c.mbedtls_x509_crt, cert_depth: c_int, flags: ?*u32) callconv(.C) c_int {
    // crt info
    printCrtInfo(crt.?);

    // cert depth
    std.log.err("depth: {}", .{cert_depth});

    // verify info
    var infoBuf = [_:0]u8{0} ** 1024;
    const verify_prefix: [:0]const u8 = "verify info: ";
    const res = c.mbedtls_x509_crt_verify_info(&infoBuf, @sizeOf(@TypeOf(infoBuf)), verify_prefix, flags.?.*);
    assert(res > 0);
    std.log.err("{}", .{infoBuf[0..@intCast(usize, res)]});
    // only return non-zero on fatal error
    return 0;
}

pub fn main() anyerror!void {
    // TODO take input instead
    const dest = "gemini.circumlunar.space/";
    const request = Request.init(dest);
    std.log.info("loading {}", .{request.getUrl()});

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    // need to use a buffer since zig treats as opaque type
    // size taken from C
    const configSize: usize = 384;
    var configBuf: [configSize]u8 = undefined;

    var ssl_config = @ptrCast(*c.mbedtls_ssl_config, &configBuf);
    c.mbedtls_ssl_config_init(ssl_config);
    var res = c.mbedtls_ssl_config_defaults(ssl_config, c.MBEDTLS_SSL_IS_CLIENT, c.MBEDTLS_SSL_TRANSPORT_STREAM, c.MBEDTLS_SSL_PRESET_DEFAULT);
    if (res != 0) {
        return GeminiError.Unknown;
    }
    defer c.mbedtls_ssl_config_free(ssl_config);

    c.mbedtls_ssl_conf_dbg(ssl_config, debugLog, null);

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
    c.mbedtls_ssl_conf_rng(ssl_config, c.mbedtls_ctr_drbg_random, &rng_ctx);
    defer c.mbedtls_ctr_drbg_free(&rng_ctx);

    // setup ca chain
    const c_crt_path: [:0]const u8 = "/etc/ssl/certs/";
    var ca_chain: c.mbedtls_x509_crt = undefined;
    c.mbedtls_x509_crt_init(&ca_chain);
    defer c.mbedtls_x509_crt_free(&ca_chain);
    res = c.mbedtls_x509_crt_parse_path(&ca_chain, c_crt_path);
    if (res != 0) {
        return GeminiError.Unknown;
    }
    printCrtInfo(&ca_chain);
    // TODO do I need a revocation list?
    const ca_crl: ?*c.mbedtls_x509_crl = null;
    c.mbedtls_ssl_conf_ca_chain(ssl_config, &ca_chain, ca_crl);

    c.mbedtls_ssl_conf_verify(ssl_config, verify, null);

    // create ssl context
    var ssl_ctx: c.mbedtls_ssl_context = undefined;
    c.mbedtls_ssl_init(&ssl_ctx);
    defer c.mbedtls_ssl_free(&ssl_ctx);

    res = c.mbedtls_ssl_setup(&ssl_ctx, ssl_config);
    if (res != 0) {
        return GeminiError.Unknown;
    }

    // set hostname
    const c_dest: [:0]const u8 = "gemini.circumlunar.space";
    const c_port: [:0]const u8 = "1965";
    res = c.mbedtls_ssl_set_hostname(&ssl_ctx, c_dest);
    if (res != 0) {
        return GeminiError.Unknown;
    }

    // create socket
    var socket: c.mbedtls_net_context = undefined;
    c.mbedtls_net_init(&socket);
    res = c.mbedtls_net_connect(&socket, c_dest, c_port, c.MBEDTLS_NET_PROTO_TCP);
    if (res != 0) {
        std.log.err("socket error: {x}", .{res});
        return GeminiError.Unknown;
    }
    defer c.mbedtls_net_free(&socket);

    c.mbedtls_ssl_set_bio(&ssl_ctx, &socket, c.mbedtls_net_send, c.mbedtls_net_recv, c.mbedtls_net_recv_timeout);

    c.mbedtls_ssl_set_hs_ca_chain(&ssl_ctx, &ca_chain, ca_crl);

    // do handshake
    res = c.mbedtls_ssl_handshake(&ssl_ctx);
    if (res != 0) {
        std.log.err("handshake error: {x}", .{res});
        return GeminiError.Unknown;
    }
}

test "create request" {
    const dest = "gemini://gemini.circumlunar.space/";
    const request = Request.init(dest);
    expect(std.mem.eql(u8, dest, request.getUrl()));
}
