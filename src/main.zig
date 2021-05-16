const std = @import("std");
const assert = std.debug.assert;
const expect = std.testing.expect;
const c = @cImport({
    @cInclude("openssl/ssl.h");
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

pub fn main() anyerror!void {
    // TODO take input instead
    const dest = "gemini.circumlunar.space/";
    const request = Request.init(dest);
    std.log.info("loading {}", .{request.getUrl()});

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    const ssl = c.SSL_CTX_new(c.TLS_client_method());
    defer c.SSL_CTX_free(ssl);

    //var socket = try std.net.tcpConnectToHost(allocator, dest, defaultPort);
    //defer socket.close();

    // TODO TLS handshake
}

test "create request" {
    const dest = "gemini://gemini.circumlunar.space/";
    const request = Request.init(dest);
    expect(std.mem.eql(u8, dest, request.getUrl()));
}
