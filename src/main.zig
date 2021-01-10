const std = @import("std");
const debug = std.debug;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;

const max_clients = 1;
const delay = 10 * time.ns_per_s;
const port = 22;

const Session = struct {
    socket: os.socket_t,
    socket_writer: SocketWriter,

    send_next: i64,
};

fn createServer() !os.socket_t {
    const sockfd = try os.socket(os.AF_UNSPEC, os.SOCK_STREAM, 0);

    // Enable reuseaddr if possible
    os.setsockopt(
        sockfd,
        os.SOL_SOCKET,
        os.SO_REUSEADDR,
        &mem.toBytes(@as(c_int, 1)),
    ) catch {};

    // Disable IPv6 only
    try os.setsockopt(
        sockfd,
        os.IPPROTO_IPV6,
        26, // TODO(vincent): this is IPV6_V6ONLY but it's not defined yet in Zig's stdlib
        &mem.toBytes(@as(c_int, 0)),
    );

    const addr = net.Address.initIp4([_]u8{ 0x7F, 0x00, 0x00, 0x01 }, port);

    try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr_in));
    try os.listen(sockfd, std.math.maxInt(u31));

    return sockfd;
}

fn socketWrite(fd: os.socket_t, bytes: []const u8) os.WriteError!usize {
    return os.write(fd, bytes);
}

const SocketWriter = io.Writer(os.socket_t, os.WriteError, socketWrite);

const logger = std.log.scoped(.main);

pub fn main() anyerror!void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) {
        debug.panic("leaks detected", .{});
    };

    var arena = heap.ArenaAllocator.init(&gpa.allocator);
    defer arena.deinit();
    var allocator = &arena.allocator;

    var sessions = std.ArrayList(Session).init(allocator);

    // Create the server
    const server_sockfd = try createServer();

    // Accept connections indefinitely
    while (true) {
        // Enqueue clients
        var timeout: i32 = -1;
        const now = time.timestamp();
        for (sessions.items) |session| {
            if (session.send_next <= now) {
                // TODO(vincent): send random line
                _ = try session.socket_writer.writeAll("foobar");

                logger.debug("wrote line for socket {}", .{session.socket});
            } else {
                timeout = @intCast(i32, session.send_next - now);

                logger.debug("timeout: {}", .{timeout});

                break;
            }
        }

        // Wait for next event

        var fd = .{
            .fd = server_sockfd,
            .events = os.POLLIN,
            .revents = 0,
        };

        _ = try os.poll(&[_]os.pollfd{fd}, timeout);
        if (fd.revents & os.POLLIN == os.POLLIN) {
            const client_fd = try os.accept(
                server_sockfd,
                null,
                null,
                os.SOCK_NONBLOCK,
            );

            logger.info("accepted client {}", .{client_fd});

            var session = .{
                .socket = client_fd,
                .socket_writer = .{ .context = client_fd },

                .send_next = time.timestamp() + delay,
            };

            try sessions.append(session);
        }
    }
}
