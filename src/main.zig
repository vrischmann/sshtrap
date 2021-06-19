const std = @import("std");
const debug = std.debug;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;

const max_clients = 4096;
const delay = 10000;
const port = 22;

const Session = struct {
    addr: net.Address,
    socket: os.socket_t,
    socket_writer: SocketWriter,

    statistics: struct {
        connect_time: i64,
        bytes_sent: usize,
    },

    send_next: i64,
};

fn createServer() !os.socket_t {
    const sockfd = try os.socket(os.AF_INET6, os.SOCK_STREAM, 0);
    errdefer os.close(sockfd);

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
        os.linux.IPV6_V6ONLY,
        &mem.toBytes(@as(c_int, 0)),
    );

    const addr = try net.Address.parseIp6("::0", port);

    try os.bind(sockfd, &addr.any, @sizeOf(os.sockaddr_in6));
    try os.listen(sockfd, std.math.maxInt(u31));

    return sockfd;
}

fn socketWrite(fd: os.socket_t, bytes: []const u8) os.WriteError!usize {
    const rc = os.linux.write(fd, bytes.ptr, bytes.len);
    return switch (os.errno(rc)) {
        0 => @intCast(usize, rc),
        else => error.BrokenPipe,
    };
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

    // Create a PRNG

    var rng = std.rand.DefaultPrng.init(@intCast(u64, time.milliTimestamp()));

    // Ignore broken pipes
    var act = os.Sigaction{
        .handler = .{
            .sigaction = os.SIG_IGN,
        },
        .mask = os.empty_sigset,
        .flags = 0,
    };
    os.sigaction(os.SIGPIPE, &act, null);

    // Create the server
    const server_sockfd = try createServer();

    // Accept connections indefinitely
    while (true) {
        // Write random data for sessions that are due for another message.
        const now = time.milliTimestamp();

        var i: usize = 0;
        while (i < sessions.items.len) : (i += 1) {
            var session = &sessions.items[i];
            if (session.send_next > now) continue;

            // Create random message
            var message_buffer: [32]u8 = undefined;
            rng.random.bytes(&message_buffer);

            session.socket_writer.writeAll(&message_buffer) catch |err| {
                logger.info("CLOSE host={} port={} fd={} elapsed={d:.3} bytes={} error={}", .{
                    session.addr,
                    session.addr.getPort(),
                    session.socket,
                    @intToFloat(f32, now - session.statistics.connect_time) / 1e3,
                    session.statistics.bytes_sent,
                    err,
                });

                // Remove the current session
                _ = sessions.orderedRemove(i);
                if (i > 0) i -= 1;

                continue;
            };

            session.send_next = now + delay;
            session.statistics.bytes_sent += message_buffer.len;
        }

        // Compute the earliest timeout
        const timeout: i32 = blk: {
            if (sessions.items.len <= 0) break :blk -1;

            var earliest_timeout: i32 = std.math.maxInt(i32);
            for (sessions.items) |session| {
                earliest_timeout = std.math.min(
                    earliest_timeout,
                    @intCast(i32, session.send_next - now),
                );
            }
            break :blk earliest_timeout;
        };

        // Wait for next event

        var fds = [_]os.pollfd{.{
            .fd = server_sockfd,
            .events = os.POLLIN,
            .revents = 0,
        }};

        const events = if (sessions.items.len < max_clients)
            try os.poll(&fds, timeout)
        else
            try os.poll(&[_]os.pollfd{}, timeout);
        if (events < 1) {
            // No event, retry
            continue;
        }

        var fd = &fds[0];
        if (fd.revents & os.POLLIN == os.POLLIN) {
            var client_addr: net.Address = undefined;
            var client_addr_len: os.socklen_t = @sizeOf(net.Address);

            const client_fd = try os.accept(
                server_sockfd,
                &client_addr.any,
                &client_addr_len,
                os.SOCK_NONBLOCK,
            );

            logger.info("ACCEPT host={} port={} fd={} n={}/{}", .{
                client_addr,
                client_addr.getPort(),
                client_fd,
                sessions.items.len + 1,
                max_clients,
            });

            const now2 = time.milliTimestamp();

            // Set the smallest possible receive buffer.
            try os.setsockopt(
                client_fd,
                os.SOL_SOCKET,
                os.SO_RCVBUF,
                &mem.toBytes(@as(c_int, 1)),
            );

            var socket_writer = .{ .context = client_fd };
            var session = Session{
                .addr = client_addr,
                .socket = client_fd,
                .socket_writer = socket_writer,

                .statistics = .{
                    .connect_time = now2,
                    .bytes_sent = 0,
                },

                .send_next = now2 + delay,
            };
            try sessions.append(session);
        }
    }
}
