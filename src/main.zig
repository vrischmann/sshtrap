const std = @import("std");
const debug = std.debug;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;

const IO_Uring = std.os.linux.IO_Uring;
const io_uring_cqe = std.os.linux.io_uring_cqe;

const max_connections = 1024;
const max_ring_entries = 512;
const max_buffer_size = 4096;
const delay = 10000;
const port = 22;

const Completion = struct {
    const Self = @This();

    ring: *IO_Uring,
    operation: Operation,

    fn prep(self: *Self) !void {
        switch (self.operation) {
            .accept => |*op| {
                _ = try self.ring.accept(
                    @ptrToInt(self),
                    op.socket,
                    &op.addr,
                    &op.addr_len,
                    0,
                );
            },
            .recv => |*op| {
                _ = try self.ring.recv(
                    @ptrToInt(self),
                    op.socket,
                    op.buffer,
                    0,
                );
            },
            .send => |*op| {
                _ = try self.ring.send(
                    @ptrToInt(self),
                    op.socket,
                    op.buffer,
                    0,
                );
            },
            .close => |*op| {
                _ = try self.ring.close(
                    @ptrToInt(self),
                    op.socket,
                );
            },
            .timeout => |*op| {
                _ = try self.ring.timeout(
                    @ptrToInt(self),
                    &op.timespec,
                    0,
                    0,
                );
            },
        }
    }
};

const Operation = union(enum) {
    accept: struct {
        socket: os.socket_t,
        addr: os.sockaddr,
        addr_len: os.socklen_t = @sizeOf(os.sockaddr),
    },
    recv: struct {
        socket: os.socket_t,
        buffer: []u8,
    },
    send: struct {
        socket: os.socket_t,
        buffer: []const u8,
    },
    close: struct {
        socket: os.socket_t,
    },
    timeout: struct {
        timespec: os.__kernel_timespec,
    },
};

const Connection = struct {
    const Self = @This();

    state: enum {
        free,
        accepting,
        connected,
    } = .free,

    recv_completion: Completion = undefined,
    send_completion: Completion = undefined,
    timeout_completion: Completion = undefined,

    addr: net.Address = net.Address{
        .any = .{
            .family = os.AF_INET6,
            .data = [_]u8{0} ** 14,
        },
    },
    socket: os.socket_t = -1,
    buffer: []u8 = undefined,

    statistics: struct {
        connect_time: i64 = 0,
        bytes_sent: usize = 0,
    } = .{},

    fn prep_recv(self: *Self, ring: *IO_Uring) !void {
        self.recv_completion = .{
            .ring = ring,
            .operation = .{
                .recv = .{
                    .socket = self.socket,
                    .buffer = self.buffer,
                },
            },
        };
        try self.recv_completion.prep();
    }

    fn prep_send(self: *Self, ring: *IO_Uring, buffer: []const u8) !void {
        self.send_completion = .{
            .ring = ring,
            .operation = .{
                .send = .{
                    .socket = self.socket,
                    .buffer = buffer,
                },
            },
        };
        try self.send_completion.prep();
    }

    fn prep_close(self: *Self, ring: *IO_Uring) !void {
        self.send_completion = .{
            .ring = ring,
            .operation = .{
                .close = .{
                    .socket = self.socket,
                },
            },
        };
        try self.send_completion.prep();
    }

    fn prep_timeout(self: *Self, ring: *IO_Uring, timeout: i64) !void {
        self.timeout_completion = .{
            .ring = ring,
            .operation = .{
                .timeout = .{
                    .timespec = .{
                        .tv_sec = 0,
                        .tv_nsec = timeout,
                    },
                },
            },
        };
        try self.timeout_completion.prep();
    }
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

const logger = std.log.scoped(.main);

pub fn main() anyerror!void {
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit()) {
        debug.panic("leaks detected", .{});
    };

    var arena = heap.ArenaAllocator.init(&gpa.allocator);
    defer arena.deinit();
    var allocator = &arena.allocator;

    // Prepare state
    var connections = try allocator.alloc(Connection, max_connections);
    mem.set(Connection, connections, .{});
    for (connections) |*connection| {
        connection.buffer = try allocator.alloc(u8, max_buffer_size);
    }

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
    const server_fd = try createServer();

    // Create the ring

    var cqes: [max_ring_entries]io_uring_cqe = undefined;

    var ring = try std.os.linux.IO_Uring.init(max_ring_entries, 0);
    defer ring.deinit();

    // Accept connections indefinitely

    var accept_completion: Completion = .{
        .ring = &ring,
        .operation = .{
            .accept = .{
                .socket = server_fd,
                .addr = undefined,
            },
        },
    };
    try accept_completion.prep();

    while (true) {
        const now = std.time.milliTimestamp();

        // Process CQEs

        const count = try ring.copy_cqes(cqes[0..], 0);
        var i: usize = 0;

        while (i < count) : (i += 1) {
            const cqe = cqes[i];

            const completion = @intToPtr(*Completion, cqe.user_data);
            switch (completion.operation) {
                .accept => |*op| {
                    if (cqe.res < 0) {
                        switch (-cqe.res) {
                            os.EPIPE => std.debug.print("EPIPE {}\n", .{cqe}),
                            os.ECONNRESET => std.debug.print("ECONNRESET {}\n", .{cqe}),
                            else => std.debug.print("ERROR {}\n", .{cqe}),
                        }
                        os.exit(1);
                    }

                    const now2 = time.milliTimestamp();

                    // Get a connection object and initialize all state.
                    //
                    // If no connection is free we don't do anything.
                    var connection = for (connections) |*conn| {
                        if (conn.state == .free) {
                            conn.state = .accepting;
                            break conn;
                        }
                    } else {
                        logger.warn("no free connection available", .{});

                        // Enqueue a new accept request.
                        try accept_completion.prep();

                        continue;
                    };
                    connection.addr = net.Address{ .any = op.addr };
                    connection.socket = @intCast(os.socket_t, cqe.res);

                    logger.info("ACCEPT fd={} host={} port={}", .{
                        connection.socket,
                        connection.addr,
                        connection.addr.getPort(),
                    });

                    // Enqueue a timeout request for the first write.
                    try connection.prep_timeout(&ring, delay * std.time.ns_per_ms);
                    // Enqueue a new accept request.
                    try accept_completion.prep();
                },
                .recv => |*op| {
                    const connection = @fieldParentPtr(Connection, "recv_completion", completion);

                    // handle errors
                    if (cqe.res <= 0) {
                        switch (-cqe.res) {
                            os.EPIPE => logger.info("RECV fd={} broken pipe", .{connection.socket}),
                            0 => logger.info("RECV fd={} end of file", .{connection.socket}),
                            else => logger.warn("RECV fd={} errno {d}", .{ connection.socket, cqe.res }),
                        }
                        try connection.prep_close(&ring);
                        continue;
                    }

                    const size = @intCast(usize, cqe.res);
                    const data = connection.buffer[0..size];

                    logger.info("RECV host={} port={} fd={} data={s}/{s} ({s})", .{
                        connection.addr,
                        connection.addr.getPort(),
                        connection.socket,
                        std.fmt.fmtSliceHexLower(data),
                        mem.trimRight(u8, data, "\r\n"),
                        std.fmt.fmtIntSizeBin(data.len),
                    });

                    try connection.prep_recv(&ring);
                },
                .send => |*op| {
                    const connection = @fieldParentPtr(Connection, "send_completion", completion);

                    // handle errors
                    if (cqe.res <= 0) {
                        switch (-cqe.res) {
                            os.EPIPE => logger.info("SEND host={} port={} fd={} broken pipe", .{
                                connection.addr,
                                connection.addr.getPort(),
                                op.socket,
                            }),
                            os.ECONNRESET => logger.info("SEND host={} port={} fd={} reset by peer pipe", .{
                                connection.addr,
                                connection.addr.getPort(),
                                op.socket,
                            }),
                            0 => logger.info("SEND host={} port={} fd={} end of file", .{
                                connection.addr,
                                connection.addr.getPort(),
                                op.socket,
                            }),
                            else => logger.warn("SEND host={} port={} fd={} errno {d}", .{
                                connection.addr,
                                connection.addr.getPort(),
                                op.socket,
                                cqe.res,
                            }),
                        }
                        try connection.prep_close(&ring);
                        continue;
                    }

                    logger.info("SEND host={} port={} fd={} data={s}", .{
                        connection.addr,
                        connection.addr.getPort(),
                        op.socket,
                        std.fmt.fmtIntSizeBin(@intCast(u64, cqe.res)),
                    });

                    // Enqueue a timeout request for the next write.
                    try connection.prep_timeout(&ring, delay * std.time.ns_per_ms);
                },
                .close => |*op| {
                    var connection = @fieldParentPtr(Connection, "send_completion", completion);

                    logger.info("CLOSE host={} port={} fd={}", .{
                        connection.addr,
                        connection.addr.getPort(),
                        op.socket,
                    });

                    // TODO(vincent): refactor into a struct ?
                    const buffer = connection.buffer;
                    connection.* = .{};
                    connection.buffer = buffer;
                },
                .timeout => {
                    const connection = @fieldParentPtr(Connection, "timeout_completion", completion);

                    const banner = blk: {
                        var banner_buffer: [4]u8 = undefined;
                        rng.random.bytes(&banner_buffer);

                        break :blk try std.fmt.bufPrint(
                            connection.buffer,
                            "{s}",
                            .{std.fmt.fmtSliceHexLower(&banner_buffer)},
                        );
                    };

                    // Enqueue a send request
                    try connection.prep_send(&ring, banner);
                },
            }
        }

        _ = try ring.submit_and_wait(1);
    }
}
