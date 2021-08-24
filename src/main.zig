const std = @import("std");
const debug = std.debug;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const mem = std.mem;
const net = std.net;
const os = std.os;
const time = std.time;

const assert = debug.assert;

const IO_Uring = std.os.linux.IO_Uring;
const io_uring_cqe = std.os.linux.io_uring_cqe;

const argsParser = @import("args");

const max_ring_entries = 512;
const max_buffer_size = 4096;

const Completion = struct {
    const Self = @This();

    ring: *IO_Uring,
    operation: Operation,
    parent: enum {
        global,
        connection,
    } = .global,

    fn prep(self: *Self) !void {
        // logger.debug("prep {s} user data={d}", .{
        //     fmt.fmtSliceEscapeUpper(@tagName(self.operation)),
        //     @ptrToInt(self),
        // });

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
                    op.count,
                    0,
                );
            },
            .timeout_remove => {
                _ = try self.ring.timeout_remove(
                    @ptrToInt(self),
                    0,
                    0,
                );
            },
        }
    }

    fn prepAccept(self: *Self, ring: *IO_Uring, socket: os.socket_t) !void {
        self.* = .{
            .ring = ring,
            .operation = .{
                .accept = .{
                    .socket = socket,
                    .addr = undefined,
                },
            },
        };
        try self.prep();
    }

    fn prepTimeout(self: *Self, ring: *IO_Uring, timeout: u63) !void {
        self.* = .{
            .ring = ring,
            .operation = .{
                .timeout = .{
                    .timespec = .{
                        .tv_sec = 0,
                        .tv_nsec = timeout,
                    },
                    .count = 0,
                },
            },
        };
        try self.prep();
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
        count: u32,
    },
    timeout_remove: struct {},
};

const Connection = struct {
    const Self = @This();

    state: enum {
        free,
        connected,
        terminating,
    } = .free,

    recv_completion: Completion = undefined,
    send_completion: Completion = undefined,
    timeout_completion: Completion = undefined,
    close_completion: Completion = undefined,

    addr: net.Address = net.Address{
        .any = .{
            .family = os.AF_INET,
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
                    .buffer = self.buffer[0..128],
                },
            },
            .parent = .connection,
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
            .parent = .connection,
        };
        try self.send_completion.prep();
    }

    fn prep_close(self: *Self, ring: *IO_Uring) !void {
        self.close_completion = .{
            .ring = ring,
            .operation = .{
                .close = .{
                    .socket = self.socket,
                },
            },
            .parent = .connection,
        };
        try self.close_completion.prep();
    }

    fn prep_timeout(self: *Self, ring: *IO_Uring, timeout: u63) !void {
        self.timeout_completion = .{
            .ring = ring,
            .operation = .{
                .timeout = .{
                    .timespec = .{
                        .tv_sec = 0,
                        .tv_nsec = timeout,
                    },
                    .count = 0,
                },
            },
            .parent = .connection,
        };
        try self.timeout_completion.prep();
    }

    fn prep_remove_timeout(self: *Self, ring: *IO_Uring) !void {
        self.timeout_completion = .{
            .ring = ring,
            .operation = .{
                .timeout_remove = .{},
            },
            .parent = .connection,
        };
        try self.timeout_completion.prep();
    }
};

fn createServer(port: u16) !os.socket_t {
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

    // Parse options
    const options = try argsParser.parseForCurrentProcess(struct {
        port: u16 = 22,
        delay: u63 = 10000,
        @"max-connections": usize = 1024,

        @"debug-iterations": ?usize = null,

        pub const shorthands = .{
            .p = "port",
            .d = "delay",
            .c = "max-connections",
        };
    }, allocator, .print);
    defer options.deinit();

    if (options.options.port <= 0) {
        logger.err("invalid port {d}", .{options.options.port});
        return error.InvalidPort;
    }

    // Prepare state
    var connections = try allocator.alloc(Connection, options.options.@"max-connections");
    for (connections) |*connection| {
        connection.* = .{
            .buffer = try allocator.alloc(u8, max_buffer_size),
        };
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
    const server_fd = try createServer(options.options.port);

    logger.info("server fd is {}", .{server_fd});

    // Create the ring

    var cqes: [max_ring_entries]io_uring_cqe = undefined;

    var ring = try std.os.linux.IO_Uring.init(max_ring_entries, 0);
    defer ring.deinit();

    // Accept connections indefinitely
    var global_accept: struct {
        completion: Completion = undefined,
        has_timeout: bool = false,
    } = .{};
    try global_accept.completion.prepAccept(&ring, server_fd);

    var i: usize = 0;
    loop: while (true) : (i += 1) {
        if (options.options.@"debug-iterations") |iter| {
            if (i >= iter) break :loop;
        }

        // Process CQEs
        const count = try ring.copy_cqes(cqes[0..], 0);

        for (cqes[0..count]) |cqe| {
            if (cqe.user_data == 0) {
                continue;
            }

            const completion = @intToPtr(*Completion, cqe.user_data);
            switch (completion.operation) {
                .accept => |*op| {
                    assert(completion.parent == .global);

                    if (cqe.res < 0) {
                        switch (@intToEnum(os.E, -cqe.res)) {
                            .PIPE => logger.warn("ACCEPT broken pipe", .{}),
                            .CONNRESET => logger.warn("ACCEPT connection reset by peer", .{}),
                            .MFILE => logger.warn("ACCEPT too many open files", .{}),
                            else => {
                                logger.err("ERROR {}\n", .{cqe});
                                os.exit(1);
                            },
                        }

                        if (!global_accept.has_timeout) {
                            global_accept.has_timeout = true;
                            try global_accept.completion.prepTimeout(&ring, 1000 * time.ns_per_ms);
                        }
                    } else {
                        // Get a connection object and initialize all state.
                        //
                        // If no connection is free we don't do anything.
                        var connection = for (connections) |*conn| {
                            if (conn.state == .free) {
                                conn.state = .connected;
                                break conn;
                            }
                        } else {
                            logger.warn("no free connection available", .{});

                            // Enqueue a new accept request
                            try global_accept.completion.prepAccept(&ring, server_fd);
                            continue;
                        };

                        connection.addr = net.Address{ .any = op.addr };
                        connection.socket = @intCast(os.socket_t, cqe.res);
                        connection.statistics.connect_time = time.milliTimestamp();

                        logger.info("ACCEPT fd={} host={}", .{
                            connection.socket,
                            connection.addr,
                        });

                        // Enqueue a timeout request for the first write.
                        try connection.prep_timeout(&ring, options.options.delay * std.time.ns_per_ms);
                        // Enqueue a new recv request for the banner
                        try connection.prep_recv(&ring);
                        // Enqueue a new accept request
                        try global_accept.completion.prepAccept(&ring, server_fd);
                    }
                },
                .recv => |*op| {
                    assert(completion.parent == .connection);

                    var connection = @fieldParentPtr(Connection, "recv_completion", completion);
                    assert(connection.state == .connected);

                    // handle errors
                    if (cqe.res <= 0) {
                        if (cqe.res == 0) {
                            logger.info("RECV host={} fd={} end of file", .{
                                connection.addr,
                                op.socket,
                            });
                        } else {
                            switch (@intToEnum(os.E, -cqe.res)) {
                                .PIPE => logger.info("RECV host={} fd={} broken pipe", .{
                                    connection.addr,
                                    op.socket,
                                }),
                                .CONNRESET => logger.info("RECV host={} fd={} reset by peer", .{
                                    connection.addr,
                                    op.socket,
                                }),
                                else => logger.warn("RECV host={} fd={} errno {d}", .{
                                    connection.addr,
                                    op.socket,
                                    cqe.res,
                                }),
                            }
                        }
                        connection.state = .terminating;
                    } else {
                        const recv = @intCast(usize, cqe.res);
                        const data = connection.buffer[0..recv];

                        logger.info("RECV host={} fd={} data={s}/{s} ({s})", .{
                            connection.addr,
                            connection.socket,
                            fmt.fmtSliceHexLower(data),
                            fmt.fmtSliceEscapeLower(data),
                            fmt.fmtIntSizeBin(data.len),
                        });
                    }
                },
                .send => |*op| {
                    assert(completion.parent == .connection);

                    var connection = @fieldParentPtr(Connection, "send_completion", completion);
                    assert(connection.state == .connected);

                    // handle errors
                    if (cqe.res <= 0) {
                        if (cqe.res == 0) {
                            logger.info("SEND host={} fd={} end of file", .{
                                connection.addr,
                                op.socket,
                            });
                        } else {
                            switch (@intToEnum(os.E, -cqe.res)) {
                                .PIPE => logger.info("SEND host={} fd={} broken pipe", .{
                                    connection.addr,
                                    op.socket,
                                }),
                                .CONNRESET => logger.info("SEND host={} fd={} reset by peer", .{
                                    connection.addr,
                                    op.socket,
                                }),
                                else => logger.warn("SEND host={} fd={} errno {d}", .{
                                    connection.addr,
                                    op.socket,
                                    cqe.res,
                                }),
                            }
                        }
                        connection.state = .terminating;
                    } else {
                        const sent = @intCast(usize, cqe.res);

                        logger.debug("SENT host={} fd={} ({s})", .{
                            connection.addr,
                            connection.socket,
                            fmt.fmtIntSizeBin(sent),
                        });

                        connection.statistics.bytes_sent += sent;
                    }

                    // Enqueue a timeout request for the next write.
                    try connection.prep_timeout(&ring, options.options.delay * std.time.ns_per_ms);
                },
                .close => |*op| {
                    assert(completion.parent == .connection);

                    var connection = @fieldParentPtr(Connection, "close_completion", completion);
                    assert(connection.state == .terminating);

                    const elapsed = time.milliTimestamp() - connection.statistics.connect_time;

                    logger.info("CLOSE host={} fd={} total sent={s} elapsed={s}", .{
                        connection.addr,
                        op.socket,
                        fmt.fmtIntSizeBin(@intCast(u64, connection.statistics.bytes_sent)),
                        fmt.fmtDuration(@intCast(u64, elapsed * time.ns_per_ms)),
                    });

                    // TODO(vincent): refactor into a struct ?
                    const buffer = connection.buffer;
                    connection.* = .{};
                    connection.buffer = buffer;
                },
                .timeout => switch (completion.parent) {
                    .global => {
                        logger.info("ACCEPT REQUEUE TIMEOUT", .{});

                        try global_accept.completion.prepAccept(&ring, server_fd);
                        global_accept.has_timeout = false;
                    },
                    .connection => {
                        const connection = @fieldParentPtr(Connection, "timeout_completion", completion);

                        logger.debug("TIMEOUT host={} fd={} state={s}", .{
                            connection.addr,
                            connection.socket,
                            @tagName(connection.state),
                        });

                        switch (connection.state) {
                            .terminating => {
                                // Enqueue a close request
                                try connection.prep_close(&ring);
                            },
                            .connected => {
                                const banner = blk: {
                                    var banner_buffer: [4]u8 = undefined;
                                    rng.random.bytes(&banner_buffer);

                                    break :blk try fmt.bufPrint(
                                        connection.buffer,
                                        "{s}",
                                        .{fmt.fmtSliceHexLower(&banner_buffer)},
                                    );
                                };
                                // Enqueue a send request
                                try connection.prep_send(&ring, banner);
                            },
                            else => debug.panic("invalid state {any}", .{connection.state}),
                        }
                    },
                },
                .timeout_remove => {
                    assert(completion.parent == .connection);

                    const connection = @fieldParentPtr(Connection, "timeout_completion", completion);
                    assert(connection.state == .terminating);

                    logger.debug("TIMEOUT REMOVED host={} fd={}", .{
                        connection.addr,
                        connection.socket,
                    });
                },
            }
        }

        _ = try ring.submit_and_wait(1);
    }
}
