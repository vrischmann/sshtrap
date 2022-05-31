const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // At the moment we can't control the CPU features using the command line `zig build`
    // and one of my targets for this program is an APU2 router which doesn't have the features below.
    //
    // We disable the features by default instead and allow the user to build with native features using `zig build -Dtarget=native-linux`
    var disabled_features = blk: {
        var res = std.Target.Cpu.Feature.Set.empty;

        const Feature = std.Target.x86.Feature;

        res.addFeature(@enumToInt(Feature.bmi2));
        res.addFeature(@enumToInt(Feature.avx2));

        break :blk res;
    };

    var default_target = std.zig.CrossTarget{
        .cpu_arch = .x86_64,
        .cpu_model = .{ .explicit = &std.Target.x86.cpu.haswell },
        // TODO(vincent): until this code is fixed with .native the features are not disabled
        // https://github.com/ziglang/zig/blob/master/lib/std/zig/cross_target.zig#L326-L356
        // .cpu_model = .native,
        .cpu_features_sub = disabled_features,
        .os_tag = .linux,
    };

    const target = b.standardTargetOptions(.{
        .default_target = default_target,
    });
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("sshtrap", "src/main.zig");

    exe.addPackage(.{ .name = "args", .source = .{ .path = "third_party/zig-args/args.zig" } });

    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();
}
