const std = @import("std");

const zon = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
	
	// Make the build.zig.zon semantic version available to the executable as an import.
	const options = b.addOptions();
	options.addOption(
		std.SemanticVersion,
		"version",
		comptime std.SemanticVersion.parse(zon.version) catch @compileError(
			"Failed to parse semantic version from build.zig.zon"
		),
	);
	
    const exe = b.addExecutable(.{
        .name = "mewgenics_gpak_util",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
				.{.name = "options", .module = options.createModule()},
			},
        }),
    });
	
    b.installArtifact(exe);
	
    const run_step = b.step("run", "Run the app");
	
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
	
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
	
    const run_exe_tests = b.addRunArtifact(exe_tests);
	
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_exe_tests.step);
}
