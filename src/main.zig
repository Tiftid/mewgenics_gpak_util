//! Tiftid 11/Feb/2026:
//! Dump a Mewgenics .gpak file to a directory of real files.
//! Can also pack a directory into a .gpak file.

const std = @import("std");
const options = @import("options");

const Mode = enum{
	pack,
	unpack,
	patch,
};

/// Tiftid 15/Feb/2026:
/// Command-line flags for patch mode.
const PatchFlags = struct{
	no_delete_temp: bool = false,
	notify_on_failed_add: bool = false,
	notify_on_failed_override: bool = false,
};

/// Tiftid 15/Feb/2026:
/// The size of the std.Io.Reader and std.Io.Writer buffers we'll be using.
const IO_BUFFER_SIZE = 4096;

/// Tiftid 15/Feb/2026:
/// The ZON type we're going to be attempting to parse from patch.zon when we're patching a mod into an 
/// existing gpak file.
pub const PatchZon = struct{
	/// The version of the patch ZON file.
	/// Used to assert forwards- or backwards-compatibility.
	version: []const u8,
	/// Filepaths (relative to patch root) to add to the gpak.
	/// TODO: We should likely pre-iterate the gpak directory, so we can ascertain if the file to add 
	/// is already in there, and avoid adding it multiple times to the same gpak.
	add: []const []const u8,
	/// Filepaths (relative to gpak root) to completely remove from the gpak.
	remove: []const []const u8,
	/// Filepath relative to gpak root to replace.
	/// Expects that the replacement has the same filepath relative to patch root.
	override: []const []const u8,
};

/// Tiftid 21/Feb/2026:
/// Tyler for some reason decided to change the gpak header to start with a backtick instead of a 
/// backslash, possibly to make parsing it actually easier or to avoid conflicts with some other filetype.
/// This makes things messy for me as I now need to maintain backwards-compatibility.
pub const HeaderVersion = enum(u32){
	/// Header begins with \H; gpak file is from before 21/Feb/2026
	@"1" = 1,
	/// Header begins with `H; gpak file is from after 21/Feb/2026
	@"2",
	
	/// Get the comptime-known truth value of the header for a given header version.
	/// Given as an ASCII slice.
	pub fn truth(self: @This()) []const u8 {
		return switch(self){
			.@"1" => "\\H",
			.@"2" => "`H",
		};
	}
	
	/// Attempt to parse a header version from a buffer.
	pub fn parse(buffer: []const u8) std.fmt.ParseIntError!@This() {
		const int = try std.fmt.parseInt(
			@typeInfo(@This()).@"enum".tag_type,
			buffer,
			10,
		);
		return std.enums.fromInt(@This(), int) orelse error.Overflow;
	}
};

/// Modified by Tiftid 14/Feb/2026 (St. Valentine's Day):
/// Parse arguments and hand off execution to the relevant function.
pub fn main(init: std.process.Init) !void {
    const alc = init.gpa;
	const io = init.io;
	
    var args = try init.minimal.args.iterateAllocator(alc);
	defer args.deinit();
	
	// Skip the first argument, as it'll be the path to the binary.
	_ = args.skip();
	
	// Ascertain the mode we'll be running in.
	const mode_name = args.next() orelse return usage();
	const mode: Mode = blk: {
		inline for(std.meta.fields(Mode)) |field| {
			if(std.mem.eql(u8, mode_name, field.name)){
				break :blk comptime @field(Mode, field.name);
			}
		}
		
		return usage(); // Wrong mode specified
	};
	
	switch(mode){
		.unpack => {
			const gpak_path = args.next() orelse return usage();
			// Output directory is allowed to be null.
			// If it is, we'll just output in the same folder this executable is running in.
			const out_path = args.next();
			
			// Iterate over the flags to attempt to ascertain the header version.
			// If we notice it's unspecified, assume the user wants version 2.
			var header_version: HeaderVersion = .@"2";
			while(args.next()) |flag| {
				const flag_name = std.mem.sliceTo(flag, '=');
				if(std.mem.eql(u8, flag_name, "header_version")){
					header_version = HeaderVersion.parse(flag[flag_name.len + 1..]) catch |e| {
						std.log.err("{t}: Failed to parse \"{s}\" as a header version!", .{
							e, flag[flag_name.len + 1..],
						});
						return e;
					};
					break;
				}
			}
			
			// Try to open the GPAK file.
			const gpak: std.Io.File = std.Io.Dir.openFileAbsolute(io, gpak_path, .{}) catch |e| {
				std.log.err("{t}: Failed to open {s}!", .{e, gpak_path});
				return e;
			};
			defer gpak.close(io);
			
			// If the output directory is specified, open it now.
			// Otherwise, fall-back to a default.
			const output_dir: std.Io.Dir = 
				if(out_path) |path|	
				try std.Io.Dir.openDirAbsolute(io, path, .{})
				else blk: {
					const exe_dir_path = try std.process.executableDirPathAlloc(io, alc);
					defer alc.free(exe_dir_path);
					break :blk try std.Io.Dir.openDirAbsolute(io, exe_dir_path, .{});
				}
			;
			defer output_dir.close(io);
			
			try unpack(io, alc, gpak, output_dir, header_version);
		},
		.pack => {
			const in_path = args.next() orelse return usage();
			const gpak_path = args.next() orelse return usage();
			
			// Iterate over the flags to attempt to ascertain the header version.
			// If we notice it's unspecified, assume the user wants version 2.
			var header_version: HeaderVersion = .@"2";
			while(args.next()) |flag| {
				const flag_name = std.mem.sliceTo(flag, '=');
				if(std.mem.eql(u8, flag_name, "header_version")){
					header_version = HeaderVersion.parse(flag[flag_name.len + 1..]) catch |e| {
						std.log.err("{t}: Failed to parse \"{s}\" as a header version!", .{
							e, flag[flag_name.len + 1..],
						});
						return e;
					};
					break;
				}
			}
			
			// Try to open the input directory.
			const input_dir = std.Io.Dir.openDirAbsolute(io, in_path, .{
				.iterate = true,
			}) catch |e| {
				std.log.err("{t}: Failed to open {s}!", .{e, in_path});
				return e;
			};
			defer input_dir.close(io);
			
			// Try to create or open the GPAK file.
			const gpak: std.Io.File = std.Io.Dir.createFileAbsolute(io, gpak_path, .{}) catch |e| {
				std.log.err("{t}: Failed to open {s}!", .{e, gpak_path});
				return e;
			};
			defer gpak.close(io);
			
			var gpak_writer_buffer: [IO_BUFFER_SIZE]u8 = undefined;
			var gpak_writer = gpak.writer(io, &gpak_writer_buffer);
			const writer: *std.Io.Writer = &gpak_writer.interface;
			
			// Also try to create or open the temp file.
			const temp_path = try std.fmt.allocPrint(
				alc,
				"{s}{s}{s}.temp",
				.{
					std.fs.path.dirname(gpak_path) orelse "",
					[1]u8{std.fs.path.sep},
					std.fs.path.stem(gpak_path),
				},
			);
			defer alc.free(temp_path);
			// std.log.info("temp filepath: {s}", .{temp_path}); // sponge
			
			const temp: std.Io.File = std.Io.Dir.createFileAbsolute(io, temp_path, .{}) catch |e| {
				std.log.err("{t}: Failed to create or open {s}!", .{e, temp_path});
				return e;
			};
			// Attempt to delete the temp file once we're done with it.
			// If this operation fails, notify the user.
			defer{
				std.Io.Dir.deleteFileAbsolute(io, temp_path) catch |e| {
					std.log.err("{t}: Failed to delete {s}!", .{e, temp_path});
				};
			}
			
			{ // Indented so the file is closed before we attempt to reopen it
				defer temp.close(io);
				
				var directory_alloc: std.Io.Writer.Allocating = .init(alc);
				errdefer directory_alloc.deinit();
				
				const directory_writer: *std.Io.Writer = &directory_alloc.writer;
				
				try pack(io, alc, input_dir, temp, directory_writer, header_version);
				
				// Now that we've written to the directory, we construct a reader from its owned slice, 
				// and stream that reader into the gpak writer.
				// This is jank, but it's what we need to do to essentially "concatenate" the directory 
				// and the file contents with minimal memory usage.
				const directory = try directory_alloc.toOwnedSlice();
				defer alc.free(directory);
				
				var directory_reader: std.Io.Reader = .fixed(directory);
				
				try stream_reader_to_writer(&directory_reader, writer, directory.len);
			}
			
			std.log.info("Writing temp file into {s}...", .{gpak_path});
			
			// Now, we need to read the temp file, and stream it into the writer.
			// The problem is that trying to construct a reader for the temp file fails, since the file 
			// handle we have is from back before the file had any data written to it.
			// So, we have to close and reopen the file.
			{ // Indented so that the file is closed before we attempt to delete it
				const temp2 = try std.Io.Dir.openFileAbsolute(io, temp_path, .{});
				defer temp2.close(io);
				
				var temp_reader_buffer: [IO_BUFFER_SIZE]u8 = undefined;
				var temp_reader = temp2.reader(io, &temp_reader_buffer);
				const reader: *std.Io.Reader = &temp_reader.interface;
				
				const length = try temp2.length(io);
				if(length > std.math.maxInt(usize)){
					@branchHint(.cold);
					std.log.err("FATAL ERROR: Temp file too large! ({d} bytes)", .{length});
					return error.TempTooLarge;
				}
				
				try stream_reader_to_writer(reader, writer, length);
			}
		},
		.patch => {
			const patch_path = args.next() orelse return usage();
			const gpak_path = args.next() orelse return usage();
			
			var flags: PatchFlags = .{};
			var header_version: HeaderVersion = .@"2";
			while(args.next()) |flag| {
				inline for(std.meta.fields(PatchFlags)) |field| {
					if(std.mem.eql(u8, flag, field.name)){
						// std.log.info("{s}: Flag enabled!", .{field.name}); // sponge
						@field(flags, field.name) = true;
					}
				}
				
				const flag_name = std.mem.sliceTo(flag, '=');
				if(std.mem.eql(u8, flag_name, "header_version")){
					header_version = HeaderVersion.parse(flag[flag_name.len + 1..]) catch |e| {
						std.log.err("{t}: Failed to parse \"{s}\" as a header version!", .{
							e, flag[flag_name.len + 1..],
						});
						return e;
					};
					break;
				}
			}
			
			// Try to open the patch directory.
			const patch_dir = std.Io.Dir.openDirAbsolute(io, patch_path, .{}) catch |e| {
				std.log.err("{t}: Failed to open {s}!", .{e, patch_path});
				return e;
			};
			defer patch_dir.close(io);
			
			// Try to open the GPAK file.
			const gpak: std.Io.File = std.Io.Dir.openFileAbsolute(io, gpak_path, .{
				.mode = .read_write,
			}) catch |e| {
				std.log.err("{t}: Failed to open {s}!", .{e, gpak_path});
				return e;
			};
			errdefer gpak.close(io);
			
			// Also try to create or open the temp file.
			const temp_path = try std.fmt.allocPrint(
				alc,
				"{s}{s}{s}.temp",
				.{
					std.fs.path.dirname(gpak_path) orelse "",
					[1]u8{std.fs.path.sep},
					std.fs.path.stem(gpak_path),
				},
			);
			defer alc.free(temp_path);
			// std.log.info("temp filepath: {s}", .{temp_path}); // sponge
			
			const temp = std.Io.Dir.createFileAbsolute(io, temp_path, .{
				.read = true,
			}) catch |e| {
				std.log.err("{t}: Failed to create or open {s}!", .{e, temp_path});
				return e;
			};
			errdefer temp.close(io);
			
			// Indented so we close the temp file before we attempt to reopen it.
			try patch(io, alc, gpak, temp, patch_dir, flags, header_version);
			
			temp.close(io);
			gpak.close(io);
			
			if(!flags.no_delete_temp){
				// After patching, simply delete the gpak and rename the temp file.
				std.log.info("Writing temp file into {s}...", .{gpak_path});
				
				try std.Io.Dir.deleteFileAbsolute(io, gpak_path);
				
				try std.Io.Dir.renameAbsolute(temp_path, gpak_path, io);
			}
		},
	}
	
	std.log.info("All done!", .{});
}

/// Tiftid 14/Feb/2026 (St. Valentine's Day):
/// The function to use when in unpacking mode.
pub fn unpack(
	io: std.Io, alc: std.mem.Allocator,
	gpak: std.Io.File, output_dir: std.Io.Dir,
	header_version: HeaderVersion,
) !void {
	// GPAK filepaths and their associated file lengths.
	var file_paths: std.ArrayList([]const u8) = .empty;
	defer{
		for(file_paths.items) |path| {
			alc.free(path);
		}
		file_paths.deinit(alc);
	}
	var file_lengths: std.ArrayList(u32) = .empty;
	defer file_lengths.deinit(alc);
	
	// Get a reader from the GPAK file.
	var gpak_reader_buffer: [IO_BUFFER_SIZE]u8 = undefined;
	var gpak_reader: std.Io.File.Reader = gpak.reader(io, &gpak_reader_buffer);
	const reader: *std.Io.Reader = &gpak_reader.interface;
	
	// Begin reading the GPAK file.
	// Assert that the header is "\H" followed by two 0 bytes.
	const header_ascii = try reader.take(2);
	if(!std.mem.eql(u8, header_ascii, header_version.truth())){
		std.log.err("FATAL ERROR: Expected gpak file to start with {s}, found {s}!", .{
			header_version.truth(),
			header_ascii,
		});
		return error.GpakWrongHeader;
	}
	const header_padding = try reader.takeInt(u16, .little);
	if(header_padding != 0){
		std.log.warn("Header should have had two 0-bytes after {s}, but it didn't!", .{
			header_version.truth(),
		});
	}
	
	// Now that we've parsed the header, we can begin parsing the virtual filesystem.
	while(true) {
		// std.log.info("Attempting to parse header of file at offset 0x{X:0>8}", .{i}); // sponge
		
		// A file is defined by a u16 representing the length of the filepath, then the filepath 
		// itself, then a u32 representing the length of the file in bytes.
		const filepath_len = try reader.takeInt(u16, .little);
		// Tiftid 15/Feb/2026:
		// We break if the filepath length is longer than the length of the reader's buffer, as that 
		// would be a ridiculously long filepath and likely indicates the end of this block.
		if(filepath_len > IO_BUFFER_SIZE){
			@branchHint(.unlikely); // This can only happen once, so we hint it as unlikely.
			
			// We also need to move the reader's seek position back 2, otherwise EVERY file read 
			// gets shifted forward by two bytes.
			reader.seek -= 2;
			
			break;
		}
		
		const filepath = try reader.take(filepath_len);
		// Tiftid 15/Feb/2026:
		// New system for ascertaining where this block ends; we just parse the filepath exactly as it's 
		// given to us, and if it doesn't look like it ends with a file extension, we break.
		const ext = std.fs.path.extension(filepath);
		// The longest file extension in Mewgenics is ".shader"
		if(ext.len <= 2 or ext.len >= 8){
			@branchHint(.unlikely); // This can only happen once, so we hint it as unlikely.
			
			// We also need to move the reader's seek position back, otherwise EVERY file read 
			// gets shifted forward.
			reader.seek -= 2 + filepath_len;
			
			break;
		}
		
		// Dupe the filepath and shove it into the ArrayList.
		// This is so the memory doesn't get stolen out from under our feet as the reader 
		// forgets about this part of the file later.
		// 
		// We also have to do this BEFORE reading the file length, because if we don't, we get very 
		// strange errors which are related to the reader calling .rebase() and rug-pulling this 
		// memory out from under us.
		try file_paths.append(alc, try alc.dupe(u8, filepath));
		
		const file_length = try reader.takeInt(u32, .little);
		
		try file_lengths.append(alc, file_length);
	}
	
	// Give the user feedback that the application is actually working towards something- 
	// it just takes a while!
	const progress: std.Progress.Node = std.Progress.start(io, .{
		.refresh_rate_ns = .fromSeconds(1 / 120), // Update at 120 FPS if possible
	});
	defer progress.end();
	
	progress.setName("Extracting files");
	progress.setEstimatedTotalItems(file_paths.items.len);
	
	// We also make a child node, just so we can display which file is currently being extracted.
	var progress_filename_buf: [std.Progress.Node.max_name_len]u8 = undefined;
	const progress_filename: std.Progress.Node = progress.start("", 0);
	defer progress_filename.end();
	
	// After the filesystem, we have the raw file data.
	// We assume that the file data is stored in the exact same order as the filepaths would suggest.
	for(file_paths.items, file_lengths.items) |filepath, file_length| {
		defer progress.completeOne();
		
		@memcpy(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
			filepath[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		progress_filename.setName(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		
		// std.log.info("Length of file {s}: 0x{X} b", .{filepath, file_length}); // sponge
		
		// Save it to the host filesystem.
		if(std.fs.path.dirname(filepath)) |filepath_dir| {
			// Make the subdirectories required to hold the output file.
			try output_dir.createDirPath(io, filepath_dir);
		} else {
			// Individual files at the root of the GPAK are unlikely, so this is a cold path.
			@branchHint(.cold);
		}
		// Make the output file.
		const file = try output_dir.createFile(io, filepath, .{});
		defer file.close(io);
		
		var file_writer_buffer: [IO_BUFFER_SIZE]u8 = undefined;
		var file_writer = file.writer(io, &file_writer_buffer);
		const writer: *std.Io.Writer = &file_writer.interface;
		
		// Stream the file.
		try stream_reader_to_writer(reader, writer, file_length);
	}
}

/// Tiftid 14/Feb/2026 (St. Valentine's Day):
/// The function to use when in packing mode.
pub fn pack(
	io: std.Io, alc: std.mem.Allocator,
	input_dir: std.Io.Dir,
	temp: std.Io.File,
	/// The writer for the directory.
	writer: *std.Io.Writer,
	header_version: HeaderVersion,
) !void {
	// GPAK filepaths and their associated file lengths.
	var file_paths: std.ArrayList([]const u8) = .empty;
	defer {
		for(file_paths.items) |filepath| {
			alc.free(filepath);
		}
		file_paths.deinit(alc);
	}
	var file_lengths: std.ArrayList(u32) = .empty;
	defer file_lengths.deinit(alc);
	
	// Give the user feedback that the application is actually working towards something- 
	// it just takes a while!
	const progress: std.Progress.Node = std.Progress.start(io, .{
		.refresh_rate_ns = .fromSeconds(1 / 120), // Update at 120 FPS if possible
	});
	defer progress.end();
	
	progress.setName("Writing files");
	progress.setEstimatedTotalItems(file_paths.items.len);
	
	// We also make a child node, just so we can display which file is currently being written.
	var progress_filename_buf: [std.Progress.Node.max_name_len]u8 = undefined;
	const progress_filename: std.Progress.Node = progress.start("", 0);
	defer progress_filename.end();
	
	// Create a writer for the temp file.
	var tempfile_writer_buffer: [IO_BUFFER_SIZE]u8 = undefined;
	var tempfile_writer = temp.writer(io, &tempfile_writer_buffer);
	const temp_writer: *std.Io.Writer = &tempfile_writer.interface;
	
	// std.debug.print("Walking input directory. This may take some time...\n", .{});
	
	// Walk the input directory to parse filepaths and lengths.
	// While we write the filepaths and lengths directly into memory (as they're somewhat light), we 
	// instead write the file data directly into our temp file.
	// 
	// Then, in a postprocess step, we can write the header, filepaths and lengths into the real output 
	// file, then stream data from the temp file into the real file, then delete the temp file.
	var walker = try input_dir.walk(alc);
	defer walker.deinit();
	while(try walker.next(io)) |entry| {
		if(entry.kind != .file) continue; // TODO: Symlinks?
		
		defer progress.completeOne();
		// Set the child node's name to the path of the current file relative to the root directory.
		@memcpy(
			&progress_filename_buf,
			entry.path[0..@min(entry.path.len, std.Progress.Node.max_name_len)],
		);
		progress_filename.setName(
			progress_filename_buf[0..@min(entry.path.len, std.Progress.Node.max_name_len)],
		);
		
		// Try to open and stat the file to ascertain its length.
		const file = try entry.dir.openFile(io, entry.basename, .{});
		defer file.close(io);
		
		// If the entry path is too long for its length to fit into a u16 (very unlikely), 
		// log it and crash.
		if(entry.path.len > std.math.maxInt(u16)){
			@branchHint(.unlikely);
			std.log.err("FATAL ERROR: Filepath {s} is too long!", .{
				entry.path,
			});
			return error.FilePathTooLong;
		}
		
		const length = try file.length(io);
		if(length > std.math.maxInt(u32)){
			@branchHint(.unlikely);
			std.log.err("FATAL ERROR: File {s} is too long ({d} bytes)", .{
				entry.path,
				length,
			});
			return error.FileDataTooLong;
		}
		
		// std.log.info("Found file {s} with length {d}", .{entry.path, length}); // sponge
		
		// Now, we know we can safely @intCast() the length and insert it into our list.
		try file_lengths.append(alc, @intCast(length));
		
		// Before we store the path name, convert back-slashes to forward-slashes.
		// Back-slashes would crash Mewgenics on launch with no error message, possibly due to being 
		// interpreted as escape characters.
		const filename_copy = try alc.dupe(u8, entry.path);
		std.mem.replaceScalar(u8, filename_copy, '\\', '/');
		try file_paths.append(alc, filename_copy);
		
		// Now, we construct a reader for the file, and use that to stream it directly into 
		// the temp file.
		var file_reader_buffer: [IO_BUFFER_SIZE]u8 = undefined;
		var file_reader = file.reader(io, &file_reader_buffer);
		const reader: *std.Io.Reader = &file_reader.interface;
		
		// The @intCast() is so that this program will compile for 32-bit systems... even though there's 
		// no real reason to do that.
		try stream_reader_to_writer(reader, temp_writer, @intCast(length));
	}
	
	_ = try writer.write(header_version.truth());
	try writer.writeInt(u16, 0, .little);
	
	// Loop over the file paths and lengths, writing them after the header.
	for(file_paths.items, file_lengths.items) |filepath, file_length| {
		try writer.writeInt(u16, @intCast(filepath.len), .little);
		try writer.writeAll(filepath);
		try writer.writeInt(u32, file_length, .little);
	}
}

/// Tiftid 15/Feb/2026:
/// The function to use when in patch mode.
/// Bear in mind that we only want to read the gpak file here, not write to it.
pub fn patch(
	io: std.Io, alc: std.mem.Allocator,
	gpak: std.Io.File,
	temp: std.Io.File,
	patch_dir: std.Io.Dir,
	flags: PatchFlags,
	header_version: HeaderVersion,
) !void {
	// First of all, attempt to read the patch file as ZON.
	const patch_file = patch_dir.openFile(io, "patch.zon", .{}) catch |e| {
		std.log.err("{t}: Failed to open patch.zon!", .{e});
		return e;
	};
	defer patch_file.close(io);
	
	const patch_zon: PatchZon = blk: {
		var patch_bytes: std.Io.Writer.Allocating = .init(alc);
		errdefer patch_bytes.deinit();
		
		// We don't check that this u64 fits in a usize, since it's astronomically unlikely that it 
		// won't.
		const patch_file_size = try patch_file.length(io);
		
		var patch_reader_buffer: [IO_BUFFER_SIZE]u8 = undefined;
		var patch_reader = patch_file.reader(io, &patch_reader_buffer);
		const reader: *std.Io.Reader = &patch_reader.interface;
		
		const writer: *std.Io.Writer = &patch_bytes.writer;
		
		try stream_reader_to_writer(reader, writer, @intCast(patch_file_size));
		
		const patch_bytes_sentinel = try patch_bytes.toOwnedSliceSentinel(0);
		defer alc.free(patch_bytes_sentinel);

		break :blk try std.zon.parse.fromSliceAlloc(
			PatchZon,
			alc,
			patch_bytes_sentinel,
			null, // No diagnostics
			.{}, // No non-default options for now
		);
	};
	defer std.zon.parse.free(alc, patch_zon);
	
	// std.log.info("Patch ZON:\n{}", .{patch_zon}); // sponge
	
	// Added files.
	// The filepaths are already held by the ZON memory.
	// 
	// Tiftid 16/Feb/2026:
	// New system; when we're iterating over the original file's directory, if we find that an 
	// add file is already present, we set its flag in this slice to false.
	// This prevents us from writing it into the temp file.
	const add_file_write_flags = try alc.alloc(bool, patch_zon.add.len);
	defer alc.free(add_file_write_flags);
	@memset(add_file_write_flags, true); // Initialise as all-true
	
	var file_paths: std.ArrayList([]const u8) = try .initCapacity(alc, 20000);
	defer {
		for(file_paths.items) |filepath| {
			alc.free(filepath);
		}
		file_paths.deinit(alc);
	}
	var file_lengths: std.ArrayList(u32) = try .initCapacity(alc, 20000);
	defer file_lengths.deinit(alc);
	// Whether or not this file should be written into the output gpak.
	var file_write_flags: std.ArrayList(bool) = try .initCapacity(alc, 20000);
	defer file_write_flags.deinit(alc);
	
	// Overwritten files.
	// The filepaths are already held by the ZON memory.
	// 
	// Tiftid 16/Feb/2026:
	// We have a new guardrail; if an override file doesn't have a corresponding entry in the gpak, we 
	// add it to the gpak anyway.
	// The old behaviour was to do nothing in this case.
	const override_file_exists = try alc.alloc(bool, patch_zon.override.len);
	@memset(override_file_exists, false);
	defer alc.free(override_file_exists);
	
	// Begin iterating over the original directory, and differentiating between unmodified and overriden
	// files.
	var gpak_filereader_buffer: [IO_BUFFER_SIZE]u8 = undefined;
	var gpak_filereader = gpak.reader(io, &gpak_filereader_buffer);
	const gpak_reader: *std.Io.Reader = &gpak_filereader.interface;
	
	// Assert that the header is "\H" followed by two 0 bytes.
	const header_ascii = try gpak_reader.take(2);
	if(!std.mem.eql(u8, header_ascii, header_version.truth())){
		std.log.err("FATAL ERROR: Expected gpak file to start with {s}, found {s}!", .{
			header_version.truth(),
			header_ascii,
		});
		return error.GpakWrongHeader;
	}
	const header_padding = try gpak_reader.takeInt(u16, .little);
	if(header_padding != 0){
		std.log.warn("Header should have had two 0-bytes after {s}, but it didn't!", .{
			header_version.truth(),
		});
	}
	
	while(true){
		const filepath_len = try gpak_reader.takeInt(u16, .little);
		// Tiftid 15/Feb/2026:
		// We break if the filepath length is longer than the length of the reader's buffer, as that 
		// would be a ridiculously long filepath and likely indicates the end of this block.
		if(filepath_len > IO_BUFFER_SIZE){
			@branchHint(.unlikely); // This can only happen once, so we hint it as unlikely.
			
			// We also need to move the reader's seek position back 2, otherwise EVERY file read 
			// gets shifted forward by two bytes.
			gpak_reader.seek -= 2;
			
			break;
		}
		
		const filepath = try gpak_reader.take(filepath_len);
		// Tiftid 15/Feb/2026:
		// New system for ascertaining where this block ends; we just parse the filepath exactly as it's 
		// given to us, and if it doesn't look like it ends with a file extension, we break.
		const ext = std.fs.path.extension(filepath);
		// The longest file extension in Mewgenics is ".shader"
		if(ext.len <= 2 or ext.len >= 8){
			@branchHint(.unlikely); // This can only happen once, so we hint it as unlikely.
			
			// We also need to move the reader's seek position back, otherwise EVERY file read 
			// gets shifted forward.
			gpak_reader.seek -= 2 + filepath_len;
			
			break;
		}
		
		// Tiftid 16/Feb/2026:
		// Iterate through the add filepaths, and test for equality.
		// If we find that the add file already exists in the gpak, tell us to not actually add it.
		for(patch_zon.add, 0..) |patch_filepath, i| {
			if(std.mem.eql(u8, patch_filepath, filepath)){
				if(flags.notify_on_failed_add)
					std.log.info("File {s} already exists in the gpak - not adding it", .{filepath})
				;
				add_file_write_flags[i] = false;
				break;
			}
		}
		// Iterate through the remove filepaths, and test for equality.
		const is_remove: bool = blk: {
			for(patch_zon.remove) |remove| {
				if(std.mem.eql(u8, remove, filepath)){
					// std.log.info("Found remove file {s}", .{filepath}); // sponge
					break :blk true;
				}
			}
			break :blk false;
		};
		// Iterate through the override file paths, and test for equality.
		const is_override: bool = blk: {
			for(patch_zon.override, 0..) |patch_filepath, i| {
				if(std.mem.eql(u8, patch_filepath, filepath)){
					// std.log.info("Found override file {s}", .{filepath}); // sponge
					override_file_exists[i] = true;
					break :blk true;
				}
			}
			break :blk false;
		};
		
		try file_write_flags.append(alc, !is_override and !is_remove);
		
		// Dupe the filepath and shove it into the ArrayList.
		// This is so the memory doesn't get stolen out from under our feet as the reader 
		// forgets about this part of the file later.
		// 
		// We also have to do this BEFORE reading the file length, because if we don't, we get very 
		// strange errors which are related to the reader calling .rebase() and rug-pulling this 
		// memory out from under us.
		try file_paths.append(alc, try alc.dupe(u8, filepath));
		
		const file_length = try gpak_reader.takeInt(u32, .little);
		
		try file_lengths.append(alc, file_length);
	}
	
	if(flags.notify_on_failed_override){
		for(patch_zon.override, override_file_exists) |filepath, exists| {
			if(!exists) std.log.warn(
				"Patch override file {s} wasn't found in the gpak! Adding it instead...", .{
					filepath,
				}
			);
		}
	}
	
	// Begin writing to the temp file.
	var temp_writer_buffer: [IO_BUFFER_SIZE]u8 = undefined;
	var temp_writer = temp.writer(io, &temp_writer_buffer);
	const writer: *std.Io.Writer = &temp_writer.interface;
	
	_ = try writer.write(header_version.truth());
	try writer.writeInt(u16, 0, .little);
	
	for(patch_zon.add, add_file_write_flags) |filepath, write| {
		if(!write) continue;
		if(filepath.len > std.math.maxInt(u16)){
			@branchHint(.unlikely);
			std.log.err("FATAL ERROR: Patch add file path {s} is too long!", .{
				filepath,
			});
			return error.PatchAddPathTooLong;
		}
		
		const file = try patch_dir.openFile(io, filepath, .{});
		defer file.close(io);
		
		const length = try file.length(io);
		if(length > std.math.maxInt(u32)){
			@branchHint(.unlikely);
			std.log.err("FATAL ERROR: Patch add file {s} is too long!", .{
				filepath,
			});
			return error.PatchAddFileTooLong;
		}
		
		try writer.writeInt(u16, @intCast(filepath.len), .little);
		try writer.writeAll(filepath);
		try writer.writeInt(u32, @intCast(length), .little);
	}
	
	for(file_paths.items, file_lengths.items, file_write_flags.items) |filepath, file_length, write| {
		if(!write) continue;
		if(filepath.len > std.math.maxInt(u16)){
			@branchHint(.unlikely);
			std.log.err("FATAL ERROR: Original gpak file path {s} is too long!", .{
				filepath,
			});
			return error.PatchUnmodifiedPathTooLong;
		}
		try writer.writeInt(u16, @intCast(filepath.len), .little);
		try writer.writeAll(filepath);
		try writer.writeInt(u32, file_length, .little);
	}
	
	for(patch_zon.override) |filepath| {
		if(filepath.len > std.math.maxInt(u16)){
			@branchHint(.unlikely);
			std.log.err("FATAL ERROR: Patch override file path {s} is too long!", .{
				filepath,
			});
			return error.PatchOverridePathTooLong;
		}
		
		const file = try patch_dir.openFile(io, filepath, .{});
		defer file.close(io);
		
		const length = try file.length(io);
		if(length > std.math.maxInt(u32)){
			@branchHint(.unlikely);
			std.log.err("FATAL ERROR: Patch override file {s} is too long!", .{
				filepath,
			});
			return error.PatchOverrideFileTooLong;
		}
		
		try writer.writeInt(u16, @intCast(filepath.len), .little);
		try writer.writeAll(filepath);
		try writer.writeInt(u32, @intCast(length), .little);
	}
	
	// Give the user feedback that the application is actually working towards something- 
	// it just takes a while!
	const progress: std.Progress.Node = std.Progress.start(io, .{
		.refresh_rate_ns = .fromSeconds(1 / 120), // Update at 120 FPS if possible
	});
	defer progress.end();
	
	// Calculate the number of files we'll expect to write.
	// We won't be writing all original files, so we need to reference their write flag.
	const file_num: usize = blk: {
		var out: usize = patch_zon.override.len;
		for(add_file_write_flags) |write| {
			if(write) out += 1;
		}
		for(file_write_flags.items) |write| {
			if(write) out += 1;
		}
		break :blk out;
	};
	
	progress.setName("Writing files");
	progress.setEstimatedTotalItems(file_num);
	
	// We also make a child node, just so we can display which file is currently being written.
	var progress_filename_buf: [std.Progress.Node.max_name_len]u8 = undefined;
	const progress_filename: std.Progress.Node = progress.start("", 0);
	defer progress_filename.end();
	
	for(patch_zon.add, add_file_write_flags) |filepath, write| {
		if(!write) continue;
		defer progress.completeOne();
		// Set the child node's name to the path of the current file.
		@memcpy(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
			filepath[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		progress_filename.setName(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		
		// Reopen the patch file and construct a reader from it.
		// Stream the reader into the temp file's writer.
		const file = patch_dir.openFile(io, filepath, .{}) catch |e| {
			std.log.err("{t}: Failed to open patch file {s}!", .{
				e, filepath,
			});
			return e;
		};
		defer file.close(io);
		
		const length = try file.length(io);
		
		var file_reader_buffer: [IO_BUFFER_SIZE]u8 = undefined;
		var file_reader = file.reader(io, &file_reader_buffer);
		const reader: *std.Io.Reader = &file_reader.interface;
		
		// If we don't flush here, the writer may refuse to write some of the beginning of the file... 
		// for some reason.
		try writer.flush();
		try stream_reader_to_writer(reader, writer, @intCast(length));
	}
	
	for(file_paths.items, file_lengths.items, file_write_flags.items) |filepath, file_length, write| {
		defer progress.completeOne();
		// Set the child node's name to the path of the current file.
		@memcpy(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
			filepath[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		progress_filename.setName(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		
		// Read the file and stream it to the temp file.
		if(write){
			try stream_reader_to_writer(gpak_reader, writer, file_length);
		} else {
			// Stream the file into a dummy writer, if we're not writing it.
			// Somehow gpak_reader.toss(file_length) was always causing error.EndOfStream, no matter 
			// what I tried.
			var dummy_buffer: [IO_BUFFER_SIZE]u8 = undefined;
			var dummy: std.Io.Writer.Discarding = .init(&dummy_buffer);
			try stream_reader_to_writer(gpak_reader, &dummy.writer, file_length);
		}
	}
	
	for(patch_zon.override) |filepath| {
		defer progress.completeOne();
		// Set the child node's name to the path of the current file.
		@memcpy(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
			filepath[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		progress_filename.setName(
			progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)],
		);
		
		// Reopen the patch file and construct a reader from it.
		// Stream the reader into the temp file's writer.
		const file = patch_dir.openFile(io, filepath, .{}) catch |e| {
			std.log.err("{t}: Failed to open patch file {s}!", .{
				e, filepath,
			});
			return e;
		};
		defer file.close(io);
		
		const length = try file.length(io);
		
		var file_reader_buffer: [IO_BUFFER_SIZE]u8 = undefined;
		var file_reader = file.reader(io, &file_reader_buffer);
		const reader: *std.Io.Reader = &file_reader.interface;
		
		// I have tested and confirmed that omitting the flush() call for the add files causes issues, 
		// but I haven't done so for this, so you may be able to omit it, since stream_reader_to_writer() 
		// always flushes after writing every chunk, and we don't mess with the writer in any other way 
		// than through calling that function before this block.
		// try writer.flush();
		try stream_reader_to_writer(reader, writer, @intCast(length));
	}
}

/// Tiftid 15/Feb/2026:
/// Generic helper function for streaming from a reader to a writer.
/// There are dedicated standard library functions for this, but they all failed me for some reason.
pub fn stream_reader_to_writer(
	reader: *std.Io.Reader,
	writer: *std.Io.Writer,
	length: usize,
) (std.Io.Reader.Error || std.Io.Writer.Error)!void {
	// Stream the input to the output, IO_BUFFER_SIZE bytes at a time.
	var chunk_prev: usize = undefined;
	var chunk: usize = 0;
	while(chunk != length){
		chunk_prev = chunk;
		chunk = @min(length, chunk + IO_BUFFER_SIZE);
		_ = try writer.write(try reader.take(chunk - chunk_prev));
		try writer.flush();
	}
}

/// Print program usage to stdout.
pub fn usage() void {
	std.debug.print(
		\\==============================================
		\\MEWGENICS GPAK UTIL {f}
		\\By Tiftid
		\\==============================================
		\\Usage:
		\\<unpack>
		\\  <path to gpak file> <(OPTIONAL) path to output directory>
		\\OR
		\\<pack>
		\\  <path to input directory> <path to output gpak file>
		\\OR
		\\<patch>
		\\  <path to patch directory containing patch.zon> <path to output gpak file>
		\\  In patch mode, the following optional flags are available:
		\\  no_delete_temp
		\\    Leave the gpak file unmodified, and leave the temp file as the patched gpak.
		\\    Primarily useful for testing.
		\\  notify_on_failed_add
		\\    Log a message whenever an add file from the patch already exists in the gpak.
		\\  notify_on_failed_override
		\\    Log a message whenever the gpak is missing a corresponding entry for one of the patch's
		\\    override files.
		\\
		\\From 21/Feb/2026, the following flag is available in all modes:
		\\  header_version=<number>
		\\     Specify the header version of the gpak file. 2 is the current version, 1 is the old version.
		\\     This tool now defaults to version 2, so it won't work with old files unless you specify 
		\\     this flag.
		, .{
			options.version,
		},
	);
}
