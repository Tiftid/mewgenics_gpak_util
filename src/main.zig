//! Tiftid 11/Feb/2026:
//! Dump a Mewgenics .gpak file to a directory of real files.
//! Can also pack a directory into a .gpak file.

const std = @import("std");
const options = @import("options");

const Mode = enum{
	pack,
	unpack,
};

/// Tiftid 15/Feb/2026:
/// The size of std.Io.Reader and std.Io.Writer buffers we'll be using.
const IO_BUFFER_SIZE = 4096;

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
	
	defer std.log.info("All done!", .{});
	
	switch(mode){
		.unpack => {
			const gpak_path = args.next() orelse return usage();
			// Output directory is allowed to be null.
			// If it is, we'll just output in the same folder this executable is running in.
			const out_path = args.next();
			
			// Try to open the GPAK file.
			const gpak: std.Io.File = try std.Io.Dir.openFileAbsolute(io, gpak_path, .{});
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
			
			try unpack(io, alc, gpak, output_dir);
		},
		.pack => {
			const in_path = args.next() orelse return usage();
			const gpak_path = args.next() orelse return usage();
			
			// Try to open the input directory.
			const input_dir = try std.Io.Dir.openDirAbsolute(io, in_path, .{
				.iterate = true,
			});
			defer input_dir.close(io);
			
			// Try to create or open the GPAK file.
			const gpak: std.Io.File = try std.Io.Dir.createFileAbsolute(io, gpak_path, .{});
			defer gpak.close(io);
			
			var gpak_writer_buffer: [IO_BUFFER_SIZE]u8 = undefined;
			var gpak_writer = gpak.writer(io, &gpak_writer_buffer);
			const writer: *std.Io.Writer = &gpak_writer.interface;
			
			// Also try to create or open the temp file.
			const temp_path = try std.fmt.allocPrint(
				alc,
				"{s}/{s}.temp",
				.{
					std.fs.path.dirname(gpak_path) orelse "",
					std.fs.path.stem(gpak_path),
				},
			);
			defer alc.free(temp_path);
			// std.log.info("temp filepath: {s}", .{temp_path}); // sponge
			
			const temp: std.Io.File = try std.Io.Dir.createFileAbsolute(io, temp_path, .{});
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
				
				try pack(io, alc, input_dir, temp, directory_writer);
				
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
	}
}

/// Tiftid 14/Feb/2026 (St. Valentine's Day):
/// The function to use when in unpacking mode.
pub fn unpack(
	io: std.Io, alc: std.mem.Allocator,
	gpak: std.Io.File, output_dir: std.Io.Dir,
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
	if(!std.mem.eql(u8, header_ascii, "\\H")){
		std.log.warn("Expected GPAK file to start with \"\\H\", but it didn't!", .{});
		return error.GpakWrongHeader;
	}
	const header_remaining = try reader.takeInt(u16, .little);
	if(header_remaining != 0){
		std.log.warn("Expected GPAK file to have two 0-bytes following \"\\H\", but it didn't!", .{});
		return error.GpakWrongHeader;
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
	
	// Make a writer for the gpak file.
	var gpak_writer_buffer: [IO_BUFFER_SIZE]u8 = undefined;
	var gpak_writer = gpak.writer(io, &gpak_writer_buffer);
	const writer: *std.Io.Writer = &gpak_writer.interface;
	
	// After the filesystem, we have the raw file data.
	// We assume that the file data is stored in the exact same order as the filepaths would suggest.
	for(file_paths.items, file_lengths.items) |filepath, file_length| {
		defer progress.completeOne();
		
		@memcpy(&progress_filename_buf, filepath[0..@min(filepath.len, std.Progress.Node.max_name_len)]);
		progress_filename.setName(progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)]);
		
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
	
	_ = try writer.write("\\H");
	try writer.writeInt(u16, 0, .little);
	
	// Loop over the file paths and lengths, writing them after the header.
	for(file_paths.items, file_lengths.items) |filepath, file_length| {
		try writer.writeInt(u16, @intCast(filepath.len), .little);
		try writer.writeAll(filepath);
		try writer.writeInt(u32, file_length, .little);
	}
}

/// Tiftid 15/Feb/2026:
/// Generic helper function for streaming from a reader to a writer.
/// There are dedicated standard library functions for this, but they all failed me for some reason.
pub fn stream_reader_to_writer(
	reader: *std.Io.Reader,
	writer: *std.Io.Writer,
	length: usize,
) !void {
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
		, .{
			options.version,
		},
	);
}
