//! Tiftid 11/Feb/2026:
//! Dump a Mewgenics .gpak file to a directory of real files.

const std = @import("std");
const options = @import("options");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
	const io = init.io;
	
    var args = try init.minimal.args.iterateAllocator(gpa);
	defer args.deinit();
	
	// GPAK filepaths and their associated file lengths.
	var file_paths: std.ArrayList([]const u8) = .empty;
	defer{
		for(file_paths.items) |path| {
			gpa.free(path);
		}
		file_paths.deinit(gpa);
	}
	var file_lengths: std.ArrayList(u32) = .empty;
	defer file_lengths.deinit(gpa);
	
	// Skip the first argument, as it'll be the path to the binary.
	_ = args.skip();
	
	const gpak_path = args.next() orelse return usage();
	// Output directory is allowed to be null.
	// If it is, we'll just output in the same folder this executable is running in.
	const out_path = args.next();
	
	// Try to open the GPAK file.
	const gpak: std.Io.File = try std.Io.Dir.openFileAbsolute(io, gpak_path, .{});
	defer gpak.close(io);
	
	// Get a reader from it.
	var gpak_reader_buffer: [4096]u8 = undefined;
	var gpak_reader: std.Io.File.Reader = gpak.reader(io, &gpak_reader_buffer);
	const reader: *std.Io.Reader = &gpak_reader.interface;
	
	// If the output directory is specified, open it now.
	// Otherwise, fall-back to a default.
	const output_dir: std.Io.Dir = 
		if(out_path) |path|	
		try std.Io.Dir.openDirAbsolute(io, path, .{})
		else blk: {
			const exe_dir_path = try std.process.executableDirPathAlloc(io, gpa);
			defer gpa.free(exe_dir_path);
			break :blk try std.Io.Dir.openDirAbsolute(io, exe_dir_path, .{});
		}
	;
	defer output_dir.close(io);
	
	// Begin reading the GPAK file.
	// Assert that the header is "\H" followed by two 0 bytes.
	const header_ascii = try reader.take(2);
	if(!std.mem.eql(u8, header_ascii, "\\H")){
		std.log.warn("Expected GPAK file {s} to start with \"\\H\", but it didn't!", .{
			gpak_path,
		});
		return error.GpakWrongHeader;
	}
	const header_remaining = try reader.takeInt(u16, .little);
	if(header_remaining != 0){
		std.log.warn("Expected GPAK file {s} to have two 0 bytes following \"\\H\", but it didn't!", .{
			gpak_path,
		});
		return error.GpakWrongHeader;
	}
	
	// Now that we've parsed the header, we can begin parsing the virtual filesystem.
	while(true) {
		// std.log.info("Attempting to parse header of file at offset 0x{X:0>8}", .{i}); // sponge
		
		// A file is defined by a u16 representing the length of the filepath, then the filepath 
		// itself, then a u32 representing the length of the file in bytes.
		const filepath_len = try reader.takeInt(u16, .little);
		const filepath = try reader.take(filepath_len);
		
		// Dupe the filepath and shove it into the ArrayList.
		// This is so the memory doesn't get stolen out from under our feet as the reader 
		// forgets about this part of the file later.
		// 
		// We also have to do this BEFORE reading the file length, because if we don't, we get very 
		// strange errors which are related to the reader calling .rebase() and rug-pulling this 
		// memory out from under us.
		try file_paths.append(gpa, try gpa.dupe(u8, filepath));
		
		const file_length = try reader.takeInt(u32, .little);
		
		try file_lengths.append(gpa, file_length);
		
		// If the u32 is exactly C9 2A 00 00, we treat it as a terminator for this loop.
		// This may become a failure-case in updated or customised versions of the GPAK file.
		if(file_length == 10953) break;
	}
	
	// We're gonna be using std.Progress to clear the terminal and display a progress bar.
	// This gives the user feedback that the application is actually working towards something- 
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
		
		@memcpy(&progress_filename_buf, filepath[0..@min(filepath.len, std.Progress.Node.max_name_len)]);
		progress_filename.setName(progress_filename_buf[0..@min(filepath.len, std.Progress.Node.max_name_len)]);
		
		// std.log.info("Length of file {s}: 0x{X} b", .{filepath, file_length}); // sponge
		
		// Save it to the host filesystem.
		if(std.fs.path.dirname(filepath)) |filepath_dir| {
			// Make the subdirectories required to hold the output file.
			try output_dir.createDirPath(io, filepath_dir);
		} else {
			@branchHint(.cold);
		}
		// Make the output file.
		const outfile = try output_dir.createFile(io, filepath, .{});
		defer outfile.close(io);
		
		// Make a writer for the file.
		var outfile_writer_buffer: [4096]u8 = undefined;
		var outfile_writer: std.Io.File.Writer = outfile.writer(io, &outfile_writer_buffer);
		const writer: *std.Io.Writer = &outfile_writer.interface;
		
		// Stream the file, 4096 bytes at a time.
		var chunk_prev: usize = undefined;
		var chunk: usize = 0;
		while(chunk != file_length){
			chunk_prev = chunk;
			chunk = @min(file_length, chunk + outfile_writer_buffer.len);
			_ = try writer.write(try reader.take(chunk - chunk_prev));
			try writer.flush();
		}
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
		\\<path to gpak file> <(OPTIONAL) path to output directory>
		\\
		\\Only supports unpacking gpak files currently, but in future I hope 
		\\to support packing a directory into a gpak file for the purposes of modding.
		, .{
			options.version,
		},
	);
}
