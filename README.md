# mewgenics_gpak_util
Command-line utility primarily intended for unpacking Mewgenics (2026)'s resources.gpak file.
Written in [Zig](https://ziglang.org).

## About Mewgenics and GPAK
If you own Mewgenics on Steam, you might notice that it only has three files: Mewgenics.exe, resources.gpak and steam_api64.dll.
This kind of thing is advantageous for game development; store all your assets in one big bundle, so you only have to make one filesystem call to have access to all of them.

The .gpak file format is particularly simple:
- It begins with \H to identify its header, then two 0-bytes
- After that, a block of "u16 string_length; (string_length)u8 string; u32 filesize" identifies each file in the pak
- After this block finishes, the raw, uncompressed file data occupies the rest of the file
- The file data is given in the same order as the filenames, so you don't ever need to store offsets

This makes it a relatively compact way to encode a large archive of files, and also very, very easy to pack or unpack.

## About this utility
All you do is pass in the absolute path to your gpak file, and optionally the absolute path to a directory you want to unpack into.
If you don't pass in an output directory, it'll just spit the unpacked files into whatever directory the executable is running inside (note: distinct from the current working directory).

Right now, it only supports unpacking GPAK files, but in future I might make it so that the first argument is a "mode", and support packing GPAK files from a source directory.

That is, if I can tear myself away from the game long enough!
