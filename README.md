# mewgenics_gpak_util
Command-line utility primarily intended for unpacking Mewgenics (2026)'s resources.gpak file.
Written in [Zig](https://ziglang.org).

## About Mewgenics and GPAK
If you own [Mewgenics on Steam](https://store.steampowered.com/app/686060/Mewgenics/), you might notice that it only has three files: Mewgenics.exe, resources.gpak and steam_api64.dll.
This kind of thing is advantageous for game development; store all your assets in one big bundle, so you only have to make one filesystem call to have access to all of them.

The .gpak file format is particularly simple:
- It begins with \H to identify its header, then two 0-bytes (possibly a file format version)
- After that, a block of "u16 string_length; (string_length)u8 string; u32 filesize" identifies each file in the pak
- After this block finishes, the raw, uncompressed file data occupies the rest of the file
- The file data is given in the same order as the filenames, so you don't ever need to store offsets

This makes it a relatively compact way to encode a large archive of files, and also very, very easy to pack or unpack.

## Modes (command-line interface)

### Optional flags for all modes (should follow other arguments)
- header_version=<number>
  - Specifies the header version for the gpak file we're reading or writing. Files with version 1 begin with "\H", files with version 2 begin with "`H". This tool considers version 2 the default, so you'll need to specify "header_version=1" to work with old gpaks.

### unpack
Unpack a gpak file into a directory of files.

Arguments: 
- Path to the gpak file (e.g. "C:\Program Files (x86)\Steam\steamapps\common\Mewgenics\resources.gpak")
- (OPTIONAL) Path to the output directory
  - If this is omitted, the files will be spit in the folder the executable is inside (NOT the CWD)

### pack
Pack a directory of files into a gpak file.

Arguments:
- Path to the input directory
- Path to the gpak file

### patch
Given a directory of files containing a patch.zon file, patch the gpak, removing some files, adding others and overriding others.
An example patch can be found in this utility in "example_patch".

The point of this is to enable light-weight mod distribution; instead of distributing an entire packed 4.5 GB gpak file, you distribute a small folder of files, with the intent that the user will patch them into their own resources.gpak using this mode.

Arguments:
- Path to the input directory
- Path to the gpak file

Optional flags (should follow arguments):
- no_delete_temp
  - Prevents the gpak file from being overwritten with the temp file, leaving it unmodified. The temp file remains, and represents the patched gpak.
- notify_on_failed_add
  - Log a message whenever an add file from the patch already exists in the gpak (failed add).
- notify_on_failed_override
  - Log a message whenever the gpak is missing a corresponding entry for one of the patch's override files.

## Some fun things in the extracted files
- The game's graphics are primarily .swf files, meaning that [Edmund](https://en.wikipedia.org/wiki/Edmund_McMillen) is still a Flash chad in 2026
- That song where they go "cat fight cat fight" lives at audio/music/tutorial/katfight_boss.ogg
- Now that the game's been updated a couple of times, I intend to add a "diff" mode that ascertains the difference between two gpak files, and dumps the result to a ZON file
