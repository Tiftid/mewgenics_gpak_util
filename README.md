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

## Some fun things in the extracted files
- The game's graphics are primarily .swf files, meaning that [Edmund](https://en.wikipedia.org/wiki/Edmund_McMillen) is still a Flash chad in 2026
- That song where they go "cat fight cat fight" lives at audio/music/tutorial/katfight_boss.ogg

## Future plans
I intend to add a "patch" mode, where you provide the following things:
- The path to an existing gpak file to patch
- A [ZON](https://ziglang.org/documentation/master/std/#std.zon) file describing how to patch the gpak
- The path to a directory containing the files to patch in (including the ZON file; it won't be a separate argument)
- The ZON file will probably be laid out as follows:
  - The root of the file will be a struct with three fields; "remove", "add" and "override"
  - The "remove" field is a list of filepaths to completely remove from the original gpak
  - The "add" field is a list of filepaths relative to the patch directory to add to the gpak
  - The "override" field is a list of structs; the first field is a filepath relative to the gpak root, and the second field is a filepath relative to the patch root; the file in the gpak will be replaced with the patch file

The intent behind doing this is to make mods distributable; instead of having to distribute an entire 4.5 GB gpak file which contains mostly unmodified base-game content, you can distribute a handful of files to be used with the patch mode of this utility.
