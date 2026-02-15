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

## What's that example_patch folder?
Patch mode has recently landed with v0.0.3!
This is a new mode that allows you to distribute a lightweight "patch", which is a small folder of files and a "patch.zon" file that describes how to patch them into the gpak file.
This is significantly easier to distribute than an entire, packed gpak which mostly contains unmodified base-game assets.

example_patch contains the patch I used for testing this mode, and you should be able to use it to patch your own resources.gpak to test if it works on your system too.
