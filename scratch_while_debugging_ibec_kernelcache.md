# Without PROD patch
Attempting to validate kernelcache @ 0x41000000

Register dump
0x00000000
0x00000001
0x00000001
0x00000000
0x00000000
0x5ff4a7c0
0x00f00000
0x5ff44500
0x43000000
Kernelcache image not valid
error loading kernelcache

# Without ECID patch
Attempting to validate kernelcache @ 0x41000000

Register dump
0x00000001
0x00000000
0x00000001
0x00000001
0x00000000
0x5ff4a7c0
0x00f00000
0x5ff44500
0x43000000
Kernelcache image not valid
error loading kernelcache

# With ECID patch
Entering recovery mode, starting command prompt
Attempting to validate kernelcache @ 0x41000000
Loading kernel cache at 0x43000000
Uncompressed kernel cache at 0x43000000
load_macho_image: failed to load device tree
error loading kernelcache

# devicetree command

creating device tree at 0x43f00000 of size 0xe04c, from image at 0x41000000

found here: https://www.reddit.com/r/jailbreak/comments/4u7hh8/question_i_am_having_trouble_with_kloader_on_my/

Attempting to validate kernelcache @ 0x41000000
Loading kernel cache at 0x43000000
Uncompressed kernel cache at 0x43000000
gBootArgs.commandLine = [ ]
Installing WIFI Calibration
kernelcache prepped at address 0x40065050