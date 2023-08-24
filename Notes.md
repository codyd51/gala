
Need to assemble some shellcode
Assemble it with as, but that includes a MachO wrapper -- just want the raw inner bytes
Pull them out with strongarm, but strongarm crashes due to missing load command when trying to read the symtab
OK make a full binary, but ld doesn't like missing symbols

as -arch armv7 assemble2.s -o dumper_macho.o

 ld dumper_macho.o
Undefined symbols for architecture armv7:
  "_main", referenced from:
     implicit entry/start for main executable
ld: symbol(s) not found for architecture armv7

 ld dumper_macho.o -U _main
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture armv7

 ld dumper_macho.o -U _main -framework libSystem.dylib -o test.o
ld: framework not found libSystem.dylib

man page mentions "static"
 ld dumper_macho.o -U _main -o test.o -static
Undefined symbols for architecture armv7:
  "start", referenced from:
     -u command line option
ld: symbol(s) not found for architecture armv7

ld dumper_macho.o -U _main -U start -static -o test.o

still missing a load command when trying to read the bound symbols (i guses it's linkedit missing, since it's -static')
just comment out the line in strongarm


https://archive.conference.hitb.org/hitbsecconf2013kul/materials/D2T1%20-%20Joshua%20'p0sixninja'%20Hill%20-%20SHAttered%20Dreams.pdf
" LimeRa1n appears to be a race condition heap buffer overflow in USB stack.
•  After release I asked @geohot to explain why it worked.
•  He said he had no clue, but I will speculate on my theory in the next part.""

https://ipsw.me/download/iPhone3,1/10B329

difficult to write anything that plays around in userspace because there's no way to set up a toolchain for iOS 4 / iOS 6 -- so bootROM exploits are the only good choice


can't use "const char* x = "..." in C becuase it'll be put in __cstring, which is lost when we creaet the shellcode
any strings need to be `.asciz` in assembly and loaded that way

can't really load the address using extern in C, because it's relative to PC
solution: pass the address from asm to the C function
fiddled a lot with ldr =symbol, etc, finally got `adr symbol` and it workrs


load_selected_image returning -1! but it's directly from the IPSW?

We acutally need two kinds of patches: the structured "replace these instructions with these other instructions" that we've been using for hand-written patches,
and a "replace this blob with another blob", which is useful for injecting a tiny test program. The latter is useful when injecting shellcode to do a bit of extra logging when debugging something going wrong

Kept running off into opcode zero, needed to do pop {pc}

When I first wrote "INJECTED LOG" it'd overwrite critical instructions next door!

We're now able to inject extra logging anywhere we like, which is really helpful for tracking down exactly what's going on

Takes about one minute from starting to recompile/put in DFU to result

Patchfinder -- good for the same patches for multiple OS builds at the same version, but I was doing diff. versions that all had diff. code. 

I was a tewak developer. One thing that always seemed like black magic to me, though, was the process of jailbreaking itself. Taking an iOS device off the shelf, and performing obscene rituals and reciting the eldirtch incandations until the shackles drop away. The real work has been done by my forebears, in particular posixninja and axiomx, who have graciously shared their knowledge via open source.

I thought it was poking a live/running system, but instead this is no longer iOS: it's very close to iOS, but we're actually running a custom OS distribution

Madea  program that can dump register state over dprintf

In the blog post, we could 'show' a disassembler, and when you patch this, then insert shellcode there, you get a register dump, then when you patch this other thing, you get a different dump. 

Finally found xerub's xpwntool which has some fixes?

# 3 types of patches:

1. structured patch
difficult to find where the relevant code was, had to start form random places looking for strings/xrefs that looked like they could be relevant, like the game where you try to traverse wikipedia in the fewest clicks
One thing that i think is really interesting about this is that no one has publicly admitted that they know exactly how it works. geohot says "i have no idea", and p0sixninja has theories. the magic of fuzzing closed-source binaries: it's like a benevolent gift that we can use but don't understand

I did a failed restore that cleared NAND before failing, so now I can't boot the device at all until I patch the validation -- good incentive!

Now we're really in a full system -- there's a filesystem that loads Mach-Os, and the binaries are written in Objective-C (or at least use CFStrings) -- there's dynamic linking, `Foundation.framework`, etc
This is where you really get the sense that you're running something that's no longer under your control

void AppleUSBDeviceMux::handleConnectResult(BulkUSBMuxSession*, errno_t) new session to port 12345 failed: 61
int AppleMobileFileIntegrity::validateCodeDirectoryHashInDaemon(vnode*, uint8_t*): no registered daemon port
Sandbox: hook..execve() killing pid 11: outside of container && !i_can_has_debugger

com.apple.launchd 1     com.apple.launchd 1     *** launchd[1] has started up. ***

Bug where I was assuming there was a single virtual base, but Mach-Os have different segments that can have different relative offsets from the vbase to file data, so I was overwriting random data in the binary

Boot image was by far the most difficult part -- thousands of lines of notes comparing register snapshots between valid and invalid image
Once that was all working, it was trivial to port the patches to iBEC

entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2

If ASR fails to validate source, you have to unplug/re-plug to get it to work again?

Did not need to un-re-plug to get it to work, after flashing LLB failde

ASR sends over plists to report progress, request the next image, etc

virtual bool AppleMobileFileIntegrity::start(IOService*): built Jun  1 2010 18:13:35
virtual bool AppleMobileFileIntegrity::start(IOService*): unrestricted task_for_pid enabled by boot-arg
virtual bool AppleMobileFileIntegrity::start(IOService*): signature enforcement disabled by boot-arg
virtual bool AppleMobileFileIntegrity::start(IOService*): signature enforcement disabled by boot-arg
virtual bool AppleMobileFileIntegrity::start(IOService*): cs_enforcement disabled by boot-arg

> As I mentioned somewhere before, xpwntool often produces broken IMG3 files (especially kernelcaches and logos) in my case. So I'll use reimagine instead, because I've never had any issues with it

Part 1: Gaining Entry
Part 2: Bootstrapping the bootchain? Something B-bootchain / bypassing the bootchain?

restored_external, people just overwrite the `restored_external` binary to do anything as it's conveniently set up to run at boot. We _could_ modify the launchd stuff to run a different binary instead, but this is easier.

asr sends tons of redundant plist metadata on every exchange

rc ) grep -arl "Authentication" /Volumes/ramdisk/
/Volumes/ramdisk//System/Library/Frameworks/IOKit.framework/Versions/A/IOKit
/Volumes/ramdisk//System/Library/Frameworks/Security.framework/Security
/Volumes/ramdisk//usr/lib/libSystem.B.dylib
/Volumes/ramdisk//usr/local/standalone/firmware/ICE04.05.04_G.fls

$ grep -arl "Authentication error" /Volumes/ramdisk/
/Volumes/ramdisk//usr/lib/libSystem.B.dylib

"Authentication error" comes from libSystem.B.dylib, it's because it's strerror()!

/usr/sbin/asr restore --source asr://localhost:12345 --target /dev/disk0s1 -erase --debug --verbose

Finally got register dumps from asr:

src ) ssh -oHostKeyAlgorithms=+ssh-dss root@localhost -p 2222
root@localhost's password:
Use mount.sh script to mount the partitions
Use reboot_bak to reboot
Use 'device_infos' to dump EMF keys (when imaging user volume)
-sh-4.0# /usr/sbin/asr restore --source asr://localhost:12345 --target /dev/disk0s1 -erase --debug --verbose

Decrypting then re-encrypting the ramdisk immediately makes ASR succeed, so it's not xpwntool problem?
What if the name doesn't end in .dmg? Still works

*** CALLING _mount_dmg CAUSES THE IMAGE TO BE INVALID SOMEHOW?!

=======================================
::
:: iBEC for n90ap, Copyright 2010, Apple Inc.
::
::      BUILD_TAG: iBoot-889.24
::
::      BUILD_STYLE: RELEASE
::
::      USB_SERIAL_NUMBER: CPID:8930 CPRV:20 CPFM:03 SCEP:01 BDID:00 ECID:00000363F615C377 IBFL:00 SRNM:[84033X5RA4S]
::
=======================================

Entering recovery mode, starting command prompt
creating device tree at 0x43f00000 of size 0xe04c, from image at 0x41000000
creating ramdisk at 0x44000000 of size 0xd15000, from image at 0x41000000
panic: arm_exception_abort: ARM undefined instruction abort in supervisor mode at 0x61000064 due to <unknown cause>: far 0x61000064 dfsr 0xffffffff
r0 0x5ff00f8a 0x00000000 0x00000000 0x47415244
r4 0x5ff1d044 0x00000000 0x00000000 0x00000000
r8 0x5ff16940 0x00000000 0x00000001 0x00000075 0x00000000
sp 0x5ff43085 lr 0x5ff16950 spsr 0x20000053

Is "Hardware AES" shown before or after the delay?
For VALID, "Hardware AES" shows up for the first time AFTER the delay!
For INVALID, "Hardware AES" shows up ONCE BEFORE the delay!
Actually, maybe for invalid it only shows after the delay
It does look like "Hardware AES" is always after the wait

Trying to patch a random byte in the DMG instead of mounting it
Changing a single byte in the restore ramdisk causes the restore to fail...

Changing any bytes at all in the DMG causes the restore to fail...

ssh mount.sh
scp -P 2222 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-dss /Users/philliptennen/Documents/Jailbreak/tools/xpwn/dmg/UDZO-2.dmg root@localhost:/mnt2
ssh /usr/sbin/asr restore --source /mnt2/UDZO-2.dmg --target /dev/disk0s1 --erase --debug --verbose
    /usr/sbin/asr restore --source /mnt2/UDZO-2.dmg --target /dev/disk0s1 -erase --debug --verbose

Procedure will be:
First boot
SSH in and mount FS
SCP rootFS
Flash with ASR
Unmount/reboot?
Then, just start the restore?

Procedure:
First boot
SSH in and mount FS
SCP rootFS
Then, just start the restore?

# Test1
Mount Data
SCP rootFS
Restore to System
fsck System
Reboot
Restored, don't wipe and don't run asr
disk0s2s1: ioctl(_IOW,'d',24,4) is unsupported.
** /dev/rdisk0s2s1
Executing fsck_hfs (version diskdev_cmds-488.1.7~39).
** Checking Journaled HFS Plus volume.
** Detected a case-sensitive volume.
** Checking extents overflow file.
** Checking catalog file.
** Checking multi-linked files.
** Checking catalog hierarchy.
** Checking extended attributes file.
** Checking volume bitmap.
** Checking volume information.
** The volume Data appears to be OK.
executing /sbin/mount
entering fixup_var
copy /mnt1/private/var to /mnt2 failed: 0x

# Test2
Mount Data
SCP rootFS
Restore to System
fsck /dev/disk0s1
Mount /dev/disk0s1
scp /mnt1/private/var to host
scp back to /mnt2/
rm -rf /mnt1/private/var
scp /mnt1/etc/fstab to host
Edit /dev/disk0s2 to /dev/disk0s2s1
scp fstab back to device
Reboot
(PT: Maybe need to fsck Data?)
Restored, don't wipe, don't run asr, don't fixup var

* Need to make sure /private/var still exists?

Saving ramdisk binaries to patched_images/, now with an SSH ramdisk booted I can patch, scp, and rerun ASR to debug. No reboot needed, speedy cycle!

Dec 31 16:21:36 localhost OSInstaller[396]: [RESTORE] erasing disk 'OS X'
Dec 31 16:21:36 localhost OSInstaller[396]: [RESTORE] erase started
Dec 31 16:21:37 localhost diskmanagementd[400]: DM ->T+[DMToolBootPreference getPartitionBootability:]: inUDS=0x7fd3db424448=disk0s2=OS X
Dec 31 16:21:37 localhost diskmanagementd[400]: DM ..T+[DMToolBootPreference getPartitionBootability:]: PMBootable=1            (bootable right now without any further action)
Dec 31 16:21:37 localhost diskmanagementd[400]: DM ..T+[DMToolBootPreference getPartitionBootability:]: PMBootCapable=0         (bootable if you call MKCFPrepareBootDevice)
Dec 31 16:21:37 localhost diskmanagementd[400]: DM ..T+[DMToolBootPreference getPartitionBootability:]: PMBootSurgeryRequired=0 (for primitive MBR on BIOS, add boot block and loader)
Dec 31 16:21:37 localhost diskmanagementd[400]: DM ..T+[DMToolBootPreference getPartitionBootability:]: PMFSSurgeryRequired=0   (for primitive MBR on BIOS, add boot block and loader)
Dec 31 16:21:37 localhost diskmanagementd[400]: DM ..T+[DMToolBootPreference getPartitionBootability:]: PMNewfsRequired=0       (bootable with MKCFPrep but it will rudely carve)
Dec 31 16:21:37 localhost diskmanagementd[400]: DM <-T+[DMToolBootPreference getPartitionBootability:]: MKerr=0 out=4=0x4
Dec 31 16:21:42 localhost OSInstaller[396]: [RESTORE] erase completed

When trying to create a custom `umount`:
ld: warning: Csu support file -lcrt1.o not found, changing to target iOS 7.0 where it is not needed
ld: library not found for -lgcc_s.1
clang: error: linker command failed with exit code 1 (use -v to see invocation)
But then it's present on-device / in the ramdisk, so we can copy it from there:
Packages ) ssh -oHostKeyAlgorithms=+ssh-dss root@localhost -p 2222
root@localhost's password:
Use mount.sh script to mount the partitions
Use reboot_bak to reboot
Use 'device_infos' to dump EMF keys (when imaging user volume)
-sh-4.0# ls /usr/lib
dyld			     libbsm.0.dylib	    libedit.2.dylib	  libiconv.2.dylib	libncurses.5.dylib     libsqlite3.0.dylib     libutil.dylib	libz.1.dylib
libIOAccessoryManager.dylib  libbz2.1.0.dylib	    libgcc_s.1.dylib	  libicucore.A.dylib	libobjc.A.dylib        libstdc++.6.0.9.dylib  libutil1.0.dylib	system
libSystem.B.dylib	     libcrypto.0.9.8.dylib  libhistory.6.0.dylib  libncurses.5.4.dylib	libreadline.6.0.dylib  libstdc++.6.dylib      libz.1.2.3.dylib

Still `Illegal Instruction` and LC_ENTRY_POINT, no LC_UNIXTHREAD...
xcrun -sdk /Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk clang -arch armv7 -fno-PIC -fno-pie -mios-version-min=2.0 umount.c -o umount3 -v -L./
It works! LC_UNIXTHREAD is present and it runs on-device

unmount works:
-sh-4.0# ls /mnt2/
018-6303-385.dmg  Keychains	       MobileDevice  audit  ea	   folders  log   mobile  preferences	       root  spool  var  wireless
018-6306-403.dmg  Managed Preferences  UDZO-3.dmg    db     empty  keybags  logs  msgs	  repacked_rootfs.dmg  run   tmp    vm
-sh-4.0# /usr/local/bin/umount /mnt2/
Unmounting /mnt2/...
Return code 0
-sh-4.0# ls /mnt2/

umount ) xcrun -sdk /Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk clang -arch armv7 -fno-PIC -fno-pie -mios-version-min=2.0 umount.c -o umount -L./ -F/Volumes/ramdisk/System/Library/PrivateFrameworks/ -framework MediaKit -L/Volumes/ramdisk/System/Library/PrivateFrameworks/MediaKit.framework/
Undefined symbols for architecture armv7:
"_MKMakeDeviceBootable", referenced from:
_main in umount-5ed908.o
ld: symbol(s) not found for architecture armv7
clang: error: linker command failed with exit code 1 (use -v to see invocation)

Just copy /ramdisk/MediaKit.framework to /Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped...
Can't find _MKMakeBootDevice symbol? Try dlopen and dlsym()...
But dlsym returns 0 for _MKMakeBootDevice! How about a different symbol? That works, go back to static linking?

ld: illegal text-relocation to '_printf' in /Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk/usr/lib/libSystem.dylib from '_main' in /var/folders/y0/clprvktj3b5__hkvm2p4m_yr0000gn/T/umount-6c9a27.o for architecture armv7
Solution: remove -fno-pie / -fno-PIC (and -mlong-calls not needed)

/dev/md0:
Trying to find MKCFPrepareBootDevice...
Found MKCFPrepareBootDevice: 0x6ce159
MKCFPrepareBootDevice() returned 22

/dev/disk0s1:
Trying to find MKCFPrepareBootDevice...
Found MKCFPrepareBootDevice: 0x6ce159
MKCFPrepareBootDevice() returned 16

/dev/rdisk0:
Trying to find MKCFPrepareBootDevice...
Found MKCFPrepareBootDevice: 0x6ce159
MKCFPrepareBootDevice() returned 22

restored_external is ran immediately thanks to /etc/rc.boot
-sh-4.0# cat /etc/rc.boot
#!/bin/sh

# remount r/w

mount /

# free space

rm /usr/local/standalone/firmware/*
rm /usr/standalone/firmware/*
mv /sbin/reboot /sbin/reboot_bak

# Fix the auto-boot

nvram auto-boot=1

# Start SSHD

/sbin/sshd

# Do the stuff original rc.boot did

/usr/local/bin/restored_external
/usr/local/bin/restored_update
/usr/local/bin/restored
/usr/libexec/ramrod/ramrod

Dead LCD Bug
Locking a device with an unsigned bootchain (specifically the LLB) while on battery power causes iOS to disable the LCD. A restore to the latest iOS is needed to fix this.

/Volumes/Apex8A293.N90OS/System/Library/CoreServices/SpringBoard.app/HeadsetBatteryBG_16.png
Something in CoreServices to set OS name, could be worth trying to change?
/Volumes/Apex8A293.N90OS/System/Library/CoreServices/SpringBoard.app/MCNext.png
/Volumes/Apex8A293.N90OS/System/Library/CoreServices/SpringBoard.app/mute.png
/Volumes/Apex8A293.N90OS/System/Library/CoreServices/SpringBoard.app/silent@2x.png
/Volumes/Apex8A293.N90OS/System/Library/CoreServices/SpringBoard.app/recalibrateBezel@2x.png
/Volumes/Apex8A293.N90OS/System/Library/CoreServices/SpringBoard.app/RotationUnlockButton@2x.png
/Volumes/Apex8A293.N90OS/System/Library/CoreServices/SpringBoard.app/SBDockBG-old.png


pinot_init()
mipi_dsim_init()
pinot_init(): read of pinot panel id failed
pinot_init(): pinot_panel_id:      0x00000000
pinot_init(): pinot_default_color: 0x00000000
pinot_init(): pinot_backlight_cal: 0x00000000
mipi_dsim_quiesce()

entering set_boot_stage
unable to get display service
found PTP interface

Need restored to create the partitions (so we can send the rootFS to /mnt2), but need to wait in the middle of restored so we can actually send it... 2 options:
introduce a reboot after asr and rerun restored
embed the "wait for scp"

You can pass ReadOnlyRootFilesystem: true/false in the restored options plist to ask iOS to mount the root filesystem as R/W for you!

Managed to mount the RW filesystem:
Here's what it looks like when RO:
/dev/disk0s1 on / (hfs, local, read-only, noatime)
/dev/disk0s2s1 on /private/var (hfs, local, nodev, nosuid, journaled, noatime, protect)

And R/W:
com.apple.launchd 1     com.apple.launchd 1     *** launchd[1] has started up. ***
Bug: launchctl.c:3599 (24106):17: ioctl(s6, SIOCAIFADDR_IN6, &ifra6) != -1
Bug: launchctl.c:3803 (24106):2: sysctl(nbmib, 2, &nb, &nbsz, NULL, 0) == 0
Running fsck on the boot volume...
Executing fsck_hfs (version diskdev_cmds-488.1.7~39).
Executing fsck_hfs (version diskdev_cmds-488.1.7~39).
/dev/disk0s1 on / (hfs, local, noatime)
/dev/disk0s2s1 on /private/var (hfs, local, nodev, nosuid, journaled, noatime, protect)

iPhone:~ root# uname -a
Darwin iPhone 10.3.1 Darwin Kernel Version 10.3.1: Wed May 26 22:28:33 PDT 2010; root:xnu-1504.50.73~2/RELEASE_ARM_S5L8930X iPhone3,1 arm N90AP Darwin

launchctl unload /System/Library/LaunchDaemons/com.apple.SpringBoard.plist

Compass is 44mb?!

2023-08-13 14:32:03.850 MobileCydia[172:613] Setting Language: en_US
_assert(13:file != NULL)@Sources.mm:51[CydiaWriteSources]
/Volumes/iphne/private/var/tmp/cydia.log

try create /Volumes/iphne/private/var/root/Library/Caches/com.saurik.Cydia

r0 = fopen("/etc/apt/sources.list.d/cydia.list", "w");
/Users/philliptennen/Downloads/redsn0w_mac_0.9.15b3/redsn0w.app/Contents/MacOS/Cydia/private/etc/apt/sources.list.d/saurik.list
mismatch?

https://github.com/zodttd/wolf3d

iPhone:~ root# su - mobile
iPhone:~ mobile$ /var/setuid_test
Attempting setuid...
returned -1
Still sandboxed
iPhone:~ mobile$ /Applications/C
Calculator.app/ Compass.app/    Contacts.app/   Cydia.app/
iPhone:~ mobile$ /Applications/Cydia.app/MobileCydia
2023-08-13 18:59:38.701 MobileCydia[438:107] Setting Language: en_US
_assert(13:file != NULL)@Sources.mm:51[CydiaWriteSources]

Modify contents of /Volumes/Apex8A293.N90OS/System/Library/Lockdown/Services.plist?

iPhone:~ root# /var/setuid_test
Attempting setuid...
returned 0
Freeeeeeee
iPhone:~ root# su - mobile
iPhone:~ mobile$ /var/setuid_test
Attempting setuid...
returned -1
Still sandboxed

"Breaking out of the sandbox is toughest stage of jailbreaking." https://newosxbook.com/files/HITSB.pdf

Kernel cache patches aren't applying?!
Pulled kernelcache off the device and it doesn't have our patches! Need to modify our idevicerestore to send our patched kernelcache?

maybe we can apply patches at runtime for faster turnaround? enable /dev/kmem patch

can't read kmem, maybe need tfp0?

two calls to chgproccnt in the xnu source for setuid
find task_for_pid: port_name_to_task xrefs

page fault when reading memory 0x0
kernel abort type 4: fault_type=0x1, fault_addr=0x0
r0: 0x8a0b5028  r1: 0x00000000  r2: 0x00000400  r3: 0x8a0b5028
r4: 0xc02a5f18  r5: 0x8a0b5000  r6: 0x00000428  r7: 0xd2a83e4c
r8: 0x00000000  r9: 0x88c3ccc0 r10: 0x8a0b5028 r11: 0x00000400
12: 0x80000000  sp: 0xd2a83e40  lr: 0x8003a0d7  pc: 0x8006721c
cpsr: 0x80000013 fsr: 0x00000007 far: 0x00000000

-sh-4.0# /kmem_test
task_for_pid_0 = 0
CE FA ED FE 0C 00 00 00  09 00 00 00 02 00 00 00  |  ................
0C 00 00 00 54 08 00 00  01 00 00 00 01 00 00 00  |  ....T...........
D0 01 00 00 5F 5F 54 45  58 54 00 00 00 00 00 00  |  ....__TEXT......
00 00 00 00 00 10 00 80  00 30 24 00 00 00 00 00  |  .........0$.....
00 30 24 00 05 00 00 00  05 00 00 00 06 00 00 00  |  .0$.............
00 00 00 00 5F 5F 74 65  78 74 00 00 00 00 00 00  |  ....__text......
00 00 00 00 5F 5F 54 45  58 54 00 00 00 00 00 00  |  ....__TEXT......
00 00 00 00 00 20 00 80  44 0B 1E 00 00 10 00 00  |  ..... ..D.......
0C 00 00 00 00 00 00 00  00 00 00 00 00 04 00 80  |  ................
00 00 00 00 00 00 00 00  5F 5F 63 73 74 72 69 6E  |  ........__cstrin
67 00 00 00 00 00 00 00  5F 5F 54 45 58 54 00 00  |  g.......__TEXT..
00 00 00 00 00 00 00 00  44 2B 1E 80 07 78 03 00  |  ........D+...x..
44 1B 1E 00 02 00 00 00  00 00 00 00 00 00 00 00  |  D...............
02 00 00 00 00 00 00 00  00 00 00 00 5F 5F 63 6F  |  ............__co
6E 73 74 00 00 00 00 00  00 00 00 00 5F 5F 54 45  |  nst.........__TE
58 54 00 00 00 00 00 00  00 00 00 00 4C A3 21 80  |  XT..........L.!.
E0 4E 02 00 4C 93 21 00  02 00 00 00 00 00 00 00  |  .N..L.!.........
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
69 6E 69 74 63 6F 64 65  00 00 00 00 00 00 00 00  |  initcode........
5F 5F 54 45 58 54 00 00  00 00 00 00 00 00 00 00  |  __TEXT..........
2C F2 23 80 FE 46 00 00  2C E2 23 00 02 00 00 00  |  ,.#..F..,.#.....
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
00 00 00 00 5F 5F 63 6F  6E 73 74 72 75 63 74 6F  |  ....__constructo
72 00 00 00 5F 5F 54 45  58 54 00 00 00 00 00 00  |  r...__TEXT......
00 00 00 00 2C 39 24 80  04 01 00 00 2C 29 24 00  |  ....,9$.....,)$.
02 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
00 00 00 00 00 00 00 00  5F 5F 64 65 73 74 72 75  |  ........__destru
63 74 6F 72 00 00 00 00  5F 5F 54 45 58 54 00 00  |  ctor....__TEXT..
00 00 00 00 00 00 00 00  30 3A 24 80 F8 00 00 00  |  ........0:$.....
30 2A 24 00 02 00 00 00  00 00 00 00 00 00 00 00  |  0*$.............
00 00 00 00 00 00 00 00  00 00 00 00 01 00 00 00  |  ................
48 01 00 00 5F 5F 44 41  54 41 00 00 00 00 00 00  |  H...__DATA......
00 00 00 00 00 40 24 80  00 20 05 00 00 30 24 00  |  .....@$.. ...0$.
00 C0 01 00 03 00 00 00  03 00 00 00 04 00 00 00  |  ................
00 00 00 00 5F 5F 64 61  74 61 00 00 00 00 00 00  |  ....__data......
00 00 00 00 5F 5F 44 41  54 41 00 00 00 00 00 00  |  ....__DATA......
00 00 00 00 00 40 24 80  8D B2 01 00 00 30 24 00  |  .....@$......0$.
0C 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
00 00 00 00 00 00 00 00  5F 5F 73 79 73 63 74 6C  |  ........__sysctl
5F 73 65 74 00 00 00 00  5F 5F 44 41 54 41 00 00  |  _set....__DATA..
00 00 00 00 00 00 00 00  90 F2 25 80 00 08 00 00  |  ..........%.....
90 E2 25 00 02 00 00 00  00 00 00 00 00 00 00 00  |  ..%.............
00 00 00 00 00 00 00 00  00 00 00 00 5F 5F 63 6F  |  ............__co
6D 6D 6F 6E 00 00 00 00  00 00 00 00 5F 5F 44 41  |  mmon........__DA
54 41 00 00 00 00 00 00  00 00 00 00 00 00 26 80  |  TA............&.
A4 99 01 00 00 00 00 00  0C 00 00 00 00 00 00 00  |  ................
00 00 00 00 01 00 00 00  00 00 00 00 00 00 00 00  |  ................
5F 5F 62 73 73 00 00 00  00 00 00 00 00 00 00 00  |  __bss...........
5F 5F 44 41 54 41 00 00  00 00 00 00 00 00 00 00  |  __DATA..........
00 A0 27 80 A4 B6 01 00  00 00 00 00 0C 00 00 00  |  ..'.............
00 00 00 00 00 00 00 00  01 00 00 00 00 00 00 00  |  ................
00 00 00 00 01 00 00 00  D0 01 00 00 5F 5F 4B 4C  |  ............__KL
44 00 00 00 00 00 00 00  00 00 00 00 00 60 29 80  |  D............`).
00 20 00 00 00 F0 25 00  00 20 00 00 03 00 00 00  |  . ....%.. ......
03 00 00 00 06 00 00 00  00 00 00 00 5F 5F 74 65  |  ............__te
78 74 00 00 00 00 00 00  00 00 00 00 5F 5F 4B 4C  |  xt..........__KL
44 00 00 00 00 00 00 00  00 00 00 00 00 60 29 80  |  D............`).
E0 0A 00 00 00 F0 25 00  02 00 00 00 00 00 00 00  |  ......%.........
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
5F 5F 63 6F 6E 73 74 72  75 63 74 6F 72 00 00 00  |  __constructor...
5F 5F 4B 4C 44 00 00 00  00 00 00 00 00 00 00 00  |  __KLD...........
E0 6A 29 80 04 00 00 00  E0 FA 25 00 02 00 00 00  |  .j).......%.....
00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
00 00 00 00 5F 5F 64 65  73 74 72 75 63 74 6F 72  |  ....__destructor


Mobile user can read /etc/test, but not open it as writable:
(The first run is when I was opening the file as read-only)
gala ) ssh -oHostKeyAlgorithms=+ssh-dss mobile@localhost -p 2222
mobile@localhost's password:
-sh-4.0$ /var/setuid_test
Attempting setuid...
returned -1
Wed Aug 16 19:18:38 2023
Poking /var/mobile/foo... Accessible
Poking /etc/test... Accessible

Wed Aug 16 19:18:43 2023
Poking /var/mobile/foo... Accessible
Poking /etc/test... Accessible

^C
# Second run, opening as "w"
-sh-4.0$ /var/setuid_test
Attempting setuid...
returned -1
Wed Aug 16 19:19:01 2023
Poking /var/mobile/foo... Accessible
Poking /etc/test... INACCESSIBLE

Use dmesg?!

AppleKeyStore:cp_key_store_action(1)
AppleKeyStore:cp_key_store_action(0)
The second keystore action fails, then the system wants to shut down
AppleBCMWLAN::powerOff Ready to power off
AppleBCMWLAN::setPowerStateGated() : Powering On
com.apple.launchd 1     com.apple.launchd 1     System: Still alive with 3/2 (normal/anonymous) children. In Normal phase of shutdown.
com.apple.launchd 1     com.apple.syslogd 17    (com.apple.syslogd) PID is still valid
com.apple.launchd 1     com.apple.securityd 37  (com.apple.securityd) PID is still valid
com.apple.launchd 1     com.apple.fairplayd.N90 26      (com.apple.fairplayd.N90) PID is still valid
com.apple.launchd 1     0x100890.anonymous.launchd 1    (0x100890.anonymous.launchd) PID is still valid
com.apple.launchd 1     0x1006d0.anonymous.sshd 5       (0x1006d0.anonymous.sshd) PID is still valid
com.apple.launchd 1     com.apple.launchd 1     System: Still alive with 3/2 (normal/anonymous) children. In Normal phase of shutdown.
com.apple.launchd 1     com.apple.syslogd 17    (com.apple.syslogd) PID is still valid
com.apple.launchd 1     com.apple.securityd 37  (com.apple.securityd) PID is still valid
com.apple.launchd 1     com.apple.fairplayd.N90 26      (com.apple.fairplayd.N90) PID is still valid
com.apple.launchd 1     0x100890.anonymous.launchd 1    (0x100890.anonymous.launchd) PID is still valid
com.apple.launchd 1     0x1006d0.anonymous.sshd 5       (0x1006d0.anonymous.sshd) PID is still valid
com.apple.launchd 1     com.apple.launchd 1     System: Still alive with 3/2 (normal/anonymous) children. In Normal phase of shutdown.
com.apple.launchd 1     com.apple.syslogd 17    (com.apple.syslogd) PID is still valid
com.apple.launchd 1     com.apple.securityd 37  (com.apple.securityd) PID is still valid
com.apple.launchd 1     com.apple.fairplayd.N90 26      (com.apple.fairplayd.N90) PID is still valid
com.apple.launchd 1     0x100890.anonymous.launchd 1    (0x100890.anonymous.launchd) PID is still valid
com.apple.launchd 1     0x1006d0.anonymous.sshd 5       (0x1006d0.anonymous.sshd) PID is still valid
com.apple.launchd 1     com.apple.launchd 1     System: Still alive with 3/2 (normal/anonymous) children. In Normal phase of shutdown.
com.apple.launchd 1     com.apple.syslogd 17    (com.apple.syslogd) PID is still valid
com.apple.launchd 1     com.apple.securityd 37  (com.apple.securityd) PID is still valid
com.apple.launchd 1     com.apple.fairplayd.N90 26      (com.apple.fairplayd.N90) PID is still valid
com.apple.launchd 1     0x100890.anonymous.launchd 1    (0x100890.anonymous.launchd) PID is still valid
com.apple.launchd 1     0x1006d0.anonymous.sshd 5       (0x1006d0.anonymous.sshd) PID is still valid
com.apple.launchd 1     com.apple.securityd 37  (com.apple.securityd) Exit timeout elapsed (20 seconds). Killing
com.apple.launchd 1     com.apple.fairplayd.N90 26      (com.apple.fairplayd.N90) Exit timeout elapsed (20 seconds). Killing
com.apple.launchd 1     com.apple.launchd 1     System: Stray anonymous job at shutdown: PID 5 PPID 1 PGID 5 sshd
com.apple.launchd 1     com.apple.launchd 1     System: Sending SIGTERM to PID 5 and continuing...
com.apple.launchd 1     com.apple.securityd 37  (com.apple.securityd) Job has overstayed its welcome. Forcing removal.
com.apple.launchd 1     com.apple.launchd 1     System: About to call: reboot(RB_AUTOBOOT).


-sh-4.0# asr_wrapper
*** asr_wrapper startup ***
Succeeded to get service
Got framebuffer service 0x00001307
Framebuffer service name: AppleCLCD
Framebuffer service class: AppleCLCD
Got framebuffer service 0x00001403
Framebuffer service name: AppleRGBOUT
Framebuffer service class: AppleRGBOUT

The native code does substring matching for "CLCD"

Looks like there can only be one 'main display holder'? I had to kill restored_external before my content would display

Ended up just neutering the restored call that claims the display

Patch springboard at runtime to show a UIAlertView

        CGColorRef text_color = CGColorCreate(color_space, (CGFloat[]){0, 0, 0, 1});
        CGContextSetStrokeColorWithColor(display_cgcontext, text_color);
        CGContextSetFillColorWithColor(display_cgcontext, text_color);
        CGContextSetLineWidth(display_cgcontext, 1.0);
        CGContextSelectFont(display_cgcontext, "Helvetica", 40, kCGEncodingMacRoman);
        CGContextSetTextDrawingMode(display_cgcontext, kCGTextFill);

        const char* text = "Receiving filesystem over USB...";
        CGContextShowTextAtPoint(display_cgcontext, 50, 20, text, strlen(text));
Thu Aug 17 15:35:21 localhost asr_wrapper[86] <Error>: No available font implementation.

ASR: *** __NSAutoreleaseNoPool(): Object 0xa09210 of class __NSArrayI autoreleased with no pool in place - just leaking
ASR: *** __NSAutoreleaseNoPool(): Object 0xa08920 of class PTVector autoreleased with no pool in place - just leaking
ASR: *** __NSAutoreleaseNoPool(): Object 0xa08920 of class PTVector autoreleased with no pool in place - just leaking
ASR: *** __NSAutoreleaseNoPool(): Object 0xa08920 of class PTVector autoreleased with no pool in place - just leaking
ASR: *** __NSAutoreleaseNoPool(): Object 0xa08920 of class PTVector autoreleased with no pool in place - just leaking
ASR: *** __NSAutoreleaseNoPool(): Object 0xa09210 of class __NSArrayI autoreleased with no pool in place - just leaking

but @autoreleasepool / NSReleasePool isnt' avialable beacuse foundation sint' favilablea 
end up calling _CFAutoreleasePoolPush

If I just do kill() in a loopwhile waiting for asr to complete, it always returns zero. But if I do kill() then waitpid(WNOHANG), the kill() works correctly
int status = 0;
int ret = waitpid(pid, &status, WNOHANG);
printf("waitpid(%d) = %d, %d\n", pid, ret, status);
if (kill(pid, 0) != 0) {
pid_t
waitpid(pid_t pid, int *stat_loc, int options);

Warning: Window NSWindow 0x124705850 ordered front from a non-active application and may order beneath the active application's windows.

TODO before release:
- Make new visualizations
- Gala communicates status via status messages that the GUI displays
- Record video?
- Write README
- Split blog post into multiple parts?
- Diagnose/fix SSL error?!
- Test CydiaSubstrate?!
- Write up new work?
- Upstream strongarm fix
- Minimize patches
- Explain each patch

localhost:~ root# /System/Library/CoreServices/SpringBoard.app/SpringBoard
2023-08-21 23:33:08.710 SpringBoard[723:4303] Migration complete. (Elapsed time: 1.22 seconds)
2023-08-21 23:33:08.948 SpringBoard[723:107] lockdown says the device is: [WildcardActivated], state is 3
2023-08-21 23:33:08.955 SpringBoard[723:107] lockdown says we've previously registered: [0], state is 0
2023-08-21 23:33:09.007 SpringBoard[723:107] Unable to set Jetsam priority on job with label com.apple.SpringBoard. Error: Operation not permitted
2023-08-21 23:33:10.447 SpringBoard[723:107] WiFi: Joined network XXCombinator (2.4Ghz). WiFi bars visible: NO
2023-08-21 23:33:10.486 SpringBoard[723:107] BTM: attaching to BTServer
2023-08-21 23:33:12.551 SpringBoard[723:107] Received notification that wireless modem state changed. Tethering is now OFF.
2023-08-21 23:33:12.659 SpringBoard[723:107] BTM: posting notification BluetoothAvailabilityChangedNotification
2023-08-21 23:33:13.236 SpringBoard[723:107] Unable to set Jetsam priority on job with label UIKitApplication:com.apple.mobilephone[0x5de5]. Error: Operation not permitted
2023-08-21 23:33:13.262 SpringBoard[723:107] Unable to set Jetsam priority on job with label UIKitApplication:com.apple.mobilemail[0xc0d]. Error: Operation not permitted
2023-08-21 23:33:20.327 SpringBoard[723:107] Unable to set Jetsam priority on job with label UIKitApplication:com.apple.Preferences[0xf05e]. Error: Operation not permitted
2023-08-21 23:33:30.647 SpringBoard[723:d20b] Unable to set Jetsam priority on job with label UIKitApplication:com.apple.Preferences[0xf05e]. Error: Operation not permitted
2023-08-21 23:33:31.913 SpringBoard[723:d20b] Unable to set Jetsam priority on job with label UIKitApplication:com.apple.Preferences[0xf05e]. Error: Operation not permitted

manaegd to get a version of cycript that works, or just had to reboot?

https://global-root-g2.chain-demos.digicert.com won't load / not trusted

When done, jump to 0x345244c6
0x34524388 009A                   ldr        r2, [sp, #0x2c + var_2C]           ; CODE XREF=_SecTrustEvaluate+266
0x3452438a 0723                   movs       r3, #0x7
0x3452438c 4FF0000B               mov.w      fp, #0x0
0x34524390 1360                   str        r3, [r2]

0x34524278 F0B5                   push       {r4, r5, r6, r7, lr}


push {r4, lr}
mov r4, #1
str r4, r1
mov r0, #0
pop {r4, pc}
0x10, 0xb5, 0x04, 0x24, 0x0c, 0x60, 0x00, 0x20, 0x10, 0xbd

launchctl: Dubious ownership on file (skipping): /System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist

default	15:36:05.006223+0100	AMPDevicesAgent	_create_ssl_context (thread 0x16be9b000): ios version is older than 9.0. Disabling tls version 1.2.
default	15:36:05.006458+0100	AMPDevicesAgent	USBMuxConnectByPort:584 Connecting to port 32498 (f2, 7e)
default	15:36:05.021723+0100	AMPDeviceDiscoveryAgent	USBMuxConnectByPort:584 Connecting to port 32498 (f2, 7e)
default	15:36:05.028964+0100	remotepairingd	AMDeviceStartSession (thread 0x1df725fc0): Could not start session with device 8e8366ad7bf1222351522c423aea5fecc9e62793: kAMDInvalidResponseError
default	15:36:05.029078+0100	remotepairingd	_WatchCompanionCapabilitySupported (thread 0x1df725fc0): AMDeviceStartSession failed: 0xe8000013 (kAMDInvalidResponseError)
default	15:36:05.029391+0100	remotepairingd	USBMuxHandleDictionary:1437 Adding event 0x600001eac020 to changelist.
default	15:36:05.029460+0100	remotepairingd	USBMuxHandleDictionary:1437 Adding event 0x600001eac1c0 to changelist.
default	15:36:05.029532+0100	remotepairingd	USBMuxHandleDictionary:1437 Adding event 0x600001eac160 to changelist.
default	15:36:05.029561+0100	remotepairingd	USBMuxHandleDictionary:1437 Adding event 0x600001eac2c0 to changelist.
default	15:36:05.031717+0100	Console	copy_string_value_from_device (thread 0x16bd9b000): AMDeviceCopyValueWithError: 0xe8000016
default	15:36:05.031785+0100	Console	_create_ssl_context (thread 0x16bd9b000): ios version is older than 4.0. Disabling tls version 1.1.
default	15:36:05.031949+0100	Console	lockssl_handshake (thread 0x16bd9b000): SSL handshake fatal lower level error -1: SSL_ERROR_SYSCALL errno (Broken pipe)
default	15:36:05.032469+0100	Console	send_session_start (thread 0x16bd9b000): lockconn_enable_ssl failed and device 1526 (8e8366ad7bf1222351522c423aea5fecc9e62793) is valid...disconnect and reconnect
default	15:36:05.032547+0100	Console	USBMuxConnectByPort:584 Connecting to port 32498 (f2, 7e)

need to make /private/var/gala 777 to make it accessible to MobileSafari

the IOSurface has a Z-order, so any time you kill SpringBoard you see the Gala boot logo again -- this is why you normally see the apple logo!
and it looks like there's normally a spinner there just as a 'hack' to make sure in the worst case the user always sees a spinner?