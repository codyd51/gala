
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
fsck System
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