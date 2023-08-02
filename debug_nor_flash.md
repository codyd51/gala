# At AppleImage3NORAccess::start imageVersion: %lx\\n log

*** Register dump
0x8057e288
0x00000003
0x00004732
0x801a12e1
0x82c1af80
0x00000003
0x801a4771
0xd2903ec8
0x80185525


# AMFI patch only, resigned images, orig IPSW:

ASR STATUS: setup
ASR: Validating target...
ASR: done
ASR STATUS: metadata
ASR: Validating source...
AppleUSBDeviceMux::handleConnectResult new session 0x846da600 established 12345<-lo0->49201 12345<-usb->1087
ASR: Using Hardware AES
ASR: Can't gather image metadata
ASR: Could not validate source - Authentication error
ASR STATUS: fail

# AMFI patch, resigned images, orig IPSW, BlobPatch(address=VirtualMemoryPointer(0x0001360a), new_content=bytes([0xfa, 0xe7]))

ASR STATUS: setup
ASR: Validating target...
ASR: done
ASR STATUS: metadata
ASR: Validating source...
AppleUSBDeviceMux::handleConnectResult new session 0x846d6400 established 12345<-lo0->49201 12345<-usb->13887
ASR: Using Hardware AES
ASR: Can't gather image metadata
ASR: Could not validate source - Authentication error
ASR STATUS: fail

# AMFI patch, resigned images, orig IPSW, 
# BlobPatch(address=VirtualMemoryPointer(0x0001360a), new_content=bytes([0xfa, 0xe7]))
# InstructionPatch.quick(0x00016f52, Instr.thumb("b #0x16fb2"), expected_length=2),

ASR STATUS: setup
ASR: Validating target...
ASR: done
ASR STATUS: metadata
ASR: Validating source...
AppleUSBDeviceMux::handleConnectResult new session 0x84616600 established 12345<-lo0->49201 12345<-usb->26687
ASR: Using Hardware AES
ASR: Can't gather image metadata
ASR: done
/usr/sbin/asr was terminated by signal 10

# Original images, original IPSW (but unpersonalized)

Filesystem validated
Sending filesystem now...
[===============                                   ]  28.0%
...
creating directory (owner=0 mode=755) /mnt1/private/var
entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2
attempting to dump restore log
writing log file: /mnt1/restore.log

# Modified kernelcache to disable AMFI, original ramdisk, original unpersonalized IPSW

Filesystem validated
Sending filesystem now...
[===============                                   ]  28.0%
...
** The volume Data appears to be OK.
executing /sbin/mount
entering install_kernel_cache
writing kernelcache to /mnt1/System/Library/Caches/com.apple.kernelcaches/kernelcache
entering install_secure_vault_daemon
entering get_hardware_platform
platform-name = s5l8930x
linking /mnt1/usr/sbin/securekeyvaultd to /mnt1/usr/sbin/securekeyvaultd.s5l8930x
no securekeyvaultd for s5l8930x
entering fixup_var
remove_path /mnt1/private/var
executing /bin/rm
creating directory (owner=0 mode=755) /mnt1/private/var
entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2
attempting to dump restore log

# Modified kernelcache to disable AMFI, resigned ramdisk without patches, original unpersonalized IPSW

Filesystem validated
Sending filesystem now...
[============================================      ]  87.0%
...
** The volume Data appears to be OK.
executing /sbin/mount
entering install_kernel_cache
writing kernelcache to /mnt1/System/Library/Caches/com.apple.kernelcaches/kernelcache
entering install_secure_vault_daemon
entering get_hardware_platform
platform-name = s5l8930x
linking /mnt1/usr/sbin/securekeyvaultd to /mnt1/usr/sbin/securekeyvaultd.s5l8930x
no securekeyvaultd for s5l8930x
entering fixup_var
remove_path /mnt1/private/var
executing /bin/rm
creating directory (owner=0 mode=755) /mnt1/private/var
entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2
attempting to dump restore log
writing log file: /mnt1/restore.log

# Modified kernelcache to disable AMFI, resigned ramdisk with one string-patch ASR patch, original unpersonalized IPSW

** The volume Data appears to be OK.
executing /sbin/mount
entering install_kernel_cache
writing kernelcache to /mnt1/System/Library/Caches/com.apple.kernelcaches/kernelcache
entering install_secure_vault_daemon
entering get_hardware_platform
platform-name = s5l8930x
linking /mnt1/usr/sbin/securekeyvaultd to /mnt1/usr/sbin/securekeyvaultd.s5l8930x
no securekeyvaultd for s5l8930x
entering fixup_var
remove_path /mnt1/private/var
executing /bin/rm
creating directory (owner=0 mode=755) /mnt1/private/var
entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2

# Modified kernelcache to disable AMFI, resigned ASR with several control flow patches, original unpersonalized IPSW

** The volume Data appears to be OK.
executing /sbin/mount
entering install_kernel_cache
writing kernelcache to /mnt1/System/Library/Caches/com.apple.kernelcaches/kernelcache
entering install_secure_vault_daemon
entering get_hardware_platform
platform-name = s5l8930x
linking /mnt1/usr/sbin/securekeyvaultd to /mnt1/usr/sbin/securekeyvaultd.s5l8930x
no securekeyvaultd for s5l8930x
entering fixup_var
remove_path /mnt1/private/var
executing /bin/rm
creating directory (owner=0 mode=755) /mnt1/private/var
entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2

# Modified boot args to get serial logs, disabled AMFI, ASR patches, unpersonalized IPSW

*** Register dump @ 0x8057ca19
0x83f6b600
0x00000000
0xd2232df4
0x00000000
0x8057ca15
0x83f6b600
0x00000000
0xd2232ecc
0x84022a00

# Checking if SHSH check is reached

entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)

*** Register dump @ 0x8057c7eb
0x00000000
0x00000000
0xc8223984
0xc8223158
0x8057cf4d
0x83e9a600
0xd3c88000
0xd2212dc8
0x00013984

SHSH check is passed?!

# 

entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)

*** Register dump @ 0x8057c807
0x00000001
0x00000000
0x00000001
0x00000001
0x00000001
0x84054600
0xd3c88000
0xd2c2adc8
0x00013984
img3_flash_NOR_image: flashing NOR data (length = 0x2a984)
img3_flash_NOR_image: flashing NOR data (length = 0xe9c4)
img3_flash_NOR_image: flashing NOR data (length = 0x60c4)
img3_flash_NOR_image: flashing NOR data (length = 0x25c04)
img3_flash_NOR_image: flashing NOR data (length = 0x2e6c4)
img3_flash_NOR_image: flashing NOR data (length = 0x33404)
img3_flash_NOR_image: flashing NOR data (length = 0x11904)
img3_flash_NOR_image: flashing NOR data (length = 0x10f44)
img3_flash_NOR_image: flashing NOR data (length = 0x11244)
img3_flash_NOR_image: flashing NOR data (length = 0x13884)
img3_flash_NOR_image: flashing NOR data (length = 0x39704)
entering create_system_key_bag
attempting to create system key bag on /mnt2
booted from secure root: give device keybag access to everyone
AppleKeyStore:cp_key_store_action(1)
AppleKeyStore:cp_key_store_action(1)
entering update_gas_gauge_software
No gas gauge update for this platform.
entering update_baseband
performing an ice3 baseband update (with AuthInstall)
bbupdater: Using chip information entries from device tree...bbupdater: OK
perform_ice3_baseband_update: registering for progress notifications
perform_ice3_baseband_update: querying baseband info
bbupdater: [02.00]::: ChipInfo: snum: 0x69EA05A97008EA8248DC6E0D, chipid: 0x50, goldcertid: 0x101, nonce: 0x
perform_ice3_baseband_update: requesting rampsi from host

In idevicerestore: 
*** HANDLING restore_handle_data_request_msg type=BasebandBootData
*** PersonalizedBootObjectV3
Unknown data request 'BasebandBootData' received

# PT: I wasn't actually using a patched ramdisk all along?!
# Looks like any changes to the ramdisk causes an authentication error in ASR?! Even though ASR runs?!
# With totally empty patchset, the ramdisk works
# Using RamdiskBinaryPatch at all (even with an empty patch list) causes ASR to fail

src ) hdiutil imageinfo /var/folders/y0/clprvktj3b5__hkvm2p4m_yr0000gn/T/tmphyia9ayj/ramdisk.dmg
Class Name: CRawDiskImage
Size Information:
Total Bytes: 13717504
Compressed Ratio: 1
Sector Count: 26792
Total Non-Empty Bytes: 13717504
Compressed Bytes: 13717504
Total Empty Bytes: 0
Checksum Type: none
Format: UDRW
partitions:
partition-scheme: none
block-size: 512
appendable: true
partitions:
0:
partition-name: whole disk
partition-start: 0
partition-synthesized: true
partition-length: 26792
partition-hint: Apple_HFS
partition-filesystems:
HFS+:
burnable: true
Format Description: raw read/write
Checksum Value:
Properties:
Encrypted: false
Kernel Compatible: true
Checksummed: false
Software License Agreement: false
Partitioned: false
Compressed: no
Segments:
0: /var/folders/y0/clprvktj3b5__hkvm2p4m_yr0000gn/T/tmphyia9ayj/ramdisk.dmg
Backing Store Information:
URL: file:///var/folders/y0/clprvktj3b5__hkvm2p4m_yr0000gn/T/tmphyia9ayj/ramdisk.dmg
Name: ramdisk.dmg
Class Name: CBSDBackingStore
Resize limits (per hdiutil resize -limits):
min 	 cur 	 max
26792	26792	75589160

Copied ramdisk mounted DMG to folder, added a file to the (writable) folder, then used `hdiutil create -srcfolder` to create the DMG
The above ramdisk seems to fail, need to research how to repack the ramdisk after making mods to it!


