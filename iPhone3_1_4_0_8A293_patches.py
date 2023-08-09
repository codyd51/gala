from pathlib import Path
from typing import Mapping

from strongarm.macho import VirtualMemoryPointer

from assemble import Instr
from os_build import ImageType
from patches import (BlobPatch, InstructionPatch, IpswPatcherConfig, Patch,
                     PatchSet, DmgApplyTarPatch, DmgBinaryPatch,
                     DmgPatchSet, DmgReplaceFileContentsPatch)


def _get_ibss_patches() -> list[Patch]:
    return [
        PatchSet(
            name="Enable UART debug logs",
            patches=[
                # More logging patches, #2 and #3 might not be needed?
                InstructionPatch(
                    # Load memory to find the value that should be passed to debug_enable_uarts()
                    # We always want debug logs, so override the value here
                    function_name="platform_early_init",
                    address=VirtualMemoryPointer(0x84010B96),
                    orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
                    patched_instructions=[Instr.thumb("movs r0, #3")],
                ),
                # More UART patch
                InstructionPatch(
                    function_name="maybe_iBSS_start",
                    address=VirtualMemoryPointer(0x84000994),
                    orig_instructions=[Instr.arm("bl #0x840153f4")],
                    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                ),
                # More UART patch
                InstructionPatch(
                    function_name="maybe_iBSS_start",
                    address=VirtualMemoryPointer(0x84000838),
                    orig_instructions=[Instr.arm("bl #0x840153f4")],
                    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                ),
            ],
        ),
        PatchSet(
            name="Load unsigned iBEC",
            patches=[
                # iBEC loading patches
                # Check PROD tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x8400DF14),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                # Check ECID tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x8400E00C),
                    orig_instructions=[Instr.thumb("cbz r0, #0x8400e02e")],
                    patched_instructions=[Instr.thumb("b #0x8400e02e")],
                ),
            ],
        ),
        PatchSet(
            name="Custom picture loading patches",
            patches=[
                # Custom boot logo patches
                InstructionPatch.quick(0x8400DEF0, Instr.thumb("movs r1, #0")),
                # We patch the comparison, so hard-code the branch direction
                # TODO(PT): This looks like it conflicts with the "PROD" patch for loading img3's?
                InstructionPatch.quick(0x8400DF10, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")], expected_length=4),
                # Match the registers for a success call
                InstructionPatch.quick(
                    0x8400DF5A,
                    [Instr.thumb("movs r0, #0"), Instr.thumb("mov r1, r2"), Instr.thumb("movs r2, #1")],
                    expected_length=6,
                ),
                # After the call to validate_shsh_and_cert, `r0 == 0` to indicate success. If successful,
                # we branch away. We always should take the branch.
                InstructionPatch.quick(0x8400DE98, Instr.thumb("b #0x8400e1e8")),
                InstructionPatch.quick(0x8400E0A6, Instr.thumb("cmp r3, r3")),
            ],
        ),
    ]


def _get_ibec_patches(boot_args: str) -> list[Patch]:
    ibec_shellcode_addr = 0x5FF000FC
    boot_args_addr = 0x5FF0028E
    jump_to_comms = Instr.thumb(f"bl #{hex(ibec_shellcode_addr)}")
    return [
        PatchSet(
            name="Enable UART debug logs",
            patches=[
                # TODO(PT): These patches seem ineffectual?
                InstructionPatch(
                    # Load memory to find the value that should be passed to debug_enable_uarts()
                    # We always want debug logs, so override the value here
                    function_name="platform_early_init",
                    address=VirtualMemoryPointer(0x5FF10546),
                    orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
                    patched_instructions=[Instr.thumb("movs r0, #3")],
                ),
                # More UART patch
                InstructionPatch(
                    function_name="maybe_iBSS_start",
                    address=VirtualMemoryPointer(0x5FF008F4),
                    orig_instructions=[Instr.arm("bl #0x5ff14d48")],
                    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                ),
                # More UART patch
                InstructionPatch(
                    function_name="maybe_iBSS_start",
                    address=VirtualMemoryPointer(0x5FF00798),
                    orig_instructions=[Instr.arm("bl #0x5ff14d48")],
                    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                ),
            ],
        ),
        PatchSet(
            name="Load unsigned kernelcache",
            patches=[
                # Check PROD tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x5FF0DB00),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                # Check ECID tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x5FF0DBF8),
                    orig_instructions=[Instr.thumb("cbz r0, #0x5ff0dc1a")],
                    patched_instructions=[Instr.thumb("b #0x5ff0dc1a")],
                ),
            ],
        ),
        PatchSet(
            name="Enable verbose boot",
            patches=[
                BlobPatch(
                    address=VirtualMemoryPointer(0x5FF19D68),
                    # new_content="rd=md0 amfi=0xff cs_enforcement_disable=1 serial=3\0".encode(),
                    new_content=f"{boot_args}\0".encode(),
                    # new_content="rd=disk0s1 amfi=0xff cs_enforcement_disable=1 serial=3\0".encode(),
                    # new_content="rd=disk0s1 amfi_get_out_of_my_way=1 serial=3\0".encode(),
                )
            ],
        ),
        PatchSet(
            name="Custom boot logo",
            patches=[
                # Check SDOM
                # Replaced with the shellcode above
                InstructionPatch.quick(0x5FF0DADC, Instr.thumb("movs r1, #0")),
                # TODO(PT): This looks like it conflicts with the "PROD" patch for loading img3's?
                # Check PROD tag
                InstructionPatch.quick(0x5FF0DAFC, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")], expected_length=4),
                # Match the registers for a success call
                InstructionPatch.quick(
                    0x5FF0DB46,
                    [Instr.thumb("movs r0, #0"), Instr.thumb("mov r1, r2"), Instr.thumb("movs r2, #1")],
                    expected_length=6,
                ),
                # After the call to validate_shsh_and_cert, `r0 == 0` to indicate success. If successful,
                # we branch away. We always should take the branch.
                InstructionPatch.quick(0x5FF0DA84, Instr.thumb("b #0x5ff0ddd4")),
                InstructionPatch.quick(0x5FF0DC92, Instr.thumb("cmp r3, r3")),
            ],
        ),
        PatchSet(
            name="Tracing",
            patches=[
                BlobPatch(
                    address=VirtualMemoryPointer(ibec_shellcode_addr),
                    new_content=Path(
                        "/Users/philliptennen/Documents/Jailbreak/gala/shellcode_within_ibec/build/shellcode_within_ibec_shellcode"
                    ).read_bytes(),
                ),
                # InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0e4bc),
                # OVRD
                InstructionPatch.quick(0x5FF0DB24, Instr.thumb("cmp r0, r0")),
                # CHIP
                InstructionPatch.quick(0x5FF0DB4E, Instr.thumb("cmp r0, r0")),
                # TYPE
                InstructionPatch.quick(0x5FF0DB6E, Instr.thumb("cmp r0, r0")),
                # SEPO
                InstructionPatch.quick(0x5FF0DB94, Instr.thumb("cmp r0, r0")),
                # CEPO
                InstructionPatch.quick(0x5FF0DBB6, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # BORD
                InstructionPatch.quick(0x5FF0DBD4, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # DATA
                InstructionPatch.quick(0x5FF0DC2E, Instr.thumb("cmp r0, r0")),
            ],
        ),
        PatchSet(
            name="",
            patches=[
                # InstructionPatch.quick(0x5ff0e4ae, [Instr.thumb("movs r1, #1"), Instr.thumb("nop")]),
                # InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0e4ca),
                # InstructionPatch.quick(0x5ff0e4ce, Instr.thumb("nop")),
                # InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0e53c),
                # InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0e50e),
                # Stop iBEC from wiping boot args!
                # InstructionPatch.quick(0x5ff0e50a, [Instr.thumb_nop(), Instr.thumb_nop()]),
                # BlobPatch(address=VirtualMemoryPointer(boot_args_addr), new_content="rd=disk0s1 serial=3 -v\0".encode()),
                # BlobPatch(address=VirtualMemoryPointer(boot_args_addr), new_content="rd=disk0s1 serial=3 amfi=0xff cs_enforcement_disable=1\0".encode()),
                # BlobPatch(address=VirtualMemoryPointer(boot_args_addr), new_content=f"{boot_args}\0".encode()),
                # BlobPatch(address=VirtualMemoryPointer(ibec_shellcode_addr), new_content="rd=disk0s1 serial=3 -v\0".encode()),
                # BlobPatch(address=VirtualMemoryPointer(0x5ff0ecc0), new_content=int(boot_args_addr).to_bytes(4, byteorder="little")),
                # BlobPatch(address=VirtualMemoryPointer(0x5ff0ecc0), new_content=int(0x5ff19d68).to_bytes(4, byteorder="little")),
                # BlobPatch(address=VirtualMemoryPointer(0x5ff1a150), new_content="AAA".encode()),
            ],
        ),
    ]


def _get_kernelcache_patches() -> list[Patch]:
    kernelcache_shellcode_addr = 0x8057A314
    return [
        PatchSet(
            name="Neuter AMFI",
            patches=[
                # PT: Can't patch this because it's in __common,__DATA, bss which takes up no space on disk (and takes up zero space in the file/has zero 'file data' -- Hopper 'magically' shows XRefs to this region)
                # PE_i_can_has_debugger
                # PT: We might need a shellcode program that sets that var to 1, but how to run it at startup?
                BlobPatch(
                    address=VirtualMemoryPointer(0x80966080),
                    new_content=Path(
                        "/Users/philliptennen/Documents/Jailbreak/gala/kernelcache_set_debug_enabled/build/kernelcache_set_debug_enabled_shellcode"
                    ).read_bytes(),
                ),
                # 0x80966080
                # 0x8026a800
                BlobPatch(address=VirtualMemoryPointer(0x801D5BEA), new_content=bytes([0x90, 0xF3, 0x49, 0xF2])),
                # TODO(PT): These might be unnecessary...
                InstructionPatch.quick(0x803AAEB2, Instr.thumb("nop")),
                InstructionPatch.quick(0x803AAEF4, Instr.thumb("nop")),
                InstructionPatch.quick(0x803AAF14, Instr.thumb("nop")),
                InstructionPatch.quick(0x803AAF28, Instr.thumb("nop")),
                InstructionPatch.quick(0x803C4540, Instr.thumb("b #0x803c454a"), expected_length=2),
            ],
        ),
        # Neuter "Error, no successful firmware download after %ld ms!! Giving up..." timer
        InstructionPatch.quick(0x8080E826, Instr.thumb("b #0x8080e85a")),
        PatchSet(
            name="Image3NOR patches",
            patches=[
                # Patch comparison of retval for bl maybe_some_kind_of_image_validation
                InstructionPatch.quick(0x8057C800, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057C7E4, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057C7F2, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057C826, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057C876, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057C88A, Instr.thumb("cmp r0, r0"), expected_length=2),
                # TODO(PT): Next we have to prevent the baseband update...
            ],
        ),
        PatchSet(
            name="abc",
            patches=[
                InstructionPatch.quick(0x8057D452, [Instr.thumb("movs r0, #0"), Instr.thumb("movs r0, #0")]),
                # SHSH
                InstructionPatch.quick(0x803AC4FE, Instr.thumb("cmp r0, r0")),
                # CERT
                InstructionPatch.quick(0x803AC560, Instr.thumb("cmp r0, r0")),
                # cmp        r0, #0x0?
                # ite        eq?
                # moveq      r4, r3
                # movne      r4, r2
                InstructionPatch.quick(0x803AA8C0, [Instr.thumb("cmp r0, r0"), Instr.thumb("b #0x803aa8ce")]),
                InstructionPatch.quick(0x803AA904, Instr.thumb("nop")),
            ],
        ),
    ]


def _get_restore_ramdisk_patches() -> DmgPatchSet:
    restored_patches = DmgBinaryPatch(
        binary_path=Path("usr/local/bin/restored_external"),
        inner_patch=PatchSet(
            name="",
            patches=[
                # Don't clear effaceable storage
                #InstructionPatch.quick(0x0000526C, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # Don't wait for server ASR
                InstructionPatch.quick(0x000052AC, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # Don't create partitions
                #InstructionPatch.quick(0x0000529C, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # No fixup /var
                #InstructionPatch.quick(0x000052EC, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # No baseband update
                InstructionPatch.quick(0x00005338, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                #BlobPatch(
                #    VirtualMemoryPointer(0x0007267C), new_content=int(0x00030E30).to_bytes(4, byteorder="little")
                #),
            ],
        ),
    )
    restore_options_plist_patch = DmgReplaceFileContentsPatch(
        file_path=Path("usr/local/share/restore/options.plist"),
        new_content="""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>SystemPartitionSize</key>
	<integer>1024</integer>
	<key>CreateFilesystemPartitions</key>
	<false/>
</dict>
</plist>
""".encode()
    )

    asr_shellcode_addr = 0x1FA60
    mediakit_shellcode_addr = 0x00032780
    patches = [
        DmgApplyTarPatch(
            tar_path=Path(
                "/Users/philliptennen/Documents/Jailbreak/tools/SSH-Ramdisk-Maker-and-Loader/resources/ssh.tar"
            )
        ),
        DmgBinaryPatch(
            binary_path=Path("usr/sbin/asr"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    BlobPatch(
                        address=VirtualMemoryPointer(0x1FA60),
                        new_content=Path(
                            "/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_asr/build/shellcode_in_asr_shellcode"
                        ).read_bytes(),
                    ),
                    #InstructionPatch.quick(0x00017df2, Instr.thumb(f"bl #{hex(asr_shellcode_addr)}")),
                ],
            ),
        ),
        DmgBinaryPatch(
            binary_path=Path("System/Library/PrivateFrameworks/MediaKit.framework/MediaKit"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    BlobPatch(
                        address=VirtualMemoryPointer(mediakit_shellcode_addr),
                        new_content=Path(
                            "/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_mediakit/build/shellcode_in_mediakit_shellcode"
                        ).read_bytes(),
                    ),
                    #InstructionPatch.quick(0x0001b1b6, Instr.thumb(f"bl #{hex(mediakit_shellcode_addr)}")),
                ],
            ),
        ),
        restored_patches,
        restore_options_plist_patch,
    ]
    return DmgPatchSet(patches=patches)


def _get_rootfs_patches() -> DmgPatchSet:
    patches = []
    return DmgPatchSet(patches=patches)


def get_iphone_3_1_4_0_8a293_patches(config: IpswPatcherConfig) -> Mapping[ImageType, list[Patch]]:
    # TODO(PT): Remove binary_types_mapping() and have dedicated Patch types for every code path
    return ImageType.binary_types_mapping(
        {
            ImageType.iBSS: _get_ibss_patches(),
            ImageType.iBEC: _get_ibec_patches(config.boot_args),
            ImageType.KernelCache: _get_kernelcache_patches(),
            ImageType.RestoreRamdisk: [_get_restore_ramdisk_patches()],
            ImageType.RootFilesystem: [_get_rootfs_patches()],
        }
    )
