from pathlib import Path
from typing import Mapping

from strongarm.macho import VirtualMemoryPointer

from assemble import Instr
from os_build import ImageType
from patches import PatchSet, InstructionPatch, BlobPatch, RamdiskBinaryPatch, Patch, RamdiskPatchSet, RamdiskApplyTarPatch


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
                    address=VirtualMemoryPointer(0x84010b96),
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
            ]
        ),
        PatchSet(
            name="Load unsigned iBEC",
            patches=[
                # iBEC loading patches
                # Check PROD tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x8400df14),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                # Check ECID tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x8400e00c),
                    orig_instructions=[Instr.thumb("cbz r0, #0x8400e02e")],
                    patched_instructions=[Instr.thumb("b #0x8400e02e")],
                ),
            ]
        ),
        PatchSet(
            name="Custom picture loading patches",
            patches=[
                # Custom boot logo patches
                InstructionPatch.quick(0x8400def0, Instr.thumb("movs r1, #0")),
                # We patch the comparison, so hard-code the branch direction
                # TODO(PT): This looks like it conflicts with the "PROD" patch for loading img3's?
                InstructionPatch.quick(0x8400df10, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")], expected_length=4),

                # Match the registers for a success call
                InstructionPatch.quick(0x8400df5a, [Instr.thumb("movs r0, #0"), Instr.thumb("mov r1, r2"), Instr.thumb("movs r2, #1")], expected_length=6),

                # After the call to validate_shsh_and_cert, `r0 == 0` to indicate success. If successful,
                # we branch away. We always should take the branch.
                InstructionPatch.quick(0x8400de98, Instr.thumb("b #0x8400e1e8")),

                InstructionPatch.quick(0x8400e0a6, Instr.thumb("cmp r3, r3")),
            ],
        ),
    ]


def _get_ibec_patches() -> list[Patch]:
    ibec_shellcode_addr = 0x5ff000fc
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
                    address=VirtualMemoryPointer(0x5ff10546),
                    orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
                    patched_instructions=[Instr.thumb("movs r0, #3")],
                ),
                # More UART patch
                InstructionPatch(
                    function_name="maybe_iBSS_start",
                    address=VirtualMemoryPointer(0x5ff008f4),
                    orig_instructions=[Instr.arm("bl #0x5ff14d48")],
                    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                ),
                # More UART patch
                InstructionPatch(
                    function_name="maybe_iBSS_start",
                    address=VirtualMemoryPointer(0x5ff00798),
                    orig_instructions=[Instr.arm("bl #0x5ff14d48")],
                    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                ),
            ]
        ),
        PatchSet(
            name="Load unsigned kernelcache",
            patches=[
                # Check PROD tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x5ff0db00),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                # Check ECID tag on image3
                InstructionPatch(
                    function_name="",
                    address=VirtualMemoryPointer(0x5ff0dbf8),
                    orig_instructions=[Instr.thumb("cbz r0, #0x5ff0dc1a")],
                    patched_instructions=[Instr.thumb("b #0x5ff0dc1a")],
                ),
            ]
        ),
        PatchSet(
            name="Enable verbose boot",
            patches=[
                BlobPatch(
                    address=VirtualMemoryPointer(0x5ff19d68),
                    #new_content="rd=md0 -v nand-enable-reformat=1 -progress\0".encode(),
                    #
                    # new_content="rd=md0 -v nand-enable-reformat=1 -progress debug=0x14e serial=3\0".encode(), <-- these boot args make the 'restore' screen not show up, and make it impossible to run ASR
                    # these boot args below make the restore sceren show up and it's possible to start ASR'
                    #new_content="rd=md0 amfi=0xff cs_enforcement_disable=1 pio-error=0\0".encode(),
                    #new_content="rd=md0 serial=3 amfi=0xff cs_enforcement_disable=1 pio-error=0\0".encode(),
                    #new_content="rd=md0 serial=3 amfi_get_out_of_my_way=1 cs_enforcement_disable=1\0".encode(),

                    #new_content="rd=md0 nand-enable-reformat=1 amfi_get_out_of_my_way=1 serial=3\0".encode(),
                    #new_content="rd=md0 amfi=0xff cs_enforcement_disable=1 serial=3\0".encode(),
                    #new_content="rd=disk0s1 amfi=0xff cs_enforcement_disable=1 serial=3\0".encode(),
                    #new_content="rd=disk0s1 amfi=0xff cs_enforcement_disable=1 serial=3\0".encode(),
                    new_content="rd=md0 amfi=0xff cs_enforcement_disable=1 serial=3\0".encode(),
                    #new_content="rd=disk0s1 amfi=0xff cs_enforcement_disable=1 serial=3\0".encode(),
                    #new_content="rd=disk0s1 amfi_get_out_of_my_way=1 serial=3\0".encode(),
                    #new_content="rd=disk0s1 -v\0".encode(),
                    #new_content="amfi_get_out_of_my_way=1 serial=3\0".encode(),
                )
            ]
        ),
        PatchSet(
            name="Custom boot logo",
            patches=[
                # Check SDOM
                #InstructionPatch.quick(0x5ff0dadc, Instr.thumb(f"bl #{hex(ibec_shellcode_addr)}")),
                #InstructionPatch.quick(0x5ff0dadc, jump_to_comms),
                #InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0dadc),
                # Replaced with the shellcode above
                InstructionPatch.quick(0x5ff0dadc, Instr.thumb("movs r1, #0")),
                # TODO(PT): This looks like it conflicts with the "PROD" patch for loading img3's?
                # Check PROD tag
                InstructionPatch.quick(0x5ff0dafc, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")], expected_length=4),

                # Match the registers for a success call
                InstructionPatch.quick(0x5ff0db46, [Instr.thumb("movs r0, #0"), Instr.thumb("mov r1, r2"), Instr.thumb("movs r2, #1")], expected_length=6),

                # After the call to validate_shsh_and_cert, `r0 == 0` to indicate success. If successful,
                # we branch away. We always should take the branch.
                InstructionPatch.quick(0x5ff0da84, Instr.thumb("b #0x5ff0ddd4")),

                InstructionPatch.quick(0x5ff0dc92, Instr.thumb("cmp r3, r3")),
            ]
        ),
        PatchSet(
            name="Tracing",
            patches=[
                BlobPatch(
                    address=VirtualMemoryPointer(ibec_shellcode_addr),
                    new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/shellcode_within_ibec/build/shellcode_within_ibec_shellcode").read_bytes(),
                ),
                InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0db24),
                #InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff00cae),
                #InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0db4e),
                #InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0db6e),
                #InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0dc2e),
                #InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0dec0),
                #InstructionPatch.shellcode2(ibec_shellcode_addr, 0x5ff0dfa2),
                # OVRD
                InstructionPatch.quick(0x5ff0db24, Instr.thumb("cmp r0, r0")),
                # CHIP
                InstructionPatch.quick(0x5ff0db4e, Instr.thumb("cmp r0, r0")),
                # TYPE
                InstructionPatch.quick(0x5ff0db6e, Instr.thumb("cmp r0, r0")),
                # SEPO
                InstructionPatch.quick(0x5ff0db94, Instr.thumb("cmp r0, r0")),
                # CEPO
                InstructionPatch.quick(0x5ff0dbb6, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # BORD
                InstructionPatch.quick(0x5ff0dbd4, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # DATA
                InstructionPatch.quick(0x5ff0dc2e, Instr.thumb("cmp r0, r0")),
            ]
        ),
        PatchSet(
            name="",
            patches=[
                #BlobPatch(address=VirtualMemoryPointer(0x5ff0028e), new_content="rd=disk0s1 serial=3 -v\0".encode()),
                #BlobPatch(address=VirtualMemoryPointer(0x5ff0ecc0), new_content=int(0x5ff0028e).to_bytes(4, byteorder="little")),
                #BlobPatch(address=VirtualMemoryPointer(0x5ff0ecc0), new_content=int(0x5ff19d68).to_bytes(4, byteorder="little")),
                BlobPatch(address=VirtualMemoryPointer(0x5ff1a150), new_content="AAA".encode()),
            ]
        )
    ]


def _get_kernelcache_patches() -> list[Patch]:
    kernelcache_shellcode_addr = 0x8057a314
    return [
        PatchSet(
            name="Neuter AMFI",
            patches=[
                # PT: Can't patch this because it's in __common,__DATA, bss which takes up no space on disk (and takes up zero space in the file/has zero 'file data' -- Hopper 'magically' shows XRefs to this region)
                # BlobPatch(VirtualMemoryPointer(0x8027986c), new_content=int(1).to_bytes(4, byteorder='little', signed=False))
                #InstructionPatch(VirtualMemoryPointer(0x801d59b2), new_content=int(1).to_bytes(4, byteorder='little', signed=False))

                # PE_i_can_has_debugger
                #InstructionPatch.quick(VirtualMemoryPointer(0x801d59b0), [Instr.thumb("movs r0, #1"), Instr.thumb("b #0x801d59bc")], expected_length=4),
                #InstructionPatch.quick(VirtualMemoryPointer(0x801d59b0), [Instr.thumb("movs r0, #1"), Instr.thumb("b #0x801d59bc")], expected_length=4),
                # PT: We might need a shellcode program that sets that var to 1, but how to run it at startup?
                #BlobPatch(address=VirtualMemoryPointer(0x8027986c), new_content=int(1).to_bytes(length=4, byteorder="little")),
                BlobPatch(address=VirtualMemoryPointer(0x80966080), new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/kernelcache_set_debug_enabled/build/kernelcache_set_debug_enabled_shellcode").read_bytes()),
                # 0x80966080
                # 0x8026a800
                #InstructionPatch.quick(0x801d5bea, Instr.thumb("bl #0x80966080")),
                BlobPatch(address=VirtualMemoryPointer(0x801d5bea), new_content=bytes([0x90, 0xF3, 0x49, 0xF2])),
                # Virtual address: 0x803b6034
                #                  0x803ec04c
                #BlobPatch(VirtualMemoryPointer(0x803b604c), new_content="HELLO".encode()),
                #MachoBlobPatch(VirtualMemoryPointer(0x803b604c), new_content="HELLO".encode()),
                # TODO(PT): These might be unnecessary...
                InstructionPatch.quick(0x803aaeb2, Instr.thumb("nop")),
                InstructionPatch.quick(0x803aaef4, Instr.thumb("nop")),
                InstructionPatch.quick(0x803aaf14, Instr.thumb("nop")),
                InstructionPatch.quick(0x803aaf28, Instr.thumb("nop")),
                InstructionPatch.quick(0x803c4540, Instr.thumb("b #0x803c454a"), expected_length=2),
            ]
        ),
        # Neuter "Error, no successful firmware download after %ld ms!! Giving up..." timer
        InstructionPatch.quick(0x8080e826, Instr.thumb("b #0x8080e85a")),
        PatchSet(
            name="Image3NOR patches",
            patches=[
                # Patch comparison of retval for bl maybe_some_kind_of_image_validation
                InstructionPatch.quick(0x8057c800, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057c7e4, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057c7f2, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057c826, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057c876, Instr.thumb("cmp r0, r0"), expected_length=2),
                InstructionPatch.quick(0x8057c88a, Instr.thumb("cmp r0, r0"), expected_length=2),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x8057c906),
                # TODO(PT): Next we have to prevent the baseband update...
            ],
        ),
        PatchSet(
            name="Tracing",
            patches=[
                BlobPatch(
                    address=VirtualMemoryPointer(kernelcache_shellcode_addr),
                    new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/shellcode_within_ibss/build/shellcode_within_ibss_shellcode").read_bytes(),
                ),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x803aa8b2),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x803ab730),
                # Risky?
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x80180120),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x803ab750),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x803ab75a),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x803ab734),
                #InstructionPatch.quick(0x803ab746, Instr.thumb("nop")),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x803ab774),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x803ab734),
                #InstructionPatch.shellcode2(kernelcache_shellcode_addr, 0x8057c38c),
            ]
        ),
        PatchSet(
            name="abc",
            patches=[
                InstructionPatch.quick(0x8057d452, [Instr.thumb("movs r0, #0"), Instr.thumb("movs r0, #0")]),
                # SHSH
                InstructionPatch.quick(0x803ac4fe, Instr.thumb("cmp r0, r0")),
                # CERT
                InstructionPatch.quick(0x803ac560, Instr.thumb("cmp r0, r0")),
                # cmp        r0, #0x0?
                # ite        eq?
                # moveq      r4, r3
                # movne      r4, r2
                InstructionPatch.quick(0x803aa8c0, [Instr.thumb("cmp r0, r0"), Instr.thumb("b #0x803aa8ce")]),
                InstructionPatch.quick(0x803aa904, Instr.thumb("nop")),
            ]
        )
    ]


def _get_restore_ramdisk_patches2() -> list[Patch]:
    #asr_shellcode_addr = 0x0002407c
    asr_shellcode_addr = 0x1fa60
    #jump_to_comms = Instr.thumb("b #0x16e4a")
    jump_to_comms = Instr.thumb(f"bl #{hex(asr_shellcode_addr)}")
    return [
        RamdiskBinaryPatch(
            binary_path=Path("usr/local/bin/restored_external"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    #InstructionPatch.quick(0x00005338, [Instr.thumb("nop"), Instr.thumb("nop"), Instr.thumb("movs r0, #0")], expected_length=6),
                    #BlobPatch(address=VirtualMemoryPointer(0x00031f5c), new_content="--noverify\0".encode()),
                ],
            ),
        ),
        RamdiskBinaryPatch(
            # TODO(PT): Ensure this doesn't start with a slash
            binary_path=Path("usr/sbin/asr"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    #BlobPatch(address=VirtualMemoryPointer(0x0001ec4c), new_content="TEST".encode()),
                    #InstructionPatch.quick(0x00016f52, Instr.thumb("b #0x16fb2"), expected_length=2),
                    #InstructionPatch.quick(0x00004708, Instr.thumb("b #0x4736"), expected_length=2),
                    #InstructionPatch.quick(0x00013608, Instr.thumb("b #0x000135fe"), expected_length=2),
                    #BlobPatch(address=VirtualMemoryPointer(0x0001360a), new_content=bytes([0xfa, 0xe7])),
                    # testing what happens with inf. loop
                    #InstructionPatch.quick(0x00016c72, Instr.thumb("b #0x16c6e")),
                    #InstructionPatch.quick(0x00016c72, Instr.thumb("nop")),
                    #InstructionPatch.quick(0x00016c30, Instr.thumb("mov r8, r0")),
                    #BlobPatch(VirtualMemoryPointer(0x0001ebe4), new_content="M".encode()),
                    #InstructionPatch.quick(0x000026aa, Instr.thumb("nop"), expected_length=2),
                    #InstructionPatch.quick(0x00016c52, Instr.thumb("cmp r0, r0"), expected_length=2),
                    #InstructionPatch.quick(0x00016f40, [Instr.thumb("nop"), Instr.thumb("nop")], expected_length=4),
                    #PatchSet(
                    #    name="Shellcode",
                    #    patches=[
                    #        # Shellcode OBVIOUSLY won't work in asr because the log function doesn't exist there... silly...
                    #        # Now it won't work because we're passing C strings but it expects CFStrings
                    #        # PT: We could have one 'shellcode patchset' that takes the addr to drop the shellcode and the addr(s?) to branch to it
                    #        BlobPatch(
                    #            address=VirtualMemoryPointer(asr_shellcode_addr),
                    #            new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_asr/build/shellcode_in_asr_shellcode").read_bytes(),
                    #        ),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x00016fc6),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x00016f18),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x00017cb6),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x000180ce),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x00018288),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x000182f4),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x00018734),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x000187ce),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x000185b0),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x00016e96),
                    #        InstructionPatch.shellcode2(asr_shellcode_addr, 0x00016e96),
                    # Shellcode OBVIOUSLY won't work in asr because the log function doesn't exist there... silly...
                    # Now it won't work because we're passing C strings but it expects CFStrings
                    # PT: We could have one 'shellcode patchset' that takes the addr to drop the shellcode and the addr(s?) to branch to it
                    #InstructionPatch.quick(0x00004708, jump_to_comms),
                    #InstructionPatch.quick(0x00012418, jump_to_comms),
                    #    ]
                    #)
                    PatchSet(
                        name="Communication",
                        patches=[
                            BlobPatch(
                                address=VirtualMemoryPointer(asr_shellcode_addr),
                                new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_asr/build/shellcode_in_asr_shellcode").read_bytes(),
                            ),
                            InstructionPatch.quick(0x0001562a, jump_to_comms),
                        ]
                    ),
                    PatchSet(
                        name="Image validation?",
                        patches=[
                            #InstructionPatch.quick(0x00012412, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")], expected_length=4),
                            InstructionPatch.quick(0x00016f52, Instr.thumb("b #0x16fb2")),
                            InstructionPatch.quick(0x00016fd0, Instr.thumb("b #0x17002")),
                        ]
                    )
                ],
            ),
        ),
    ]


def _get_restore_ramdisk_patches() -> list[Patch]:
    asr_shellcode_addr = 0x1fa60
    jump_to_comms = Instr.thumb(f"bl #{hex(asr_shellcode_addr)}")
    patches = [
        RamdiskApplyTarPatch(tar_path=Path("/Users/philliptennen/Documents/Jailbreak/tools/SSH-Ramdisk-Maker-and-Loader/resources/ssh.tar")),
        RamdiskBinaryPatch(
            binary_path=Path("usr/sbin/asr"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    BlobPatch(
                        address=VirtualMemoryPointer(asr_shellcode_addr),
                        new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_asr/build/shellcode_in_asr_shellcode").read_bytes(),
                    ),
                    #InstructionPatch.quick(0x00013608, Instr.thumb("b #0x135fe")),
                    #InstructionPatch.quick(0x000087ea, jump_to_comms),
                    #InstructionPatch.quick(0x00015776, jump_to_comms),
                    #InstructionPatch.quick(0x00015790, jump_to_comms),
                    #InstructionPatch.quick(0x00003c72, jump_to_comms),
                    #InstructionPatch.quick(0x000046aa, jump_to_comms),
                    #InstructionPatch.quick(0x000105a2, jump_to_comms),
                    #InstructionPatch.quick(0x00011106, [jump_to_comms, Instr.thumb("nop")], expected_length=6),
                    #InstructionPatch.quick(0x0001093a, jump_to_comms),
                    #InstructionPatch.quick(0x0001069a, jump_to_comms),
                    # Skip passphrase block?
                    #InstructionPatch.quick(0x0001069a, Instr.thumb("b #0x106a6")),
                    #InstructionPatch.quick(0x000106bc, jump_to_comms),
                    # Is this function called?
                    #InstructionPatch.quick(0x0000de00, jump_to_comms),
                ]
            ),
        ),
        #RamdiskBinaryPatch(
        #    # TODO(PT): Ensure this doesn't start with a slash
        #    binary_path=Path("usr/sbin/asr"),
        #    inner_patch=PatchSet(
        #        name="",
        #        patches=[
        #            #PatchSet(
        #            #    name="Communication",
        #            #    patches=[
        #            #        BlobPatch(
        #            #            address=VirtualMemoryPointer(asr_shellcode_addr),
        #            #            new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_asr/build/shellcode_in_asr_shellcode").read_bytes(),
        #            #        ),
        #            #        InstructionPatch.quick(0x0001562a, jump_to_comms),
        #            #    ]
        #            #),
        #            #PatchSet(
        #            #    name="Image validation?",
        #            #    patches=[
        #            #        InstructionPatch.quick(0x00016f52, Instr.thumb("b #0x16fb2")),
        #            #        InstructionPatch.quick(0x00016fd0, Instr.thumb("b #0x17002")),
        #            #    ]
        #            #)
        #        ],
        #    ),
        #),
        RamdiskBinaryPatch(
            binary_path=Path("usr/local/bin/restored_external"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    # Don't clear effaceable storage
                    InstructionPatch.quick(0x0000526c, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                    # Don't wait for server ASR
                    InstructionPatch.quick(0x000052ac, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                    # Don't create partitions
                    InstructionPatch.quick(0x0000529c, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                    # No fixup /var
                    InstructionPatch.quick(0x000052ec, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                    # No baseband update
                    InstructionPatch.quick(0x00005338, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                    BlobPatch(VirtualMemoryPointer(0x0007267c), new_content=int(0x00030e30).to_bytes(4, byteorder="little")),
                ]
            )
        ),
    ]
    return [RamdiskPatchSet(patches=patches)]


def get_iphone_3_1_4_0_8a293_patches() -> Mapping[ImageType, list[Patch]]:
    return ImageType.binary_types_mapping({
        ImageType.iBSS: _get_ibss_patches(),
        ImageType.iBEC: _get_ibec_patches(),
        ImageType.KernelCache: _get_kernelcache_patches(),
        ImageType.RestoreRamdisk: _get_restore_ramdisk_patches(),
    })
