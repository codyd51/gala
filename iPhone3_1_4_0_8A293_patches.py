from pathlib import Path
from typing import Mapping

from strongarm.macho import VirtualMemoryPointer

from assemble import Instr
from os_build import ImageType
from patches import PatchSet, InstructionPatch, BlobPatch, RamdiskBinaryPatch, Patch, MachoBlobPatch


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
                    new_content="rd=md0 -v nand-enable-reformat=1 -progress debug=0x14e serial=3\0".encode(),
                    #new_content="rd=md0 nand-enable-reformat=1 serial=3 amfi_get_out_of_my_way=1\0".encode(),
                )
            ]
        ),
        PatchSet(
            name="Custom boot logo",
            patches=[
                # Check SDOM
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
        )
    ]


def _get_kernelcache_patches() -> list[Patch]:
    return [
        PatchSet(
            name="Neuter AMFI",
            patches=[
                # Virtual address: 0x803b6034
                #                  0x803ec04c
                #BlobPatch(VirtualMemoryPointer(0x803b604c), new_content="HELLO".encode()),
                MachoBlobPatch(VirtualMemoryPointer(0x803b604c), new_content="HELLO".encode()),
                InstructionPatch.quick(0x803aaeb2, Instr.thumb("nop")),
                InstructionPatch.quick(0x803aaef4, Instr.thumb("nop")),
                InstructionPatch.quick(0x803aaf14, Instr.thumb("nop")),
                InstructionPatch.quick(0x803aaf28, Instr.thumb("nop")),
            ]
        )
    ]


def _get_restore_ramdisk_patches() -> list[Patch]:
    return [
        RamdiskBinaryPatch(
            binary_path=Path("usr/local/bin/restored_external"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    BlobPatch(address=VirtualMemoryPointer(0x0002fe34), new_content="HACK!".encode()),
                    #InstructionPatch.quick(0x00001000, Instr.thumb("nop")),
                ],
            ),
        ),
        RamdiskBinaryPatch(
            # TODO(PT): Ensure this doesn't start with a slash
            binary_path=Path("usr/sbin/asr"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    BlobPatch(
                        address=VirtualMemoryPointer(0x0001ec56),
                        new_content="HELLO!".encode(),
                    ),
                    BlobPatch(address=VirtualMemoryPointer(0x0001f3ba), new_content="TEST".encode()),
                    #InstructionPatch.quick(0x00001000, Instr.thumb("nop")),
                ],
            ),
        ),
    ]


def get_iphone_3_1_4_0_8a293_patches() -> Mapping[ImageType, list[Patch]]:
    return ImageType.binary_types_mapping({
        ImageType.iBSS: _get_ibss_patches(),
        ImageType.iBEC: _get_ibec_patches(),
        ImageType.KernelCache: _get_kernelcache_patches(),
        ImageType.RestoreRamdisk: _get_restore_ramdisk_patches(),
        #ImageType.iBSS: [],
        #ImageType.iBEC: [],
        #ImageType.RestoreRamdisk: [],
    })
