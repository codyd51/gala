from strongarm.macho import VirtualMemoryPointer

from gala.assemble import Instr
from gala.configuration import GalaConfig
from gala.patch_types import BlobPatch
from gala.patch_types import InstructionPatch
from gala.patch_types import Patch
from gala.patch_types import PatchSet


def get_ibec_patches(config: GalaConfig) -> list[Patch]:
    boot_args = config.boot_config.boot_args
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
    ]
