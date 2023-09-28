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
                    function_name="platform_early_init",
                    reason="""
                        Original code loads a word from memory to find the value to pass to debug_enable_uarts().
                        Override the read value so it's always 3 (which emits serial logs).
                    """,
                    address=VirtualMemoryPointer(0x5FF10546),
                    orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
                    patched_instructions=[Instr.thumb("movs r0, #3")],
                ),
            ],
        ),
        PatchSet(
            name="Load unsigned kernelcache",
            patches=[
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        This block verifies the PROD tag on the Img3. This fails for our unpersonalized IPSW, but needs
                        to succeed. Just drop the branch and patch the return value so it looks like it passes.
                    """,
                    address=VirtualMemoryPointer(0x5ff0dafc),
                    orig_instructions=[Instr.thumb("bl #0x5ff0d7c0")],
                    patched_instructions=[Instr.thumb("movs r0, #0"), Instr.thumb("nop")],
                    expected_length=4,
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        This block verifies the ECID tag on the Img3. This fails for our unpersonalized IPSW, but needs
                        to succeed. Patch the comparison so it looks like it passes.
                    """,
                    address=VirtualMemoryPointer(0x5FF0DBF8),
                    orig_instructions=[Instr.thumb("cbz r0, #0x5ff0dc1a")],
                    patched_instructions=[Instr.thumb("b #0x5ff0dc1a")],
                ),
            ],
        ),
        PatchSet(
            name="Enable verbose boot",
            patches=[
                # Override the hard-coded boot argument string with whatever our configuration says
                BlobPatch(
                    address=VirtualMemoryPointer(0x5FF19D68),
                    new_content=f"{boot_args}\0".encode(),
                )
            ],
        ),
        PatchSet(
            name="Custom boot logo",
            patches=[
                # Check SDOM
                InstructionPatch.quick(0x5FF0DADC, Instr.thumb("movs r1, #0")),
                # Match the registers for a success call
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        These instructions branch to a routine to verify the CHIP tag on the image. 
                        We don't want this comparison anyway, and here I'm overwriting the registers to match their 
                        states when loading a successful image.
                    """,
                    address=VirtualMemoryPointer(0x5FF0DB46),
                    orig_instructions=[
                        Instr.thumb("mov r0, r5"),
                        Instr.thumb("bl #0x5ff0d7c0"),
                    ],
                    patched_instructions=[
                        Instr.thumb("movs r0, #0"),
                        Instr.thumb("mov r1, r2"),
                        Instr.thumb("movs r2, #1")
                    ],
                    expected_length=6,
                ),
                InstructionPatch(
                    function_name="image3_load_validate_constraints",
                    reason="""
                        After the call to validate_shsh_and_cert just above, r0 == 0 indicates success. If successful, 
                        we branch away. We always want to take the success branch.
                    """,
                    address=VirtualMemoryPointer(0x5FF0DA84),
                    orig_instructions=[Instr.thumb("beq.w #0x5ff0ddd4")],
                    patched_instructions=[Instr.thumb("b #0x5ff0ddd4"), Instr.thumb_nop()],
                    expected_length=4,
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        The original instruction here compares r3 to 0. This comparison needs to succeed, but doesn't
                        for images we generate. Override the comparison so we can move forward.
                    """,
                    address=VirtualMemoryPointer(0x5FF0DC92),
                    orig_instructions=[Instr.thumb("cmp r3, #0")],
                    patched_instructions=[Instr.thumb("cmp r3, r3")],
                ),
            ],
        ),
        PatchSet(
            name="Neuter more img3 validation comparisons",
            patches=[
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="Original code is checking the OVRD tag on the image3. Ensure the tag always looks valid.",
                    address=VirtualMemoryPointer(0x5FF0DB24),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="Original code is checking the CHIP tag on the image3. Ensure the tag always looks valid.",
                    address=VirtualMemoryPointer(0x5FF0DB4E),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="Original code is checking the TYPE tag on the image3. Ensure the tag always looks valid.",
                    address=VirtualMemoryPointer(0x5FF0DB6E),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="Original code is checking the SEPO tag on the image3. Ensure the tag always looks valid.",
                    address=VirtualMemoryPointer(0x5FF0DB94),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="Original code is checking the CEPO tag on the image3. Ensure the tag always looks valid.",
                    address=VirtualMemoryPointer(0x5FF0DBB6),
                    orig_instructions=[Instr.thumb("mov r4, r0"), Instr.thumb("cbnz r0, #0x5ff0dbfa")],
                    patched_instructions=[Instr.thumb("movs r0, #0"), Instr.thumb("nop")],
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="Original code is checking the BORD tag on the image3. Ensure the tag always looks valid.",
                    address=VirtualMemoryPointer(0x5FF0DBD4),
                    orig_instructions=[Instr.thumb("mov r4, r0"), Instr.thumb("cbnz r0, #0x5ff0dbfa")],
                    patched_instructions=[Instr.thumb("movs r0, #0"), Instr.thumb("nop")],
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="Original code is checking the DATA tag on the image3. Ensure the tag always looks valid.",
                    address=VirtualMemoryPointer(0x5FF0DC2E),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("cmp r0, r0")],
                ),
            ],
        ),
    ]
