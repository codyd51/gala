from strongarm.macho import VirtualMemoryPointer

from gala.assemble import Instr
from gala.configuration import GalaConfig
from gala.patch_types import InstructionPatch
from gala.patch_types import Patch
from gala.patch_types import PatchSet


def get_ibss_patches(_config: GalaConfig) -> list[Patch]:
    return [
        PatchSet(
            name="Enable UART debug logs",
            patches=[
                InstructionPatch(
                    # Load memory to find the value that should be passed to debug_enable_uarts()
                    # We always want debug logs, so override the value here
                    function_name="platform_early_init",
                    reason="""
                        Original code loads a word from memory to find the value to pass to debug_enable_uarts().
                        Override the read value so it's always 3 (which emits serial logs).
                    """,
                    address=VirtualMemoryPointer(0x84010B96),
                    orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
                    patched_instructions=[Instr.thumb("movs r0, #3")],
                ),
            ],
        ),
        PatchSet(
            name="Load unsigned iBEC",
            patches=[
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        This block verifies the PROD tag on the Img3. This fails for our unpersonalized IPSW, but needs
                        to succeed. Just drop the branch and patch the return value so it looks like it passes.
                    """,
                    address=VirtualMemoryPointer(0x8400DF10),
                    orig_instructions=[Instr.thumb("bl #0x8400dbd4")],
                    patched_instructions=[Instr.thumb("movs r0, #0"), Instr.thumb("nop")],
                    expected_length=4,
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        This block verifies the ECID tag on the Img3. This fails for our unpersonalized IPSW, but needs
                        to succeed. Patch the comparison so it looks like it passes.
                    """,
                    address=VirtualMemoryPointer(0x8400E00C),
                    orig_instructions=[Instr.thumb("cbz r0, #0x8400e02e")],
                    patched_instructions=[Instr.thumb("b #0x8400e02e")],
                ),
            ],
        ),
        PatchSet(
            name="Custom picture loading patches",
            patches=[
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        This block verifies the SDOM tag on the Img3. This fails for images that we generate, but passes
                        for legit images. Drop the comparison so the branch away isn't taken.
                    """,
                    address=VirtualMemoryPointer(0x8400DEF0),
                    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    patched_instructions=[Instr.thumb("movs r1, #0")],
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        These instructions branch to a routine to verify the CHIP tag on the image. 
                        We don't want this comparison anyway, and here I'm overwriting the registers to match their 
                        states when loading a successful image.
                    """,
                    address=VirtualMemoryPointer(0x8400DF5A),
                    orig_instructions=[
                        Instr.thumb("mov r0, r5"),
                        Instr.thumb("bl #0x8400dbd4"),
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
                    address=VirtualMemoryPointer(0x8400DE98),
                    orig_instructions=[Instr.thumb("beq.w #0x8400e1e8")],
                    patched_instructions=[Instr.thumb("b #0x8400e1e8"), Instr.thumb_nop()],
                    expected_length=4,
                ),
                InstructionPatch(
                    function_name="image3_load_decrypt_payload",
                    reason="""
                        The original instruction here compares r3 to 0. This comparison needs to succeed, but doesn't
                        for images we generate. Override the comparison so we can move forward.
                    """,
                    address=VirtualMemoryPointer(0x8400E0A6),
                    orig_instructions=[Instr.thumb("cmp r3, #0")],
                    patched_instructions=[Instr.thumb("cmp r3, r3")],
                ),
            ],
        ),
    ]
