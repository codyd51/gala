from __future__ import annotations

from abc import ABC, abstractmethod
from copy import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Mapping

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from strongarm.macho import MachoParser, VirtualMemoryPointer

from assemble import Instr, assemble
from os_build import OsBuildEnum, KeyRepository, ImageType
from utils import run_and_check, TotalEnumMapping, hexdump

JAILBREAK_ROOT = Path("/Users/philliptennen/Documents/Jailbreak")
_XPWNTOOL = JAILBREAK_ROOT / "tools" / "xpwn-xerub" / "ipsw-patch" / "xpwntool"
_IMAGETOOL = JAILBREAK_ROOT / "tools" / "xpwn-xerub" / "ipsw-patch" / "imagetool"


@dataclass
class Function:
    name: str
    address: VirtualMemoryPointer


class Patch(ABC):
    @abstractmethod
    def apply(self, image_base_address: VirtualMemoryPointer, image_data: bytearray) -> None:
        ...


@dataclass
class InstructionPatch(Patch):
    """A 'structured' patch meant for small-scale patches of specific instructions.
    Provides various validations that the state of the binary described in the fields match reality.
    This helps sanity-check various assumptions about exactly what the patch is doing.

    For example, this type of patch requires the user to describe upfront which instructions they expect to be patching.
    This type of patch will disassemble the pre-patched instructions, to ensure that the actual bytes being patched
    match the expected instructions.
    Similarly, this type of patch will also disassemble the newly applied patch, to make sure the assembled patch code
    exactly matches what was described in the patch.
    This type of patch will also ensure that the patched instructions fit exactly into the number of bytes described
    by the original instructions (i.e. ensure the patch writer doesn't accidentally write out of bounds from what they
    were expecting).
    """
    function_name: str
    address: VirtualMemoryPointer
    orig_instructions: list[Instr]
    patched_instructions: list[Instr]
    expected_length: int | None = None

    @classmethod
    def shellcode(cls, addr: int) -> InstructionPatch:
        shellcode_addr = 0x840000fc
        branch_to_shellcode = Instr.thumb(f"bl #{hex(shellcode_addr)}")
        return cls(
            function_name='',
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[branch_to_shellcode]
        )

    @classmethod
    def quick(cls, addr: int, new_instr: Instr | list[Instr], expected_length: int | None = None) -> InstructionPatch:
        return cls(
            function_name='',
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[new_instr] if isinstance(new_instr, Instr) else new_instr,
            expected_length=expected_length,
        )

    def apply(self, image_base_address: VirtualMemoryPointer, data: bytearray) -> None:
        print()
        #function = patch.function
        #print(f'Patching {function.name}:')
        print(f'Applying patch at {self.address}')
        print(f'    {self.address} {self.orig_instructions}')
        print(f'   Patch ----> {self.patched_instructions}')
        #if len(patch.orig_instructions) != len(patch.patched_instructions):
        #    raise ValueError(f'Expected to have the same number of instructions in the pre- and post-patch state')

        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        cs.detail = True

        region_size = sum([i.format.typical_size for i in self.orig_instructions])
        patch_file_offset = self.address - image_base_address
        instr_bytes = data[patch_file_offset:patch_file_offset + region_size]
        actual_orig_instructions = list(cs.disasm(instr_bytes, self.address)) if len(self.orig_instructions) else []

        # Validate the original instructions are what we expect
        if len(actual_orig_instructions) != len(self.orig_instructions):
            raise ValueError(f'Expected to find {len(self.orig_instructions)} instructions, but found {len(actual_orig_instructions)}: {self.orig_instructions}, {actual_orig_instructions}')
        for actual_orig_instruction, expected_orig_instruction in zip(actual_orig_instructions, self.orig_instructions):
            actual_orig_instruction_str = f'{actual_orig_instruction.mnemonic} {actual_orig_instruction.op_str}'
            if actual_orig_instruction_str != expected_orig_instruction.value:
                raise ValueError(f"Expected to disassemble \"{expected_orig_instruction}\", but found \"{actual_orig_instruction_str}\"")

        # Assemble the patched instructions
        patched_instr_address = self.address
        patch_length = 0
        for patched_instr in self.patched_instructions:
            assembled_bytes = assemble(patched_instr_address, patched_instr)
            # It's possible for assembled Thumb instructions to take up 4 bytes: for example, THUMB bl <offset>.
            # Therefore, check the length of the assembled bytes, rather than relying on size reported by the format
            assembled_bytes_len = len(assembled_bytes)
            # Validate that the instruction was assembled correctly
            disassembled_instrs = list(cs.disasm(assembled_bytes, patched_instr_address))
            if len(disassembled_instrs) != 1:
                raise ValueError(f"Expected to disassemble exactly one instruction, but got {disassembled_instrs}")
            disassembled_instr = disassembled_instrs[0]
            if not disassembled_instr.op_str:
                assembled_instr_str = disassembled_instr.mnemonic
            else:
                assembled_instr_str = f"{disassembled_instr.mnemonic} {disassembled_instr.op_str}"
            if assembled_instr_str != patched_instr.value:
                raise ValueError(f"Expected to assemble \"{patched_instr.value}\", but assembled \"{assembled_instr_str}\"")

            # Apply the patch to the binary
            data[patch_file_offset:patch_file_offset + assembled_bytes_len] = assembled_bytes

            # Iterate to the next instruction location
            patched_instr_address += assembled_bytes_len
            patch_file_offset += assembled_bytes_len
            patch_length += assembled_bytes_len

        if self.expected_length and patch_length != self.expected_length:
            raise ValueError(f'Expected a patch of {self.expected_length} bytes, but patch was {patch_length} bytes!')


@dataclass
class BlobPatch(Patch):
    """An 'unstructured' patch that allows the patch writer to drop raw bytes at a given location, with no validation
    on what's being overwritten or the contents of the patch.
    """
    address: VirtualMemoryPointer
    new_content: bytes

    def apply(self, image_base_address: VirtualMemoryPointer, image_data: bytearray) -> None:
        print(f'Applying unstructured patch of {len(self.new_content)} bytes at {self.address}')
        # hexdump(patch.new_content)
        patch_file_offset = self.address - image_base_address
        image_data[patch_file_offset:patch_file_offset + len(self.new_content)] = self.new_content


class FunctionRepository:
    _BUILDS_TO_KNOWN_FUNCTIONS = TotalEnumMapping({
        OsBuildEnum.iPhone3_1_4_0_8A293: [],
        OsBuildEnum.iPhone3_1_4_1_8B117: [],
        OsBuildEnum.iPhone3_1_5_0_9A334: [],
        OsBuildEnum.iPhone3_1_6_1_10B144: [
            Function(
                name="image3_load_validate_signature",
                address=VirtualMemoryPointer(0x8400568e),
            ),
            Function(
                name="main_ibss",
                address=VirtualMemoryPointer(0x840008c8),
            ),
        ],
    })

    @classmethod
    def function_with_name(cls, os_build: OsBuildEnum, name: str) -> Function:
        known_functions = cls._BUILDS_TO_KNOWN_FUNCTIONS[os_build]
        names_to_functions = {f.name: f for f in known_functions}
        return names_to_functions[name]


class PatchRepository:
    @classmethod
    def builds_to_image_patches(cls) -> Mapping[OsBuildEnum, Mapping[ImageType, list[Patch]]]:
        # PT: This needs to be a method, rather than a class variable, because otherwise it
        # captures file data **when the class is defined/interpreted**,
        # which is before we've rebuilt the shellcode image with new code! Annoying
        shellcode_addr = 0x840000fc
        branch_to_shellcode = Instr.thumb(f"bl #{hex(shellcode_addr)}")
        return TotalEnumMapping({
            OsBuildEnum.iPhone3_1_4_0_8A293: TotalEnumMapping({
                ImageType.iBSS: [
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
                    #PatchRegion(
                    #    function_name="maybe_iBSS_start",
                    #    address=VirtualMemoryPointer(0x84000994),
                    #    orig_instructions=[Instr.arm("bl #0x840153f4")],
                    #    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                    #),
                    ## More UART patch
                    #PatchRegion(
                    #    function_name="maybe_iBSS_start",
                    #    address=VirtualMemoryPointer(0x84000838),
                    #    orig_instructions=[Instr.arm("bl #0x840153f4")],
                    #    patched_instructions=[Instr.thumb("movs r0, #3"), Instr.thumb("nop")],
                    #),

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
                    #PatchRegion(
                    #    # Replacing a call to dprintf with a func that disables the display
                    #    function_name="",
                    #    address=VirtualMemoryPointer(0x84000bf2),
                    #    orig_instructions=[Instr.arm("bl #0x84016fc8")],
                    #    patched_instructions=[branch_to_shellcode],
                    #),
                    #PatchRegion(
                    #    function_name="",
                    #    address=VirtualMemoryPointer(0x84000afc),
                    #    orig_instructions=[Instr.arm('bl #0x84010604')],
                    #    patched_instructions=[branch_to_shellcode],
                    #)
                    # 0x8400de90 FFF794FC               bl         validate_shsh_and_cert
                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400de90),
                    #    orig_instructions=[],
                    #    patched_instructions=[Instr.thumb('movs r0, #0'), Instr.thumb("nop")],
                    #)

                    # Trying to patch out the call to image3_load... obviously causes no pictures to load, whether valid or not
                    # PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x84015912),
                    #    orig_instructions=[],
                    #    patched_instructions=[Instr.thumb('movs r0, #0'), Instr.thumb("nop")],
                    #),

                    # Try and patch out a call in image3_validate_signature
                    # Patching this call causes this assert:
                    # panic: image3_load_validate_signature: ASSERT FAILED at (lib/image/image3/image3_wrapper.c:image3_load_validate_signature:490): NULL != objectHandle
                    # The function contains a malloc/free, so it might be some kind of load
                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400e1de),
                    #    orig_instructions=[],
                    #    patched_instructions=[Instr.thumb('movs r0, #0'), Instr.thumb("nop")],
                    #),

                    # Try and patch out the call to validate_shsh_and_cert
                    # This causes both valid and invalid images to stop loading, so it contains some important load logic?
                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400de90),
                    #    orig_instructions=[],
                    #    patched_instructions=[Instr.thumb('movs r0, #0'), Instr.thumb("nop")],
                    #),

                    # Check whether the KBAG is checked
                    # 0x8400e02e
                    #PatchRegion.shellcode(0x8400d9b2),

                    # Fixes a jump away with an invalid setpicture
                    InstructionPatch(
                        function_name='',
                        address=VirtualMemoryPointer(0x8400d9aa),
                        orig_instructions=[Instr.thumb("cmp r5, #0")],
                        patched_instructions=[Instr.thumb("cmp r5, r5")],
                    ),

                    # This cbz branches away for invalid pictures, but stays for valid pictures
                    InstructionPatch(
                        function_name='',
                        address=VirtualMemoryPointer(0x8400d9b0),
                        orig_instructions=[],
                        patched_instructions=[Instr.thumb("nop")],
                    ),

                    InstructionPatch.quick(0x8400d9be, Instr.thumb("b #0x8400d9c4")),

                    # Registers are similar for valid vs invalid images for all of these:
                    #PatchRegion.shellcode(0x8400d83c),
                    #PatchRegion.shellcode(0x8400d8ee),
                    #PatchRegion.shellcode(0x8400d908),

                    # R0 == 0 for a valid image, R1 == 1 for an invalid image here!
                    #PatchRegion.shellcode(0x8400d986),

                    # R1 == <Addr> for a valid image, R1 == <0> for an invalid image here!
                    # PatchRegion.shellcode(0x8400d9b0),

                    # R0 == 0 for valid image, R1 == -1 for invalid image
                    # PatchRegion.shellcode(0x84015e08),

                    #PatchRegion.shellcode(0x84016184),
                    InstructionPatch.shellcode(0x8400e0a6),

                    InstructionPatch.quick(0x8400def0, Instr.thumb("movs r1, #0")),
                    # We patch the comparison, so hard-code the branch direction
                    #PatchRegion.quick(0x8400def2, [Instr.thumb("b #0x8400e00e"), Instr.thumb("nop")], expected_length=4),
                    #PatchRegion.quick(0x8400def2, [Instr.thumb("b #0x8400e00e"), Instr.thumb("nop")], expected_length=4),
                    InstructionPatch.quick(0x8400def2, [Instr.thumb("nop"), Instr.thumb("nop")], expected_length=4),
                    InstructionPatch.quick(0x8400df10, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")], expected_length=4),

                    # Match the registers for a success call
                    InstructionPatch.quick(0x8400df5a, [Instr.thumb("movs r0, #0"), Instr.thumb("mov r1, r2"), Instr.thumb("movs r2, #1")], expected_length=6),

                    # Match the registers for a success call
                    InstructionPatch.quick(0x8400dfc6, [Instr.thumb("movs r0, #0"), Instr.thumb("movs r1, #0")], expected_length=4),

                    # Make sure it always acts like the success path
                    #PatchRegion.quick(0x84015bb0, Instr.thumb("cmp r0, r0")),
                    #PatchRegion.quick(0x84015be8, Instr.thumb("cmp r0, r0")),
                    #PatchRegion.quick(0x84015bfe, Instr.thumb("cmp r0, r0")),
                    #PatchRegion.quick(0x84015c16, Instr.thumb("cmp r0, r0")),
                    #PatchRegion.quick(0x84015c48, Instr.thumb("cmp r0, r0")),

                    # After the call to validate_shsh_and_cert, `r0 == 0` to indicate success. If successful,
                    # we branch away. We always should take the branch.
                    InstructionPatch.quick(0x8400de98, Instr.thumb("b #0x8400e1e8")),

                    #PatchRegion.quick(0x84015cba, Instr.thumb("b #0x84015cc0")),
                    InstructionPatch.quick(0x84015bb2, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015bea, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015c00, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015c18, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015c4a, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015c5a, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015c6a, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015c74, Instr.thumb("b #0x84015c7e")),
                    InstructionPatch.quick(0x84015c7a, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015c88, Instr.thumb("nop")),
                    InstructionPatch.quick(0x84015ca2, Instr.thumb("b #0x84015cb2")),
                    InstructionPatch.quick(0x84015cba, Instr.thumb("b #0x84015cc0")),
                    InstructionPatch.quick(0x8400d9ac, Instr.thumb("nop")),

                    # These patches cause no image to appear?!
                    # PatchRegion.quick(0x84015c68, Instr.thumb("cmp r0, r0")),
                    #PatchRegion.quick(0x84015c86, Instr.thumb("cmp r0, r0")),

                    # Patches for setpicture
                    # Yes: 0x8400de2c 6169                   ldr        r1, [r4, #0x14]
                    # Wrong!!! No : 0x8400defc 2846                   mov        r0, r5
                    # No : 0x8400deca 09F017FF               bl         sub_84017cfc
                    # Yes: 0x8400e1d6 14A8                   add        r0, sp, #0x50
                    # Yes: 0x8400e1e6 39E6                   b          image3_load_copyobject*+164
                    # No : 0x8400de72 D4F810A0               ldr.w      sl, [r4, #0x10]
                    # Yes: 0x8400de90 FFF794FC               bl         sub_8400d7bc
                    # Yes: 0x8400e1e8 0695                   str        r5, [sp, arg_18]
                    # Yes: 0x8400def6 09F0FBFE               bl         sub_84017cf0

                    # The below might only be valid for valid images?
                    # Yes: 0x8400defc 2846                   mov        r0, r5
                    # No : 0x8400df20 11AB                   add        r3, sp, #0x44
                    # No : 0x8400df6a 0090                   str        r0, [sp, arg_0]
                    # Yes: 0x8400df3c 09F0C6FE               bl         sub_84017ccc
                    # Yes: 0x8400df66 059A                   ldr        r2, [sp, arg_14]
                    # Yes: 0x8400dfac 09F09AFE               bl         sub_84017ce4
                    # Yes: 0x8400dfce 02F063FA               bl         sub_84010498

                    # Yes: 0x8400dfec 09F074FE               bl         sub_84017cd8
                    #      On retest this doesn't run!
                    #      On retest it runs when there's a valid image, but not when there's an invalid image

                    # Yes: 0x8400e00e 0D99                   ldr        r1, [sp, arg_34]
                    # Yes: 0x8400e018 0120                   movs       r0, #0x1

                    # Retesting each of them on an invalid image...
                    # No : 0x8400defc 2846                   mov        r0, r5
                    # Yes: 0x8400deca 09F017FF               bl         sub_84017cfc
                    # 0x8400def6 09F0FBFE               bl         sub_84017cf0
                    #PatchRegion(
                    #    function_name="",
                    #    address=VirtualMemoryPointer(0x8400def6),
                    #    orig_instructions=[Instr.arm("bl #0x84017cf0")],
                    #    patched_instructions=[branch_to_shellcode],
                    #),

                    # Patch SDOM check return value in image3_load_decrypt_image
                    #PatchRegion(
                    #    function_name="",
                    #    address=VirtualMemoryPointer(0x8400def0),
                    #    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    #    patched_instructions=[Instr.thumb("cmp r0, r0")],
                    #),

                    # This completely neuters the call to validate_shsh_and_cert
                    # I think this function might do some important loading, so instead do a patch that specifically touches it
                    #PatchRegion(
                    #    function_name="",
                    #    address=VirtualMemoryPointer(0x8400de96),
                    #    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    #    patched_instructions=[Instr.thumb("cmp r0, r0")],
                    #),

                    # Invalid setpicture:
                    # Yes: 0x8400d864 6378                   ldrb       r3, [r4, #0x1]
                    # Yes: 0x8400d882 6379                   ldrb       r3, [r4, #0x5]
                    # Yes: 0x8400d93e 059A                   ldr        r2, [sp, #0x50 + var_3C]
                    # No : 0x8400d9e2 737B                   ldrb       r3, [r6, #0xd]
                    # No : 0x8400d9d0 D8F80430               ldr.w      r3, [r8, #0x4]
                    # No : 0x8400d9c0 0546                   mov        r5, r0
                    # Yes: 0x8400d9aa 002D                   cmp        r5, #0x0
                    # No: 0x8400d9ae 0799                   ldr        r1, [sp, #0x50 + var_34]
                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400d9ae),
                    #    orig_instructions=[],
                    #    patched_instructions=[branch_to_shellcode],
                    #),

                    # Fixes a jump away with an invalid setpicture
                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400d9aa),
                    #    orig_instructions=[Instr.thumb("cmp r5, #0")],
                    #    patched_instructions=[Instr.thumb("cmp r5, r5")],
                    #),

                    # Overrides comparing return value of sub_8401244c in image3_load_validate_constraints
                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400deae),
                    #    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    #    patched_instructions=[Instr.thumb("cmp r0, r0")],
                    #),

                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400deb4),
                    #    orig_instructions=[],
                    #    patched_instructions=[branch_to_shellcode],
                    #),

                    # Invalid setpicture with patch @ 0x8400d9aa:
                    # In validate_shsh_and_cert
                    # Yes: 0x8400d9ae 0799                   ldr        r1, [sp, #0x50 + var_34]
                    # Yes: 0x8400d9e2 737B                   ldrb       r3, [r6, #0xd]
                    # Yes: 0x8400d9d0 D8F80430               ldr.w      r3, [r8, #0x4]
                    #
                    # In image3_load_decrypt_payload
                    # No : 0x8400def6 09F0FBFE               bl         sub_84017cf0
                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400deca),
                    #    orig_instructions=[],
                    #    patched_instructions=[branch_to_shellcode],
                    #),

                    #PatchRegion(
                    #    function_name='',
                    #    address=VirtualMemoryPointer(0x8400def0),
                    #    orig_instructions=[Instr.thumb("cmp r0, #0")],
                    #    patched_instructions=[Instr.thumb("cmp r0, r0")],
                    #),

                    #PatchRegion(
                    #    function_name="",
                    #    address=VirtualMemoryPointer(0x8400df18),
                    #    orig_instructions=[Instr.thumb("ldr r1, [sp, #0x34]"), Instr.arm("tst.w r1, #8")],
                    #    patched_instructions=[branch_to_shellcode, Instr.thumb("nop")],
                    #),
                    BlobPatch(
                        address=VirtualMemoryPointer(shellcode_addr),
                        new_content=Path("/Users/philliptennen/Documents/Jailbreak/jailbreak/shellcode_within_ibss/build/shellcode_within_ibss_shellcode").read_bytes(),
                    )
                ],
                ImageType.iBEC: [],
                ImageType.AppleLogo: [
                    #BlobPatch(
                    #    address=VirtualMemoryPointer(0x00007540),
                    #    new_content=0x1a29.to_bytes(byteorder='little', length=2) * 4000,
                    #    #new_content=0xdeadbeef.to_bytes(byteorder='little', length=4),
                    #)
                    BlobPatch(
                        address=VirtualMemoryPointer(0),
                        new_content=Path("/Users/philliptennen/Downloads/output-onlinepngtools copy.png").read_bytes(),
                    )
                ],
            }),
            OsBuildEnum.iPhone3_1_4_1_8B117: TotalEnumMapping({
                ImageType.iBSS: [],
                ImageType.iBEC: [],
                ImageType.AppleLogo: [],
            }),
            OsBuildEnum.iPhone3_1_5_0_9A334: TotalEnumMapping({
                ImageType.iBSS: [],
                ImageType.iBEC: [],
                ImageType.AppleLogo: [],
            }),
            OsBuildEnum.iPhone3_1_6_1_10B144: TotalEnumMapping({
                ImageType.iBSS: [
                    InstructionPatch(
                        function_name="image3_load_validate_signature",
                        address=VirtualMemoryPointer(0x84005694),
                        # PT: This comment is unverified
                        # This test is followed by a `bne`. The taken direction is a "validation failed" path, so we want to stay here.
                        orig_instructions=[Instr.arm("tst.w r0, #1")],
                        patched_instructions=[
                            Instr.thumb("cmp r0, r0"),
                            Instr.thumb("nop")
                        ],
                    ),
                    InstructionPatch(
                        function_name="image3_load_validate_signature",
                        address=VirtualMemoryPointer(0x840056ac),
                        # PT: This comment is unverified
                        # The branch just preceding this calls a validation function,
                        # and the comparison following this branches away to a failure path. We want the validation to always succeed.
                        orig_instructions=[Instr.thumb("cmp r0, #0")],
                        patched_instructions=[Instr.thumb("cmp r0, r0")],
                    ),
                    # More comparison patches follow
                    InstructionPatch(
                        function_name="image3_load_validate_signature",
                        address=VirtualMemoryPointer(0x8400570e),
                        orig_instructions=[Instr.thumb("cmp r0, #0")],
                        patched_instructions=[Instr.thumb("cmp r0, r0")],
                    ),
                    InstructionPatch(
                        function_name="image3_load_validate_signature",
                        address=VirtualMemoryPointer(0x84005712),
                        # Replace the call to the 'image3_validate_constraints' function with a direct return value
                        # This return value is compared to 0x1 just below, so set it upfront
                        orig_instructions=[Instr.thumb("beq #0x84005746")],
                        patched_instructions=[Instr.thumb("movs r0, #1")],
                    ),
                    InstructionPatch(
                        function_name="image3_load_validate_signature",
                        address=VirtualMemoryPointer(0x84005726),
                        orig_instructions=[Instr.thumb("cmp r0, #0")],
                        patched_instructions=[Instr.thumb("cmp r0, r0")],
                    ),
                    InstructionPatch(
                        function_name="image3_load_validate_signature",
                        address=VirtualMemoryPointer(0x8400573a),
                        orig_instructions=[Instr.thumb("cmp r0, #1")],
                        patched_instructions=[Instr.thumb("cmp r0, r0")],
                    ),
                    InstructionPatch(
                        function_name="main_ibss",
                        address=VirtualMemoryPointer(0x84000940),
                        # Just above is a function call, maybe to dfu_parse_ticket?
                        # If the call returns zero, we jump back to the 'receive a DFU image' loop, and don't do further
                        # processing. We always want to process the image.
                        orig_instructions=[Instr.thumb("cbnz r0, #0x84000964")],
                        patched_instructions=[Instr.thumb("b #0x84000964")],
                    ),
                ],
                # Not implemented yet
                ImageType.iBEC: [],
                ImageType.AppleLogo: [],
            }),
        })

    @classmethod
    def patches_for_image(cls, os_build: OsBuildEnum, image: ImageType) -> list[Patch]:
        image_patches_for_build = cls.builds_to_image_patches()[os_build]
        return image_patches_for_build[image]


def dump_text_section(input_file: Path) -> bytes:
    parser = MachoParser(input_file)
    binary = parser.get_armv7_slice()
    text_section = binary.section_with_name("__text", "__TEXT")
    return binary.get_content_from_virtual_address(text_section.address, text_section.size)


def decrypt_img3(path: Path, output_path: Path, key: str, iv: str):
    run_and_check(
        [
            _XPWNTOOL.as_posix(),
            path.as_posix(),
            output_path.as_posix(),
            "-k",
            key,
            "-iv",
            iv,
        ],
    )
    if not output_path.exists():
        raise RuntimeError(f"Expected decrypted img3 to be produced at {output_path.as_posix()}")


def encrypt_img3(path: Path, output_path: Path, original_img3: Path, key: str, iv: str):
    run_and_check(
        [
            _XPWNTOOL.as_posix(),
            path.as_posix(),
            output_path.as_posix(),
            "-t",
            original_img3.as_posix(),
            "-k",
            key,
            "-iv",
            iv,
        ],
    )


def apply_patches(
    image_type: ImageType,
    input: Path,
    output: Path,
    patches: list[Patch],
):
    print(f'Applying {len(patches)} patches to {image_type.name}...')
    # TODO(PT): The base address may need to vary based on OS version as well as image type?
    base_address = image_type.base_address
    input_bytes = input.read_bytes()
    patched_bytes = bytearray(copy(input_bytes))

    for patch in patches:
        patch.apply(base_address, patched_bytes)

    output.write_bytes(patched_bytes)


def patch_decrypted_image(
    os_build: OsBuildEnum,
    image_type: ImageType,
    decrypted_image_path: Path,
    patched_image_path: Path
):
    patches = PatchRepository.patches_for_image(os_build, image_type)
    apply_patches(image_type, decrypted_image_path, patched_image_path, patches)


def patch_image(os_build: OsBuildEnum, image_type: ImageType) -> Path:
    key_pair = KeyRepository.key_iv_pair_for_image(os_build, image_type)
    image_ipsw_subpath = os_build.ipsw_path_for_image_type(image_type)
    file_name = image_ipsw_subpath.name

    ipsw = JAILBREAK_ROOT / "ipsw" / f"{os_build.unescaped_name}_Restore.ipsw.unzipped"
    encrypted_image = ipsw / image_ipsw_subpath
    if not encrypted_image.exists():
        raise ValueError(f'Expected to find an encrypted image at {encrypted_image}')

    output_dir = JAILBREAK_ROOT / "patched_images" / os_build.unescaped_name
    output_dir.mkdir(parents=True, exist_ok=True)
    reencrypted_image = output_dir / f"{file_name}.reencrypted"

        # Only a single blob patche is supported
        # TODO(PT): Validate
        new_content: BlobPatch = patches[0]
        assert isinstance(new_content, BlobPatch)
        new_boot_image = Path("/Users/philliptennen/Downloads/output-onlinepngtools copy.png")
        run_and_check(
            [
                _IMAGETOOL.as_posix(),
                "inject",
                new_boot_image.as_posix(),
                reencrypted_image.as_posix(),
                encrypted_image.as_posix(),
                key_pair.iv,
                key_pair.key,
            ],
        )
    else:
        # Decrypt the image
        # (And delete any decrypted image we already produced)
        decrypted_image = output_dir / f"{file_name}.decrypted"
        decrypted_image.unlink(missing_ok=True)

        decrypt_img3(encrypted_image, decrypted_image, key_pair.key, key_pair.iv)

        patched_image = output_dir / f"{file_name}.patched"
        patched_image.unlink(missing_ok=True)
        patch_decrypted_image(os_build, image_type, decrypted_image, patched_image)
        print(f'Wrote patched {image_type.name} to {patched_image.as_posix()}')

        reencrypted_image = output_dir / f"{file_name}.reencrypted"
        encrypt_img3(patched_image, reencrypted_image, encrypted_image, key_pair.key, key_pair.iv)
        print(f'Wrote re-encrypted {image_type.name} to {reencrypted_image.as_posix()}')

    return reencrypted_image


def regenerate_patched_images(os_build: OsBuildEnum) -> Mapping[ImageType, Path]:
    return TotalEnumMapping({
        image_type: patch_image(os_build, image_type)
        for image_type in ImageType
    })


if __name__ == '__main__':
    regenerate_patched_images(OsBuildEnum.iPhone3_1_4_0_8A293)
