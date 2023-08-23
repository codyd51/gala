from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from strongarm.macho import (ArchitectureNotSupportedError, MachoParser,
                             VirtualMemoryPointer)

from assemble import Instr, assemble
from configuration import IpswPatcherConfig
from patches.base import Patch


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
        shellcode_addr = 0x8057A314
        branch_to_shellcode = Instr.thumb(f"bl #{hex(shellcode_addr)}")
        return cls(
            function_name="",
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[branch_to_shellcode],
        )

    @classmethod
    def shellcode2(cls, shellcode_addr: int, addr: int) -> InstructionPatch:
        branch_to_shellcode = Instr.thumb(f"bl #{hex(shellcode_addr)}")
        return cls(
            function_name="",
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[branch_to_shellcode],
        )

    @classmethod
    def quick(cls, addr: int, new_instr: Instr | list[Instr], expected_length: int | None = None) -> InstructionPatch:
        return cls(
            function_name="",
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[new_instr] if isinstance(new_instr, Instr) else new_instr,
            expected_length=expected_length,
        )

    def apply(
        self,
        config: IpswPatcherConfig,
        decrypted_image_path: Path,
        image_base_address: VirtualMemoryPointer,
        data: bytearray,
    ) -> None:
        print()
        # function = patch.function
        # print(f'Patching {function.name}:')
        print(f"Applying patch at {self.address}")
        print(f"    {self.address} {self.orig_instructions}")
        print(f"   Patch ----> {self.patched_instructions}")
        # if len(patch.orig_instructions) != len(patch.patched_instructions):
        #    raise ValueError(f'Expected to have the same number of instructions in the pre- and post-patch state')

        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        cs.detail = True

        region_size = sum([i.format.typical_size for i in self.orig_instructions])

        try:
            macho_parser = MachoParser(decrypted_image_path)
            if macho_parser.is_magic_supported():
                print(f"Applying instruction patch to a Mach-O")
                binary = macho_parser.get_armv7_slice()
                patch_file_offset = binary.file_offset_for_virtual_address(self.address)
            else:
                raise ArchitectureNotSupportedError()
        except ArchitectureNotSupportedError:
            print(f"Applying instruction patch to a raw binary")
            patch_file_offset = self.address - image_base_address

        instr_bytes = data[patch_file_offset : patch_file_offset + region_size]
        actual_orig_instructions = list(cs.disasm(instr_bytes, self.address)) if len(self.orig_instructions) else []

        # Validate the original instructions are what we expect
        if len(actual_orig_instructions) != len(self.orig_instructions):
            raise ValueError(
                f"Expected to find {len(self.orig_instructions)} instructions, but found {len(actual_orig_instructions)}: {self.orig_instructions}, {actual_orig_instructions}"
            )
        for actual_orig_instruction, expected_orig_instruction in zip(actual_orig_instructions, self.orig_instructions):
            actual_orig_instruction_str = f"{actual_orig_instruction.mnemonic} {actual_orig_instruction.op_str}"
            if actual_orig_instruction_str != expected_orig_instruction.value:
                raise ValueError(
                    f'Expected to disassemble "{expected_orig_instruction}", but found "{actual_orig_instruction_str}"'
                )

        # Assemble the patched instructions
        patched_instr_address = self.address
        patch_length = 0
        for patched_instr in self.patched_instructions:
            try:
                assembled_bytes = assemble(patched_instr_address, patched_instr)
            except ValueError as e:
                raise ValueError(f"Failed to assemble instruction \"{patched_instr.value}\": {e}")
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
                raise ValueError(f'Expected to assemble "{patched_instr.value}", but assembled "{assembled_instr_str}"')

            # Apply the patch to the binary
            data[patch_file_offset : patch_file_offset + assembled_bytes_len] = assembled_bytes

            # Iterate to the next instruction location
            patched_instr_address += assembled_bytes_len
            patch_file_offset += assembled_bytes_len
            patch_length += assembled_bytes_len

        if self.expected_length and patch_length != self.expected_length:
            raise ValueError(f"Expected a patch of {self.expected_length} bytes, but patch was {patch_length} bytes!")


@dataclass
class BlobPatch(Patch):
    """An 'unstructured' patch that allows the patch writer to drop raw bytes at a given location, with no validation
    on what's being overwritten or the contents of the patch.
    """

    address: VirtualMemoryPointer
    new_content: bytes

    def apply(
            self,
            config: IpswPatcherConfig,
            decrypted_image_path: Path,
            image_base_address: VirtualMemoryPointer,
            image_data: bytearray,
    ) -> None:
        print(f"Applying unstructured patch of {len(self.new_content)} bytes at {self.address}")
        try:
            macho_parser = MachoParser(decrypted_image_path)
            if macho_parser.is_magic_supported():
                print(f"Applying blob patch to a Mach-O")
                binary = macho_parser.get_armv7_slice()
                patch_file_offset = binary.file_offset_for_virtual_address(self.address)
            else:
                raise ArchitectureNotSupportedError()
        except ArchitectureNotSupportedError:
            print(f"Applying blob patch to a raw binary")
            patch_file_offset = self.address - image_base_address

        if patch_file_offset < 0 or patch_file_offset >= len(image_data):
            raise ValueError(f"Invalid offset {patch_file_offset}")
        print(f"File offset for {self.new_content} is {hex(patch_file_offset)}")
        image_data[patch_file_offset : patch_file_offset + len(self.new_content)] = self.new_content
