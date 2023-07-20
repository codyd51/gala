from __future__ import annotations

from abc import ABC, abstractmethod
from copy import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Mapping, Optional, Any

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
        shellcode_addr = 0x5ff000fc
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


@dataclass
class PatchSet(Patch):
    """A collection of patches that are logically grouped together.
    This has no difference in functionality to declaring top-level patches individually, and serves purely as an
    organizational tool.
    """
    name: str
    patches: list[Patch]

    def apply(self, image_base_address: VirtualMemoryPointer, image_data: bytearray) -> None:
        print(f'Applying patch set {self.name}...')
        for patch in self.patches:
            patch.apply(image_base_address, image_data)


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


def _binary_types_mapping(mapping: dict[ImageType, Any]):
    return TotalEnumMapping(mapping, omitted_variants=ImageType.picture_types())


class PatchRepository:
    @classmethod
    def builds_to_image_patches(cls) -> Mapping[OsBuildEnum, Mapping[ImageType, list[Patch]]]:
        # PT: This needs to be a method, rather than a class variable, because otherwise it
        # captures file data **when the class is defined/interpreted**,
        # which is before we've rebuilt the shellcode image with new code! Annoying
        return TotalEnumMapping({
            OsBuildEnum.iPhone3_1_4_0_8A293: _binary_types_mapping({
                ImageType.iBSS: [
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
                            InstructionPatch.quick(0x8400df10, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")], expected_length=4),

                            # Match the registers for a success call
                            InstructionPatch.quick(0x8400df5a, [Instr.thumb("movs r0, #0"), Instr.thumb("mov r1, r2"), Instr.thumb("movs r2, #1")], expected_length=6),

                            # After the call to validate_shsh_and_cert, `r0 == 0` to indicate success. If successful,
                            # we branch away. We always should take the branch.
                            InstructionPatch.quick(0x8400de98, Instr.thumb("b #0x8400e1e8")),

                            InstructionPatch.quick(0x8400e0a6, Instr.thumb("cmp r3, r3")),
                        ],
                    ),
                ],
                ImageType.iBEC: [
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
                        name="Prototyping",
                        patches=[
                            #InstructionPatch.shellcode(0x5ff0dbf8),
                            #BlobPatch(
                            #    address=VirtualMemoryPointer(0x5ff000fc),
                            #    new_content=Path("/Users/philliptennen/Documents/Jailbreak/jailbreak/shellcode_within_ibss/build/shellcode_within_ibss_shellcode").read_bytes(),
                            #)
                            BlobPatch(
                                address=VirtualMemoryPointer(0x5ff19d68),
                                new_content="rd=md0 -v nand-enable-reformat=1 -progress\0".encode(),
                            )
                        ]
                    )
                ],
                ImageType.KernelCache: [],
            }),
            OsBuildEnum.iPhone3_1_4_1_8B117: _binary_types_mapping({
                ImageType.iBSS: [],
                ImageType.iBEC: [],
                ImageType.KernelCache: [],
            }),
            OsBuildEnum.iPhone3_1_5_0_9A334: _binary_types_mapping({
                ImageType.iBSS: [],
                ImageType.iBEC: [],
                ImageType.KernelCache: [],
            }),
            OsBuildEnum.iPhone3_1_6_1_10B144: _binary_types_mapping({
                ImageType.iBSS: [],
                ImageType.iBEC: [],
                ImageType.KernelCache: [],
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


@dataclass
class IpswPatcherConfig:
    os_build: OsBuildEnum
    replacement_pictures: dict[ImageType, Path]


def patch_image(config: IpswPatcherConfig, image_type: ImageType) -> Path:
    os_build = config.os_build
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

    if image_type in ImageType.picture_types():
        # Check whether a replacement image has been specified
        if image_type in config.replacement_pictures:
            run_and_check(
                [
                    _IMAGETOOL.as_posix(),
                    "inject",
                    config.replacement_pictures[image_type].as_posix(),
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


def regenerate_patched_images(config: IpswPatcherConfig) -> Mapping[ImageType, Path]:
    return TotalEnumMapping({
        image_type: patch_image(config, image_type)
        for image_type in ImageType
    })


if __name__ == '__main__':
    regenerate_patched_images(IpswPatcherConfig(os_build=OsBuildEnum.iPhone3_1_4_0_8A293, replacement_pictures={}))
