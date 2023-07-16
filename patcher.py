from copy import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Mapping

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from strongarm.macho import MachoParser, VirtualMemoryPointer

from assemble import Instr, assemble
from os_build import OsBuildEnum, KeyRepository, ImageType
from utils import run_and_check, TotalEnumMapping, hexdump

_JAILBREAK_ROOT = Path("/Users/philliptennen/Documents/Jailbreak")
_XPWNTOOL = _JAILBREAK_ROOT / "xpwn" / "build" / "ipsw-patch" / "xpwntool"


@dataclass
class Function:
    name: str
    address: VirtualMemoryPointer


@dataclass
class PatchRegion:
    #function: Function
    function_name: str
    address: VirtualMemoryPointer
    orig_instructions: list[Instr]
    patched_instructions: list[Instr]


@dataclass
class PatchRawBytes:
    address: VirtualMemoryPointer
    new_content: bytes


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
    _OLD_IBSS_PATCHES = [
        PatchRegion(
            # Load memory to find the value that should be passed to debug_enable_uarts()
            # We always want debug logs, so override the value here
            function_name="platform_early_init",
            address=VirtualMemoryPointer(0x84010b96),
            orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
            patched_instructions=[Instr.thumb("movs r0, #3")],
        ),
        PatchRegion(
            # In do_go_target, there's a call to validate_memory_image. We always want to consider it to have succeeded
            # TODO(PT): This patch might not be necessary if we we patch the signature checks correctly?
            function_name="do_go_target",
            address=VirtualMemoryPointer(0x84000bdc),
            orig_instructions=[Instr.thumb("bge #0x84000bee")],
            patched_instructions=[Instr.thumb("b #0x84000bee")],
        ),
        PatchRegion(
            # TODO(PT): Add an `explanation` field
            # After an inner call to an image validation function, we compare the return value to zero.
            # If it's anything else, we return -1 and the image validation fails. We always want the following
            # comparison to succeed, so compare r0 to itself.
            function_name="",
            address=VirtualMemoryPointer(0x8400e1e2),
            orig_instructions=[Instr.thumb("cmp r0, #0")],
            patched_instructions=[Instr.thumb("cmp r0, r0")],
        ),
        PatchRegion(
            # If the comparison is NE, we stay on the happy path.
            function_name="",
            address=VirtualMemoryPointer(0x8400e1f0),
            orig_instructions=[Instr.thumb("cmp r5, #0")],
            patched_instructions=[Instr.thumb("cmp r5, r5")],
        ),
        PatchRegion(
            # We stay on the happy path by jumping away.
            # It is kind of seeming like the image handle is null though...
            function_name="",
            address=VirtualMemoryPointer(0x8400de7a),
            orig_instructions=[Instr.thumb("cbnz r0, #0x8400de90")],
            patched_instructions=[Instr.thumb("b #0x8400de90")],
        ),
        #PatchRegion(
        #    # We stay on the happy path by jumping away.
        #    function_name="",
        #    address=VirtualMemoryPointer(0x8400e1f2),
        #    orig_instructions=[Instr.arm("bne.w #0x8400deca")],
        #    patched_instructions=[Instr.arm("b #0x8400deca")],
        #)
    ]

    @classmethod
    def builds_to_image_patches(cls) -> Mapping[OsBuildEnum, Mapping[ImageType, Tuple[list[PatchRegion], list[PatchRawBytes]]]]:
        # PT: This needs to be a method, rather than a class variable, because otherwise it
        # captures file data **when the class is defined/interpreted**,
        # which is before we've rebuilt the shellcode image with new code! Annoying
        return TotalEnumMapping({
            OsBuildEnum.iPhone3_1_4_0_8A293: TotalEnumMapping({
                ImageType.iBSS: (
                    [
                        #PatchRegion(
                        #    function_name="",
                        #    address=VirtualMemoryPointer(0x84000be4),
                        #    orig_instructions=[Instr.arm("mov.w r0, #-1")],
                        #    patched_instructions=[Instr.arm("bl #0x840000fc")],
                        #)
                    ],
                    [
                        #PatchRawBytes(
                        #    address=VirtualMemoryPointer(0x84000be4),
                        #    new_content=Path("/Users/philliptennen/Documents/Jailbreak/jailbreak/shellcode_within_ibss/build/shellcode_within_ibss_shellcode").read_bytes(),
                        #),
                        PatchRawBytes(
                            address=VirtualMemoryPointer(0x840000fc),
                            new_content=Path("/Users/philliptennen/Documents/Jailbreak/jailbreak/shellcode_within_ibss/build/shellcode_within_ibss_shellcode").read_bytes(),
                        )
                    ]
                ),
                ImageType.iBEC: (
                    [],
                    []
                ),
            }),
            OsBuildEnum.iPhone3_1_4_1_8B117: TotalEnumMapping({
                ImageType.iBSS: (
                    [],
                    []
                ),
                ImageType.iBEC: (
                    [],
                    []
                ),
            }),
            OsBuildEnum.iPhone3_1_5_0_9A334: TotalEnumMapping({
                ImageType.iBSS: (
                    [],
                    []
                ),
                ImageType.iBEC: (
                    [],
                    []
                ),
            }),
            OsBuildEnum.iPhone3_1_6_1_10B144: TotalEnumMapping({
                ImageType.iBSS: (
                    [
                        PatchRegion(
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
                        PatchRegion(
                            function_name="image3_load_validate_signature",
                            address=VirtualMemoryPointer(0x840056ac),
                            # PT: This comment is unverified
                            # The branch just preceding this calls a validation function,
                            # and the comparison following this branches away to a failure path. We want the validation to always succeed.
                            orig_instructions=[Instr.thumb("cmp r0, #0")],
                            patched_instructions=[Instr.thumb("cmp r0, r0")],
                        ),
                        # More comparison patches follow
                        PatchRegion(
                            function_name="image3_load_validate_signature",
                            address=VirtualMemoryPointer(0x8400570e),
                            orig_instructions=[Instr.thumb("cmp r0, #0")],
                            patched_instructions=[Instr.thumb("cmp r0, r0")],
                        ),
                        PatchRegion(
                            function_name="image3_load_validate_signature",
                            address=VirtualMemoryPointer(0x84005712),
                            # Replace the call to the 'image3_validate_constraints' function with a direct return value
                            # This return value is compared to 0x1 just below, so set it upfront
                            orig_instructions=[Instr.thumb("beq #0x84005746")],
                            patched_instructions=[Instr.thumb("movs r0, #1")],
                        ),
                        PatchRegion(
                            function_name="image3_load_validate_signature",
                            address=VirtualMemoryPointer(0x84005726),
                            orig_instructions=[Instr.thumb("cmp r0, #0")],
                            patched_instructions=[Instr.thumb("cmp r0, r0")],
                        ),
                        PatchRegion(
                            function_name="image3_load_validate_signature",
                            address=VirtualMemoryPointer(0x8400573a),
                            orig_instructions=[Instr.thumb("cmp r0, #1")],
                            patched_instructions=[Instr.thumb("cmp r0, r0")],
                        ),
                        PatchRegion(
                            function_name="main_ibss",
                            address=VirtualMemoryPointer(0x84000940),
                            # Just above is a function call, maybe to dfu_parse_ticket?
                            # If the call returns zero, we jump back to the 'receive a DFU image' loop, and don't do further
                            # processing. We always want to process the image.
                            orig_instructions=[Instr.thumb("cbnz r0, #0x84000964")],
                            patched_instructions=[Instr.thumb("b #0x84000964")],
                        ),
                    ],
                    [],
                ),
                # Not implemented yet
                ImageType.iBEC: (
                    [],
                    [],
                ),
            }),
        })

    @classmethod
    def patches_for_image(cls, os_build: OsBuildEnum, image: ImageType) -> Tuple[list[PatchRegion], list[PatchRawBytes]]:
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
    input: Path,
    output: Path,
    structured_patches: list[PatchRegion],
    unstructured_patches: list[PatchRawBytes]
):
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True
    # TODO(PT): This base address should be updated for non-iBSS images?
    base_address = 0x84000000
    input_bytes = input.read_bytes()
    patched_bytes = bytearray(copy(input_bytes))
    for patch in structured_patches:
        print()
        #function = patch.function
        #print(f'Patching {function.name}:')
        print(f'Applying patch at {patch.address}')
        print(f'    {patch.address} {patch.orig_instructions}')
        print(f'   Patch ----> {patch.patched_instructions}')
        #if len(patch.orig_instructions) != len(patch.patched_instructions):
        #    raise ValueError(f'Expected to have the same number of instructions in the pre- and post-patch state')

        region_size = sum([i.format.size for i in patch.orig_instructions])
        patch_file_offset = patch.address - base_address
        instr_bytes = input_bytes[patch_file_offset:patch_file_offset + region_size]
        actual_orig_instructions = list(cs.disasm(instr_bytes, patch.address))

        # Validate the original instructions are what we expect
        if len(actual_orig_instructions) != len(patch.orig_instructions):
            raise ValueError(f'Expected to find {len(patch.orig_instructions)} instructions, but found {len(actual_orig_instructions)}: {patch.orig_instructions}, {actual_orig_instructions}')
        for actual_orig_instruction, expected_orig_instruction in zip(actual_orig_instructions, patch.orig_instructions):
            actual_orig_instruction_str = f'{actual_orig_instruction.mnemonic} {actual_orig_instruction.op_str}'
            if actual_orig_instruction_str != expected_orig_instruction.value:
                raise ValueError(f"Expected to disassemble \"{expected_orig_instruction}\", but found \"{actual_orig_instruction_str}\"")

        # Assemble the patched instructions
        patched_instr_address = patch.address
        for patched_instr in patch.patched_instructions:
            assembled_bytes = assemble(patched_instr_address, patched_instr)
            print(f"Assembled bytes {assembled_bytes}")
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
            patched_bytes[patch_file_offset:patch_file_offset + patched_instr.format.size] = assembled_bytes

            # Iterate to the next instruction location
            patched_instr_address += patched_instr.format.size
            patch_file_offset += patched_instr.format.size

    for patch in unstructured_patches:
        print()
        print(f'Applying unstructured patch of {len(patch.new_content)} bytes at {patch.address}')
        hexdump(patch.new_content)
        patch_file_offset = patch.address - base_address
        patched_bytes[patch_file_offset:patch_file_offset + len(patch.new_content)] = patch.new_content

    # All done with our patches, now let's repack the binary into an Img3
    # Also save the unpacked version, for manually verifying our patches in a disassembler
    output.write_bytes(patched_bytes)


def patch_decrypted_image(
    os_build: OsBuildEnum,
    image_type: ImageType,
    decrypted_image_path: Path,
    patched_image_path: Path
):
    structured_patches, unstructured_patches = PatchRepository.patches_for_image(os_build, image_type)
    apply_patches(decrypted_image_path, patched_image_path, structured_patches, unstructured_patches)


def patch_image(os_build: OsBuildEnum, image_type: ImageType) -> Path:
    key_pair = KeyRepository.key_iv_pair_for_image(os_build, image_type)
    image_ipsw_subpath = os_build.ipsw_path_for_image_type(image_type)
    file_name = image_ipsw_subpath.name

    output_dir = _JAILBREAK_ROOT / "patched_images" / os_build.unescaped_name
    output_dir.mkdir(parents=True, exist_ok=True)
    decrypted_image = output_dir / f"{file_name}.decrypted"

    # Decrypt the image
    # (And delete any decrypted image we already produced)
    decrypted_image.unlink(missing_ok=True)

    ipsw = _JAILBREAK_ROOT / "ipsw" / f"{os_build.unescaped_name}_Restore.ipsw.unzipped"
    encrypted_image = ipsw / image_ipsw_subpath
    if not encrypted_image.exists():
        raise ValueError(f'Expected to find an encrypted image at {encrypted_image}')

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
    regenerate_patched_images(OsBuildEnum.iPhone3_1_5_0_9A334)
