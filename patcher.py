import os
import subprocess
from copy import copy
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Self

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from strongarm.macho import MachoParser, VirtualMemoryPointer


def run_and_check(cmd_list: list[str], cwd: Path = None, env_additions: dict[str, str] | None = None) -> None:
    print(" ".join(cmd_list), cwd)
    env = os.environ.copy()
    if env_additions:
        for k, v in env_additions.items():
            env[k] = v

    status = subprocess.run(cmd_list, cwd=cwd.as_posix() if cwd else None, env=env)
    if status.returncode != 0:
        raise RuntimeError(f'Running "{" ".join(cmd_list)}" failed with exit code {status.returncode}')


def dump_text_section(input_file: Path) -> bytes:
    parser = MachoParser(input_file)
    binary = parser.get_armv7_slice()
    text_section = binary.section_with_name("__text", "__TEXT")
    return binary.get_content_from_virtual_address(text_section.address, text_section.size)


@dataclass
class Function:
    name: str
    address: VirtualMemoryPointer


class InstructionFormat(Enum):
    Thumb = 0
    Arm = 1

    @property
    def size(self) -> int:
        return {
            InstructionFormat.Thumb: 2,
            InstructionFormat.Arm: 4,
        }[self]


@dataclass
class Instr:
    format: InstructionFormat
    value: str

    @classmethod
    def thumb(cls, value: str) -> Self:
        return cls(
            format=InstructionFormat.Thumb,
            value=value
        )

    @classmethod
    def arm(cls, value: str) -> Self:
        return cls(
            format=InstructionFormat.Arm,
            value=value
        )

    def __repr__(self) -> str:
        return f'{self.format.name}({self.value})'


@dataclass
class PatchRegion:
    function: Function
    address: VirtualMemoryPointer
    orig_instructions: list[Instr]
    patched_instructions: list[Instr]


def assemble_cmp(ops: list[str]):
    pass


def register_name_to_encoded_value(register_name: str) -> str:
    try:
        return {
            "r0": "000",
            "r1": "001",
        }[register_name]
    except KeyError:
        raise ValueError(f"Unhandled register {register_name}")


def immediate_literal_to_int(imm: str) -> int:
    if imm[0] != '#':
        raise ValueError(f'Expected a hash character')
    # Handle base-16 and base-10
    if imm[1:3] == '0x':
        return int(imm[3:], 16)
    else:
        return int(imm[1:], 10)


def int_to_bits_with_width(val: int, width: int) -> str:
    return f"{bin(val)[2:]:>0{width}}"


def immediate_literal_to_bits(imm: str, width: int) -> str:
    int_val = immediate_literal_to_int(imm)
    return int_to_bits_with_width(int_val, width)


def assemble_thumb(address: VirtualMemoryPointer, mnemonic: str, ops: list[str]) -> str:
    # Ref: http://bear.ces.cwru.edu/eecs_382/ARM7-TDMI-manual-pt3.pdf?ref=zdimension.fr
    match mnemonic:
        case "cmp":
            return "010000{op}{rs}{rd}".format(
                op="1010",
                rs=register_name_to_encoded_value(ops[0]),
                rd=register_name_to_encoded_value(ops[1]),
            )
        case "nop":
            return f"{'10111111':<016}"
        case "movs":
            # 5.3 Format 3: move/compare/add/subtract immediate
            return "001{op}{rd}{offset8}".format(
                op="00",
                rd=register_name_to_encoded_value(ops[0]),
                offset8=immediate_literal_to_bits(ops[1], 8),
            )
        case "b":
            # 5.18 Format 18: unconditional branch
            dest_address = immediate_literal_to_int(ops[0])
            # "The address specified by label is a full 12-bit two’s complement address,
            # but must always be halfword aligned (ie bit 0 set to 0),
            # since the assembler places label >> 1 in the Offset11 field."
            dest_offset = (dest_address - address - 4) >> 1
            if dest_offset <= 0:
                # Negative offsets are actually allowed, but are unhandled for now
                raise ValueError(f'Expected a positive offset')
            if abs(dest_offset) > 2048:
                raise ValueError("Expected offset to be <= 2048")
            return "11100{offset11}".format(
                offset11=int_to_bits_with_width(dest_offset, 11),
            )
        case _:
            raise NotImplementedError(mnemonic)


def bitstring_to_bytes(s: str) -> bytes:
    # Ref: https://stackoverflow.com/questions/32675679/convert-binary-string-to-bytearray-in-python-3
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='little')


def assemble(address: VirtualMemoryPointer, instr: Instr) -> bytes:
    instr_str = instr.value
    parts = instr_str.split(" ")
    mnemonic = parts[0]
    ops_str = " ".join(parts[1:])
    ops = ops_str.split(", ")
    print(f'mnemonic: "{mnemonic}", ops: {ops}')

    match instr.format:
        case InstructionFormat.Thumb:
            binary_str = assemble_thumb(address, mnemonic, ops)
            return bitstring_to_bytes(binary_str)
        case InstructionFormat.Arm:
            raise NotImplementedError()


def main():
    jailbreak_root = Path("/Users/philliptennen/Documents/Jailbreak")
    output_dir = jailbreak_root / "patched_images" / "iPhone3,1_6.1_10B144"
    output_dir.mkdir(parents=True, exist_ok=True)
    iBSS = jailbreak_root / "ipsw" / "iPhone3,1_6.1_10B144_Restore.ipsw.unzipped" / "Firmware" / "dfu" / "iBSS.n90ap.RELEASE.dfu"
    decrypted_iBSS = output_dir / "iBSS.n90ap.RELEASE.dfu.decrypted"

    iBEC = jailbreak_root / "ipsw" / "iPhone3,1_6.1_10B144_Restore.ipsw.unzipped" / "Firmware" / "dfu" / "iBEC.n90ap.RELEASE.dfu"
    decrypted_iBEC = output_dir / "iBEC.n90ap.RELEASE.dfu.decrypted"

    xpwntool = jailbreak_root / "xpwn" / "build" / "ipsw-patch" / "xpwntool"

    # Decrypt the iBSS and iBEC images
    # (And delete any decrypted image we already produced)
    decrypted_iBSS.unlink(missing_ok=True)
    decrypted_iBEC.unlink(missing_ok=True)
    run_and_check(
        [
            xpwntool.as_posix(),
            iBSS.as_posix(),
            decrypted_iBSS.as_posix(),
            "-k",
            "f7f5fd61ea0792f13ea84126c3afe33944ddc543b62b552e009cbffaf7e34e28",
            "-iv",
            "24af28537e544ebf981ce32708a7e21f",
        ],
    )
    if not decrypted_iBSS.exists():
        raise RuntimeError(f"Expected decrypted iBSS to be produced at {decrypted_iBSS.as_posix()}")
    run_and_check(
        [
            xpwntool.as_posix(),
            iBEC.as_posix(),
            decrypted_iBEC.as_posix(),
            "-k",
            "061695b0ba878657ae195416cff88287f222b50baabb9f72e0c2271db6b58db5",
            "-iv",
            "1168b9ddb4c5df062892810fec574f55",
        ],
    )
    if not decrypted_iBEC.exists():
        raise RuntimeError(f"Expected decrypted iBEC to be produced at {decrypted_iBEC.as_posix()}")

    image3_load_validate_signature = Function(
        name="image3_load_validate_signature",
        address=VirtualMemoryPointer(0x8400568e),
    )
    main_ibss = Function(
        name="main_ibss",
        address=VirtualMemoryPointer(0x840008c8),
    )
    # PT: I think this is enough patches to get going and load an image...
    patches = [
        PatchRegion(
            function=image3_load_validate_signature,
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
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x840056ac),
            # PT: This comment is unverified
            # The branch just preceding this calls a validation function,
            # and the comparison following this branches away to a failure path. We want the validation to always succeed.
            orig_instructions=[Instr.thumb("cmp r0, #0")],
            patched_instructions=[Instr.thumb("cmp r0, r0")],
        ),
        # More comparison patches follow
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x8400570e),
            orig_instructions=[Instr.thumb("cmp r0, #0")],
            patched_instructions=[Instr.thumb("cmp r0, r0")],
        ),
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x84005712),
            # Replace the call to the 'image3_validate_constraints' function with a direct return value
            # This return value is compared to 0x1 just below, so set it upfront
            orig_instructions=[Instr.thumb("beq #0x84005746")],
            patched_instructions=[Instr.thumb("movs r0, #1")],
        ),
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x84005726),
            orig_instructions=[Instr.thumb("cmp r0, #0")],
            patched_instructions=[Instr.thumb("cmp r0, r0")],
        ),
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x8400573a),
            orig_instructions=[Instr.thumb("cmp r0, #1")],
            patched_instructions=[Instr.thumb("cmp r0, r0")],
        ),
        PatchRegion(
            function=main_ibss,
            address=VirtualMemoryPointer(0x84000940),
            # Just above is a function call, maybe to dfu_parse_ticket?
            # If the call returns zero, we jump back to the 'receive a DFU image' loop, and don't do further
            # processing. We always want to process the image.
            orig_instructions=[Instr.thumb("cbnz r0, #0x84000964")],
            patched_instructions=[Instr.thumb("b #0x84000964")],
        )
    ]

    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True
    base_address = 0x84000000
    decrypted_iBSS_bytes = decrypted_iBSS.read_bytes()
    patched_iBSS_bytes = bytearray(copy(decrypted_iBSS_bytes))
    for patch in patches:
        function = patch.function
        print()
        print(f'Patching {function.name}:')
        print(f'    {patch.address} {patch.orig_instructions}')
        print(f'   Patch ----> {patch.patched_instructions}')
        #if len(patch.orig_instructions) != len(patch.patched_instructions):
        #    raise ValueError(f'Expected to have the same number of instructions in the pre- and post-patch state')

        region_size = sum([i.format.size for i in patch.orig_instructions])
        patch_file_offset = patch.address - base_address
        instr_bytes = decrypted_iBSS_bytes[patch_file_offset:patch_file_offset + region_size]
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
            patched_iBSS_bytes[patch_file_offset:patch_file_offset + patched_instr.format.size] = assembled_bytes

            # Iterate to the next instruction location
            patched_instr_address += patched_instr.format.size
            patch_file_offset += patched_instr.format.size

        # All done with our patches, now let's repack the binary into an Img3
        # Also save the unpacked version, for manually verifying our patches in a disassembler
        patched_iBSS = output_dir / "iBSS.n90ap.RELEASE.dfu.patched"
        patched_iBSS.unlink(missing_ok=True)
        patched_iBSS.write_bytes(patched_iBSS_bytes)
        reencrypted_iBSS = output_dir / "iBSS.n90ap.RELEASE.dfu.reencrypted"
        run_and_check(
            [
                xpwntool.as_posix(),
                patched_iBSS.as_posix(),
                reencrypted_iBSS.as_posix(),
                "-k",
                "f7f5fd61ea0792f13ea84126c3afe33944ddc543b62b552e009cbffaf7e34e28",
                "-iv",
                "24af28537e544ebf981ce32708a7e21f",
            ],
        )
        print(f'Wrote patched iBSS to {patched_iBSS.as_posix()}')
        print(f'Wrote re-encrypted iBSS to {reencrypted_iBSS.as_posix()}')


if __name__ == '__main__':
    main()
