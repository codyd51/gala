from dataclasses import dataclass
from enum import Enum
from typing import Self

from strongarm.macho import VirtualMemoryPointer

from utils import TotalEnumMapping


class InstrFormat(Enum):
    Thumb = 0
    Arm = 1

    @property
    def typical_size(self) -> int:
        """Some instructions (such as Thumb BL) are actually encoded as two instructions, so there's not a perfect
        mapping of mode to instruction size.
        """
        return {
            InstrFormat.Thumb: 2,
            InstrFormat.Arm: 4,
        }[self]


@dataclass
class Instr:
    format: InstrFormat
    value: str

    @classmethod
    def thumb(cls, value: str) -> Self:
        return cls(
            format=InstrFormat.Thumb,
            value=value
        )

    @classmethod
    def arm(cls, value: str) -> Self:
        return cls(
            format=InstrFormat.Arm,
            value=value
        )

    def __repr__(self) -> str:
        return f'{self.format.name}({self.value})'


def register_name_to_encoded_value(register_name: str) -> str:
    try:
        return {
            "r0": "000",
            "r1": "001",
            "r2": "010",
            "r3": "011",
            "r4": "100",
            "r5": "101",
            "r6": "110",
            "r7": "111",
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
            dest_offset = (dest_address - address - 4)

            if dest_offset < 2048:
                # Relative offset from pc
                sign_bit = "0" if dest_offset > 0 else "1"
                return f"11100{sign_bit}{int_to_bits_with_width(twos_complement(dest_offset >> 1, 10), 10)}"

            # "The address specified by label is a full 12-bit two’s complement address,
            # but must always be halfword aligned (ie bit 0 set to 0),
            # since the assembler places label >> 1 in the Offset11 field."
            dest_offset = dest_offset >> 1
            if dest_offset <= 0:
                # Negative offsets are actually allowed, but are unhandled for now
                raise ValueError(f'Expected a positive offset')
            if abs(dest_offset) > 2048:
                raise ValueError("Expected offset to be <= 2048")
            return "11100{offset11}".format(
                offset11=int_to_bits_with_width(dest_offset, 11),
            )
        case "bl":
            # 5.19 Format 19: long branch with link
            instr_template = "1111{is_low}{offset}"
            dest_address = immediate_literal_to_int(ops[0])
            offset = (dest_address - address - 4)
            offset = abs(twos_complement(offset, 23))

            # Low word comes first
            low_offset = (offset >> 1) & 0b11111111111
            high_offset = (offset >> 1) >> 11
            word1 = f"{instr_template.format(is_low='1', offset=int_to_bits_with_width(low_offset, 11))}"
            word2 = f"{instr_template.format(is_low='0', offset=int_to_bits_with_width(high_offset, 11))}"
            return f"{word1}{word2}"
        case "mov":
            # 2846  mov        r0, r5
            print(ops)
            source_reg = int(ops[1].split("r")[1])
            dest_reg = int(ops[0].split("r")[1])
            source_is_high = source_reg >= 8
            dest_is_high = dest_reg >= 8
            return "01000110{h1}{h2}{rs}{rd}".format(
                h1="1" if dest_is_high else "0",
                h2="1" if source_is_high else "0",
                rs=register_name_to_encoded_value(ops[1]),
                rd=register_name_to_encoded_value(ops[0]),
            )

        case _:
            raise NotImplementedError(mnemonic)


def twos_complement2(val: int, bit_count: int) -> int:
    if (val & (1 << (bit_count - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
        print(f'sign bit is set')
        val = val - (1 << bit_count)        # compute negative value
    return val                         # return positive value as is


def twos_complement(val, nbits):
    """Compute the 2's complement of int value val"""
    if val < 0:
        val = (1 << nbits) + val
    else:
        if (val & (1 << (nbits - 1))) != 0:
            # If sign bit is set.
            # compute negative value.
            val = val - (1 << nbits)
    return val


def assemble_arm(address: VirtualMemoryPointer, mnemonic: str, ops: list[str]) -> str:
    # Ref: https://iitd-plos.github.io/col718/ref/arm-instructionset.pdf
    match mnemonic:
        case "b" | "bl":
            # 4.4 Branch and Branch with Link
            # > Branch instructions contain a signed 2’s complement 24 bit offset.
            # > This is shifted left two bits, sign extended to 32 bits, and added to the PC.
            # > The instruction can therefore specify a branch of +/- 32Mbytes.
            # > The branch offset must take account of the prefetch operation,
            # > which causes the PC to be 2 words (8 bytes) ahead of the current instruction.
            dest_address = immediate_literal_to_int(ops[0])
            if dest_address != 0x840000fc:
                raise NotImplementedError()
            #return bin(0xFFF78AFA)[2:]
            return bin(0xfa8af7ff)[2:]

            # Max allowed shellcode size = 0x840001fe - 0x840000fc = 0x102

            dest_offset = (dest_address - address - 8) >> 2
            print(f'address {hex(address)}')
            print(f'dest_address {hex(dest_address)}')
            print(f'dest_offset {hex(dest_offset)}')
            #dest_offset_str = int_to_bits_with_width(dest_offset >> 2, 24)
            #dest_offset = int(dest_offset_str, 2)
            #dest_offset = dest_offset(int(dest_offset, 2), len(binary_string))
            #dest_offset = twos_complement()
            #if dest_offset <= 0:
            #    # Negative offsets are actually allowed, but are unhandled for now
            #    raise ValueError(f'Expected a positive offset')
            link = "1" if mnemonic == "bl" else "0"
            return "{cond}101{link}{offset}".format(
                cond="1111",
                link=link,
                offset=int_to_bits_with_width(dest_offset, 24)
            )


def bitstring_to_bytes(s: str) -> bytes:
    # Ref: https://stackoverflow.com/questions/32675679/convert-binary-string-to-bytearray-in-python-3
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='little')


def _assemble_to_bitstring(format: InstrFormat, address: VirtualMemoryPointer, mnemonic: str, ops: list[str]) -> str:
    return TotalEnumMapping({
        InstrFormat.Thumb: lambda: assemble_thumb(address, mnemonic, ops),
        InstrFormat.Arm: lambda: assemble_arm(address, mnemonic, ops),
    })[format]()


def assemble(address: VirtualMemoryPointer, instr: Instr) -> bytes:
    instr_str = instr.value
    parts = instr_str.split(" ")
    mnemonic = parts[0]
    ops_str = " ".join(parts[1:])
    ops = ops_str.split(", ")
    print(f'mnemonic: "{mnemonic}", ops: {ops}')
    ret= bitstring_to_bytes(_assemble_to_bitstring(instr.format, address, mnemonic, ops))
    import binascii
    # 16F0F2F9
    # 503407fb
    print(f'Assembled {binascii.hexlify(ret)}')
    return ret


if __name__ == '__main__':
    assert assemble(VirtualMemoryPointer(0x84015cba), Instr.thumb("b #0x84015cc0")) == bytes([0x01, 0xe0])
    assert assemble(VirtualMemoryPointer(0x8400df5a), Instr.thumb("mov r0, r5")) == bytes([0x28, 0x46])
