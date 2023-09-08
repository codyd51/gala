from pathlib import Path

from assemble import Instr
from configuration import GalaConfig
from patches import DebPatchSet, InstructionPatch, Patch, PatchSet
from patches.deb_patches import DebBinaryPatch


def get_mobilesubstrate_patches(_config: GalaConfig) -> list[DebPatchSet]:
    skip_failing_conditions = PatchSet(
        name="Skip failing conditions",
        patches=[
            InstructionPatch.quick(0x0000B13C, new_instr=Instr.thumb("b #0xb146"), expected_length=2),
            InstructionPatch.quick(0x0000B1C8, new_instr=Instr.thumb_nop()),
            InstructionPatch.quick(0x0000B252, new_instr=Instr.thumb_nop()),
        ],
    )
    patches = [
        DebBinaryPatch(
            binary_path=Path("Library/Frameworks/CydiaSubstrate.framework/Commands/cynject"),
            inner_patch=skip_failing_conditions,
        ),
    ]
    return [DebPatchSet(patches=patches)]


def get_apple_logo_patches(_config: GalaConfig) -> list[Patch]:
    return []
