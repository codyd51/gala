from patches.base import Function, Patch, PatchSet
from patches.binary_patches import BlobPatch, InstructionPatch
from patches.deb_patches import DebPatch, DebPatchSet
from patches.dmg_patches import (
    DmgApplyTarPatch,
    DmgBinaryPatch,
    DmgPatch,
    DmgPatchSet,
    DmgRemoveTreePatch,
    DmgReplaceFileContentsPatch,
    FilePermission,
)

__all__ = [
    "Patch",
    "PatchSet",
    "Function",
    "InstructionPatch",
    "BlobPatch",
    "DebPatch",
    "DebPatchSet",
    "DmgPatch",
    "DmgPatchSet",
    "DmgApplyTarPatch",
    "DmgRemoveTreePatch",
    "FilePermission",
    "DmgReplaceFileContentsPatch",
    "DmgBinaryPatch",
]
