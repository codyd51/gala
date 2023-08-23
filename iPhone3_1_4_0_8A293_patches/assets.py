from configuration import GalaConfig
from patches import DebPatch, DebPatchSet, Patch


def get_mobilesubstrate_patches(_config: GalaConfig) -> list[DebPatchSet]:
    patches = [
        DebPatch()
    ]
    return [DebPatchSet(patches=patches)]


def get_apple_logo_patches(_config: GalaConfig) -> list[Patch]:
    return []
