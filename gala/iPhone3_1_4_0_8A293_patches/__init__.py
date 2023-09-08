from typing import Callable, Mapping

from gala.configuration import GalaConfig
from gala.iPhone3_1_4_0_8A293_patches.assets import get_apple_logo_patches, get_mobilesubstrate_patches
from gala.iPhone3_1_4_0_8A293_patches.ibec import get_ibec_patches
from gala.iPhone3_1_4_0_8A293_patches.ibss import get_ibss_patches
from gala.iPhone3_1_4_0_8A293_patches.kernelcache import get_kernelcache_patches
from gala.iPhone3_1_4_0_8A293_patches.restore_ramdisk import get_restore_ramdisk_patches
from gala.iPhone3_1_4_0_8A293_patches.root_filesystem import get_rootfs_patches
from gala.os_build import ImageType
from gala.patch_types import Patch

# PT: Some patches have serial dependencies (i.e. the root filesystem needs a .deb that's produced by a previous step),
# so we can't generate the patched images in one pool. Instead, we need to execute them as an ordered series.
_PatchGenerator = Callable[[GalaConfig], list[Patch]]
_MapOfImageTypeToPatchGenerator = Mapping[ImageType, _PatchGenerator]

MapOfPictureTypesToPatchGenerators = _MapOfImageTypeToPatchGenerator
MapOfDebTypesToPatchGenerators = _MapOfImageTypeToPatchGenerator
MapOfDmgTypesToPatchGenerators = _MapOfImageTypeToPatchGenerator
MapOfBinaryTypesToPatchGenerators = _MapOfImageTypeToPatchGenerator


def get_iphone_3_1_4_0_8a293_patches() -> (
    MapOfDebTypesToPatchGenerators,
    MapOfDmgTypesToPatchGenerators,
    MapOfBinaryTypesToPatchGenerators,
):
    # TODO(PT): Remove binary_types_mapping() and have dedicated Patch types for every code path
    return (
        ImageType.picture_types_mapping(
            {
                # TODO(PT): Implement this and replace the current logo patcher
                ImageType.AppleLogo: get_apple_logo_patches,
            }
        ),
        # .deb patches must be applied first, as IPSW patches depend on the output
        # (Patched .debs need to be embedded in the patched filesystem)
        ImageType.deb_types_mapping(
            {
                ImageType.MobileSubstrate: get_mobilesubstrate_patches,
            }
        ),
        ImageType.dmg_types_mapping(
            {
                ImageType.RestoreRamdisk: get_restore_ramdisk_patches,
                ImageType.RootFilesystem: get_rootfs_patches,
            }
        ),
        ImageType.binary_types_mapping(
            {
                ImageType.iBSS: get_ibss_patches,
                ImageType.iBEC: get_ibec_patches,
                ImageType.KernelCache: get_kernelcache_patches,
            }
        ),
    )
