from pathlib import Path

from gala.configuration import ASSETS_ROOT
from gala.configuration import GalaConfig
from gala.os_build import ImageType
from gala.patch_types import DmgApplyTarPatch
from gala.patch_types import DmgPatchSet
from gala.patch_types import DmgReplaceFileContentsPatch


def get_rootfs_patches(config: GalaConfig) -> list[DmgPatchSet]:
    # TODO(PT): To truly reflect that this has a serial dependency on the Cydia Substrate patched image,
    # the (image type -> already-generated patched image path) mapping should be provided here.

    mount_system_partition_as_writable = DmgReplaceFileContentsPatch(
        file_path=Path("private/etc/fstab"),
        new_content=(
            """
/dev/disk0s1 / hfs rw,suid,dev 0 1
/dev/disk0s2s1 /private/var hfs rw,suid,dev 0 2
"""
        ).encode(),
    )

    install_cydia = DmgApplyTarPatch(tar_path=ASSETS_ROOT / "Cydia.tar")

    # Provide our patched MobileSubstrate build
    patcher_config = config.patcher_config
    patched_mobile_substrate_name = (
        f"{patcher_config.os_build.asset_path_for_image_type(ImageType.MobileSubstrate).stem}.patched"
    )
    provide_patched_mobile_substrate = DmgReplaceFileContentsPatch(
        file_path=Path("private/var/gala/mobilesubstrate_0.9.6301_iphoneos-arm.deb"),
        # TODO(PT): Perhaps the IpswPatcherConfig can provide the patched images dir?
        new_content=(patcher_config.patched_images_root() / patched_mobile_substrate_name).read_bytes(),
    )
    provide_deb_for_substrate_safe_mode = DmgReplaceFileContentsPatch(
        file_path=Path("private/var/gala/com.saurik.substrate.safemode_0.9.5000_iphoneos-arm.deb"),
        new_content=(ASSETS_ROOT / "com.saurik.substrate.safemode_0.9.5000_iphoneos-arm.deb").read_bytes(),
    )

    # This file needs to be owned by the _securityd user.
    # TODO(PT): Add a validation to ensure the path never starts with /
    trust_store_trusts_globalsign_root_r3 = DmgReplaceFileContentsPatch(
        file_path=Path("private/var/Keychains/TrustStore.sqlite3"),
        new_content=(ASSETS_ROOT / "TrustStore.sqlite3").read_bytes(),
    )

    install_dropbear = DmgApplyTarPatch(tar_path=ASSETS_ROOT / "ssh_for_rootfs.tar")

    patches = [
        mount_system_partition_as_writable,
        install_dropbear,
        install_cydia,
        # Delete the Compass app to make room for the Cydia patch
        # DmgRemoveTreePatch(tree_path=Path("Applications/Compass.app")),
        provide_patched_mobile_substrate,
        provide_deb_for_substrate_safe_mode,
        trust_store_trusts_globalsign_root_r3,
    ]
    return [DmgPatchSet(patches=patches)]
