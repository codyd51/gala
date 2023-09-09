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

    # Provide the GlobalSign Root G3 certificate, which the user will
    # need to install to be able to connect to Cydia servers
    provide_globalsign_root_r3_cert = DmgReplaceFileContentsPatch(
        file_path=Path("private/var/gala/GlobalSign_Root_R3.crt"),
        new_content=(ASSETS_ROOT / "GlobalSign_Root_R3.crt").read_bytes(),
    )

    # Also provide our patched MobileSubstrate build
    patcher_config = config.patcher_config
    patched_mobile_substrate_name = (
        f"{patcher_config.os_build.asset_path_for_image_type(ImageType.MobileSubstrate).stem}.patched"
    )
    provide_patched_mobile_substrate = DmgReplaceFileContentsPatch(
        file_path=Path("private/var/gala/mobilesubstrate_0.9.6301_iphoneos-arm.deb"),
        # TODO(PT): Perhaps the IpswPatcherConfig can provide the patched images dir?
        new_content=(patcher_config.patched_images_root() / patched_mobile_substrate_name).read_bytes(),
    )

    provide_deb_for_access_local_files_in_safari = DmgReplaceFileContentsPatch(
        file_path=Path("private/var/gala/com.bigboss.patchsafari2_2.1.3248-1_iphoneos-arm.deb"),
        new_content=(ASSETS_ROOT / "com.bigboss.patchsafari2_2.1.3248-1_iphoneos-arm.deb").read_bytes(),
    )
    provide_deb_for_substrate_safe_mode = DmgReplaceFileContentsPatch(
        file_path=Path("private/var/gala/com.saurik.substrate.safemode_0.9.5000_iphoneos-arm.deb"),
        new_content=(ASSETS_ROOT / "com.saurik.substrate.safemode_0.9.5000_iphoneos-arm.deb").read_bytes(),
    )

    install_dropbear = DmgApplyTarPatch(tar_path=ASSETS_ROOT / "ssh_for_rootfs.tar")

    patches = [
        mount_system_partition_as_writable,
        install_dropbear,
        install_cydia,
        # Delete the Compass app to make room for the Cydia patch
        # DmgRemoveTreePatch(tree_path=Path("Applications/Compass.app")),
        provide_globalsign_root_r3_cert,
        provide_patched_mobile_substrate,
        provide_deb_for_substrate_safe_mode,
        provide_deb_for_access_local_files_in_safari,
    ]
    return [DmgPatchSet(patches=patches)]
