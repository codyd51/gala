from __future__ import annotations

import shutil
from copy import copy
from pathlib import Path
from typing import Mapping

from strongarm.macho import MachoParser
from strongarm.macho import VirtualMemoryPointer

from gala.configuration import DEPENDENCIES_ROOT
from gala.configuration import JAILBREAK_ROOT
from gala.configuration import PATCHED_IMAGES_ROOT
from gala.configuration import GalaConfig
from gala.configuration import IpswPatcherConfig
from gala.iPhone3_1_4_0_8A293_patches import MapOfBinaryTypesToPatchGenerators
from gala.iPhone3_1_4_0_8A293_patches import MapOfDebTypesToPatchGenerators
from gala.iPhone3_1_4_0_8A293_patches import MapOfDmgTypesToPatchGenerators
from gala.iPhone3_1_4_0_8A293_patches import MapOfPictureTypesToPatchGenerators
from gala.iPhone3_1_4_0_8A293_patches import get_iphone_3_1_4_0_8a293_patches
from gala.os_build import ImageType
from gala.os_build import KeyRepository
from gala.os_build import OsBuildEnum
from gala.patch_types import Function
from gala.patch_types import Patch
from gala.utils import TotalEnumMapping
from gala.utils import run_and_check

_XPWNTOOL = DEPENDENCIES_ROOT / "xpwn-xerub" / "ipsw-patch" / "xpwntool"
_XPWN_DMG = DEPENDENCIES_ROOT / "xpwn" / "dmg" / "dmg"
_IMAGETOOL = DEPENDENCIES_ROOT / "xpwn-xerub" / "ipsw-patch" / "imagetool"


class FunctionRepository:
    _BUILDS_TO_KNOWN_FUNCTIONS = TotalEnumMapping(
        {
            OsBuildEnum.iPhone3_1_4_0_8A293: [],
            OsBuildEnum.iPhone3_1_4_1_8B117: [],
            OsBuildEnum.iPhone3_1_5_0_9A334: [],
            OsBuildEnum.iPhone3_1_6_1_10B144: [
                Function(
                    name="image3_load_validate_signature",
                    address=VirtualMemoryPointer(0x8400568E),
                ),
                Function(
                    name="main_ibss",
                    address=VirtualMemoryPointer(0x840008C8),
                ),
            ],
        }
    )

    @classmethod
    def function_with_name(cls, os_build: OsBuildEnum, name: str) -> Function:
        known_functions = cls._BUILDS_TO_KNOWN_FUNCTIONS[os_build]
        names_to_functions = {f.name: f for f in known_functions}
        return names_to_functions[name]


class PatchRepository:
    @classmethod
    def builds_to_image_patches(
        cls,
    ) -> Mapping[
        OsBuildEnum,
        (
            MapOfPictureTypesToPatchGenerators,
            MapOfDebTypesToPatchGenerators,
            MapOfDmgTypesToPatchGenerators,
            MapOfBinaryTypesToPatchGenerators,
        ),
    ]:
        empty_patch_sets = (
            ImageType.picture_types_mapping(
                {
                    ImageType.AppleLogo: [],
                }
            ),
            ImageType.deb_types_mapping(
                {
                    ImageType.MobileSubstrate: [],
                }
            ),
            ImageType.dmg_types_mapping(
                {
                    ImageType.RestoreRamdisk: [],
                    ImageType.RootFilesystem: [],
                }
            ),
            ImageType.binary_types_mapping(
                {
                    ImageType.iBSS: [],
                    ImageType.iBEC: [],
                    ImageType.KernelCache: [],
                }
            ),
        )
        return TotalEnumMapping(
            {
                OsBuildEnum.iPhone3_1_4_0_8A293: get_iphone_3_1_4_0_8a293_patches(),
                OsBuildEnum.iPhone3_1_4_1_8B117: empty_patch_sets,
                OsBuildEnum.iPhone3_1_5_0_9A334: empty_patch_sets,
                OsBuildEnum.iPhone3_1_6_1_10B144: empty_patch_sets,
            }
        )


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
    patcher_config: IpswPatcherConfig,
    image_type: ImageType,
    input: Path,
    output: Path,
    patches: list[Patch],
):
    print(f"Applying {len(patches)} patches to {image_type.name}, output={output}...")
    # TODO(PT): The base address may need to vary based on OS version as well as image type?
    # TODO(PT): The base address should perhaps be renamed to something like `a_priori_load_address`
    # For Mach-O's, the MachO contains the load address. We just need to know it for objects like the iBSS and iBEC, which are 'raw'
    # For pictures and ramdisks it's irrelevant
    base_address = image_type.base_address
    input_bytes = input.read_bytes()
    patched_bytes = bytearray(copy(input_bytes))

    for patch in patches:
        patch.apply(patcher_config, input, base_address, patched_bytes)

    if patched_bytes != input_bytes:
        print(f"Bytes successfully modified?")

    output.write_bytes(patched_bytes)


def patch_image(config: GalaConfig, image_type: ImageType, patches: list[Patch]) -> Path:
    patcher_config = config.patcher_config
    os_build = patcher_config.os_build
    output_dir = PATCHED_IMAGES_ROOT / os_build.unescaped_name
    output_dir.mkdir(parents=True, exist_ok=True)

    # TODO(PT): Replace this to cover all .deb patches, and store the .deb path in the patch
    if image_type in ImageType.deb_types():
        orig_deb_path = os_build.asset_path_for_image_type(image_type)
        file_name = orig_deb_path.stem
        copied_orig_deb = output_dir / f"{file_name}.orig"
        patched_deb = output_dir / f"{file_name}.patched"

        copied_orig_deb.unlink(missing_ok=True)
        patched_deb.unlink(missing_ok=True)

        shutil.copy(orig_deb_path.as_posix(), copied_orig_deb.as_posix())
        apply_patches(config.patcher_config, image_type, copied_orig_deb, patched_deb, patches)

        print(f"Wrote repacked {image_type.name} to {patched_deb.as_posix()}")
        return patched_deb

    key_pair = KeyRepository.key_iv_pair_for_image(os_build, image_type)
    image_ipsw_subpath = os_build.ipsw_path_for_image_type(image_type)
    file_name = image_ipsw_subpath.name

    ipsw = JAILBREAK_ROOT / "unzipped_ipsw" / f"{os_build.unescaped_name}_Restore.ipsw.unzipped"
    encrypted_image = ipsw / image_ipsw_subpath
    if not encrypted_image.exists():
        raise ValueError(f"Expected to find an encrypted image at {encrypted_image}")

    reencrypted_image = output_dir / f"{file_name}.reencrypted"

    if image_type in ImageType.picture_types():
        # Check whether a replacement image has been specified
        if image_type in patcher_config.replacement_pictures:
            run_and_check(
                [
                    _IMAGETOOL.as_posix(),
                    "inject",
                    patcher_config.replacement_pictures[image_type].as_posix(),
                    reencrypted_image.as_posix(),
                    encrypted_image.as_posix(),
                    key_pair.iv,
                    key_pair.key,
                ],
            )

    elif image_type == ImageType.RootFilesystem:
        extracted_dmg = output_dir / f"{file_name}.extracted"
        patched_dmg = output_dir / f"{file_name}.patched"
        repacked_dmg = output_dir / f"{file_name}.repacked"

        if not patcher_config.should_rebuild_root_filesystem:
            print(f"Skip rebuilding root filesystem...")
            if not repacked_dmg.exists():
                raise ValueError(f"Supposed to skip rebuilding root filesystem, but a cached version doesn't exist")
            return repacked_dmg

        extracted_dmg.unlink(missing_ok=True)

        # Extract the root filesystem
        run_and_check(
            [
                _XPWN_DMG.as_posix(),
                "extract",
                encrypted_image.as_posix(),
                extracted_dmg.as_posix(),
                "-k",
                key_pair.key,
            ]
        )

        # Apply our patches
        patched_dmg.unlink(missing_ok=True)
        apply_patches(config.patcher_config, image_type, extracted_dmg, patched_dmg, patches)
        print(f"Wrote patched {image_type.name} to {patched_dmg.as_posix()}")

        # Rebuild the .dmg
        repacked_dmg.unlink(missing_ok=True)
        run_and_check(
            [
                _XPWN_DMG.as_posix(),
                "build",
                patched_dmg.as_posix(),
                repacked_dmg.as_posix(),
            ]
        )
        print(f"Wrote repacked {image_type.name} to {repacked_dmg.as_posix()}")
        # TODO(PT): Early return with repacked_dmg here?

    else:
        # Decrypt the image
        # (And delete any decrypted image we already produced)
        decrypted_image = output_dir / f"{file_name}.decrypted"
        decrypted_image.unlink(missing_ok=True)

        decrypt_img3(encrypted_image, decrypted_image, key_pair.key, key_pair.iv)

        patched_image = output_dir / f"{file_name}.patched"
        patched_image.unlink(missing_ok=True)
        apply_patches(config.patcher_config, image_type, decrypted_image, patched_image, patches)
        print(f"Wrote patched {image_type.name} to {patched_image.as_posix()}")

        reencrypted_image = output_dir / f"{file_name}.reencrypted"
        reencrypted_image.unlink(missing_ok=True)
        encrypt_img3(patched_image, reencrypted_image, encrypted_image, key_pair.key, key_pair.iv)
        print(f"Wrote re-encrypted {image_type.name} to {reencrypted_image.as_posix()}")

    return reencrypted_image


def regenerate_patched_images(config: GalaConfig) -> Mapping[ImageType, Path]:
    # PT: These patches have serial dependencies, so execute them in-order
    grouping_type_to_patch_generators = PatchRepository.builds_to_image_patches()[config.patcher_config.os_build]
    image_type_to_patched_images = {}
    for image_type_grouping in grouping_type_to_patch_generators:
        for image_type, patch_generator in image_type_grouping.items():
            patches = patch_generator(config)
            image_type_to_patched_images[image_type] = patch_image(config, image_type, patches)

    # Wrap it in a TEM as a final check that we've regenerated everything
    return TotalEnumMapping(image_type_to_patched_images)


def generate_patched_ipsw(os_build: OsBuildEnum, image_types_to_paths: Mapping[ImageType, Path]) -> None:
    # Produce a patched IPSW
    ipsw = JAILBREAK_ROOT / "ipsw" / f"{os_build.unescaped_name}_Restore.ipsw.unzipped"
    output_dir = JAILBREAK_ROOT / "patched_images" / os_build.unescaped_name
    unzipped_patched_ipsw = output_dir / "patched.ipsw.unzipped"
    if unzipped_patched_ipsw.exists():
        shutil.rmtree(unzipped_patched_ipsw)
    shutil.copytree(ipsw, unzipped_patched_ipsw)
    patched_restore_ramdisk = image_types_to_paths[ImageType.RestoreRamdisk]
    restore_ramdisk_relative_path = os_build.ipsw_path_for_image_type(ImageType.RestoreRamdisk)
    restore_ramdisk_to_overwrite = unzipped_patched_ipsw / restore_ramdisk_relative_path
    print(restore_ramdisk_to_overwrite)
    restore_ramdisk_to_overwrite.write_bytes(patched_restore_ramdisk.read_bytes())

    for file in unzipped_patched_ipsw.rglob("**/*"):
        print(file)
        if file.name == ".DS_Store":
            print(f"unlinking {file}")
            file.unlink()

    # Zip it
    zipped_patched_ipsw = output_dir / "patched.ipsw.zip"
    zipped_patched_ipsw_without_extension = output_dir / "patched.ipsw"
    shutil.make_archive(zipped_patched_ipsw_without_extension.as_posix(), "zip", unzipped_patched_ipsw.as_posix())
    shutil.move(zipped_patched_ipsw, zipped_patched_ipsw_without_extension)
