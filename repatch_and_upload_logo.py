import subprocess
import time
from pathlib import Path

from os_build import ImageType, OsBuildEnum
from patcher import JAILBREAK_ROOT, patch_image
from utils import run_and_check


def fetch_original_decrypted_image() -> Path:
    os_build = OsBuildEnum.iPhone3_1_4_0_8A293
    image_type = ImageType.AppleLogo
    image_ipsw_subpath = os_build.ipsw_path_for_image_type(image_type)
    file_name = image_ipsw_subpath.name

    patches_output_dir = JAILBREAK_ROOT / "patched_images" / os_build.unescaped_name
    decrypted_image = patches_output_dir / f"{file_name}.decrypted"

    print(decrypted_image)
    return decrypted_image


def main():
    patched_image = patch_image(OsBuildEnum.iPhone3_1_4_0_8A293, ImageType.AppleLogo)
    run_and_check(["irecovery", "-f", patched_image.as_posix()])
    run_and_check(["irecovery", "-c setpicture"])
    run_and_check(["irecovery", "-c bgcolor 255 255 255"])


if __name__ == "__main__":
    main()
