from pathlib import Path

from gala.os_build import ImageType, OsBuildEnum
from gala.patcher import JAILBREAK_ROOT


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
    original_image_path = fetch_original_decrypted_image()
    original_image_bytes = original_image_path.read_bytes()
    print(len(original_image_bytes))

    # Contrary to what's implied by the dimensions in the file name
    # Maybe it's @2X?
    width = 320
    height = 480
    out_path = Path(__file__).parent / "output_image.txt"
    out = ""
    for row in range(0, height):
        for col in range(0, width):
            idx = (row * width) + col
            out += f"({row}, {col}), {idx}\n"
            word_bytes = original_image_bytes[idx : idx + 4]
            word = int.from_bytes(word_bytes, byteorder="big", signed=False)
            out += f"{hex(word)[2:]} "
            print(f"{hex(word)[2:]} ", end="")
        print()
        out += "\n"
    out_path.write_text(out)


if __name__ == "__main__":
    main()
