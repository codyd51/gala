import argparse
from pathlib import Path

from strongarm.macho import MachoParser


def dump_text_section(input_file: Path) -> bytes:
    parser = MachoParser(input_file)
    binary = parser.get_armv7_slice()
    text_section = binary.section_with_name("__text", "__TEXT")
    return binary.get_content_from_virtual_address(text_section.address, text_section.size)


def dump_text_section_to_file(input_file: Path, output_file: Path) -> None:
    with open(output_file.as_posix(), "wb") as f:
        f.write(dump_text_section(input_file))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("object_file_path")
    parser.add_argument("output_path")
    args = parser.parse_args()

    # object_file_path = Path(__file__).parent / "payload"
    object_file_path = Path(args.object_file_path)
    output_file_path = Path(args.output_path)
    print(f"Object path: {object_file_path}")
    print(f"Output path: {output_file_path}")
    dump_text_section_to_file(object_file_path, output_file_path)


if __name__ == "__main__":
    main()
