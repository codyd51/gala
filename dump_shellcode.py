from pathlib import Path
from strongarm.macho import MachoBinary, MachoParser
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("object_file_path")
    parser.add_argument("output_path")
    args = parser.parse_args()
    
    # object_file_path = Path(__file__).parent / "payload"
    object_file_path = Path(args.object_file_path)
    output_file_path = Path(args.output_path)
    print(f'Object path: {object_file_path}')
    print(f'Output path: {output_file_path}')
    
    parser = MachoParser(object_file_path)
    print(parser)
    binary = parser.get_armv7_slice()
    print(binary)
    virt_base = binary.get_virtual_base()
    print(f'virtual base {virt_base}')
    bytes = binary.get_content_from_virtual_address(virt_base, 0x4)
    text_section = binary.section_with_name("__text", "__TEXT")
    print(text_section)
    bytes = binary.get_content_from_virtual_address(text_section.address, text_section.size)
    
    with open(output_file_path.as_posix(), "wb") as f:
        f.write(bytes)
    

if __name__ == '__main__':
    main()
