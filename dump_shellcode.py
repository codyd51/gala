from pathlib import Path
from strongarm.macho import MachoBinary, MachoParser


def main():
    object_file_path = Path(__file__).parent / "dumper_full_macho"
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
    for byte in bytes:
        print(f"{byte:02x}")
    
    output_file = Path(__file__).parent / "trimmed_shellcode"
    with open(output_file.as_posix(), "wb") as f:
        f.write(bytes)
    

if __name__ == '__main__':
    main()
