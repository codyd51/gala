from pathlib import Path

from strongarm.macho import VirtualMemoryPointer, MachoParser

from configuration import IpswPatcherConfig
from os_build import OsBuildEnum
from patches import BlobPatch, InstructionPatch


def main():
    cynject = Path("/Users/philliptennen/Documents/Jailbreak/tools/cycript/cynject_from_device")
    output = Path("/Users/philliptennen/Documents/Jailbreak/tools/cycript/patched_cynject_from_device")

    binary = MachoParser(cynject).slices[0]
    image_data = bytearray(cynject.read_bytes())
    patcher_config = IpswPatcherConfig(
        os_build=OsBuildEnum.iPhone3_1_4_0_8A293,
        replacement_pictures={},
        should_rebuild_root_filesystem=False,
        should_create_disk_partitions=False,
    )
    base_address = binary.get_virtual_base()
    print(base_address)
    print(binary.get_file_offset())
    print()

    if False:
        patch = BlobPatch(
            address=VirtualMemoryPointer(0x00004700),
            new_content=Path(
                "/Users/philliptennen/Documents/Jailbreak/gala/shellcode_within_cynject/build/shellcode_within_cynject_shellcode"
            ).read_bytes(),
        )
        print(patch.new_content)
        patch.apply(patcher_config, cynject, 1, image_data)

        #patch2 = BlobPatch(address=VirtualMemoryPointer(0x0000b1ae), new_content=bytes([0xF9, 0xF7, 0xA7, 0xFA]))
        # ldr        r0, =0x92d6  ; 0x92d6,0xadc0
        # add        r0, pc       ; ___stderrp_14024
        # ldr        r0, [r0]     ; ___stderrp_14024
        # ldr        r0, [r0]
        patch2 = BlobPatch(address=VirtualMemoryPointer(0x0000b1ae), new_content=bytes(
            [
                #0xF9, 0xF7, 0xA7, 0xFA

                #0x44, 0xF2, 0x01, 0x70,
                #0x80, 0x47,

                0x04, 0x00, 0x1F, 0xE5,
                0x00, 0x00, 0x90, 0xE5,
                0x00, 0x68,
                0x44, 0xF2, 0x01, 0x71,
                0x88, 0x47,
            ]
        ))
        patch2.apply(patcher_config, cynject, 2, image_data)

    if False:
        BlobPatch(
            address=VirtualMemoryPointer(0x0000bc5c),
            new_content="*** 0x%08x\n\0".encode()
        ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)
        BlobPatch(
            address=VirtualMemoryPointer(0x0000b1ae),
            new_content=bytes([0x32, 0x00, 0xb0, 0x49, 0x79, 0x44, 0x00, 0xbf, 0x00, 0xbf]),
        ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)

    if True:
        BlobPatch(
            address=VirtualMemoryPointer(0x0000b13c),
            new_content=bytes([0x03, 0xe0]),
        ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)

    if True:
        BlobPatch(
            address=VirtualMemoryPointer(0x0000b1c8),
            new_content=bytes([0x00, 0xbf]),
        ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)

    BlobPatch(
        address=VirtualMemoryPointer(0x0000b252),
        new_content=bytes([0x00, 0xbf]),
    ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)

    print(image_data == cynject.read_bytes())
    output.write_bytes(image_data)


if __name__ == '__main__':
    main()
