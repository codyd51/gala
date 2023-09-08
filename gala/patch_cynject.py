from pathlib import Path

from strongarm.macho import MachoParser, VirtualMemoryPointer

from gala.configuration import IpswPatcherConfig
from gala.os_build import OsBuildEnum
from gala.patch_types import BlobPatch


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

    if True:
        BlobPatch(
            address=VirtualMemoryPointer(0x0000B13C),
            new_content=bytes([0x03, 0xE0]),
        ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)

    if True:
        BlobPatch(
            address=VirtualMemoryPointer(0x0000B1C8),
            new_content=bytes([0x00, 0xBF]),
        ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)

    BlobPatch(
        address=VirtualMemoryPointer(0x0000B252),
        new_content=bytes([0x00, 0xBF]),
    ).apply(patcher_config, cynject, VirtualMemoryPointer(0), image_data)

    print(image_data == cynject.read_bytes())
    output.write_bytes(image_data)


if __name__ == "__main__":
    main()
