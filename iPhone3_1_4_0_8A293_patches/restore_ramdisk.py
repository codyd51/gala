from pathlib import Path

from strongarm.macho import VirtualMemoryPointer

from assemble import Instr
from configuration import GalaConfig
from patches import DmgPatchSet, DmgBinaryPatch, PatchSet, BlobPatch, InstructionPatch, DmgApplyTarPatch, \
    DmgReplaceFileContentsPatch, FilePermission


def get_restore_ramdisk_patches(config: GalaConfig) -> list[DmgPatchSet]:
    should_create_disk_partitions = config.patcher_config.should_create_disk_partitions
    restored_patches = DmgBinaryPatch(
        binary_path=Path("usr/local/bin/restored_external"),
        inner_patch=PatchSet(
            name="",
            patches=[
                # Don't clear effaceable storage
                # InstructionPatch.quick(0x0000526C, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # Don't wait for server ASR
                #InstructionPatch.quick(0x000052AC, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                BlobPatch(
                    address=VirtualMemoryPointer(0x00031f10),
                    new_content="/usr/bin/asr_wrapper\0".encode()
                ),
                BlobPatch(
                    address=VirtualMemoryPointer(0x00031f28),
                    new_content="\0".encode()
                ),
                # Don't create partitions
                # InstructionPatch.quick(0x0000529C, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # No fixup /var
                # InstructionPatch.quick(0x000052EC, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # No baseband update
                InstructionPatch.quick(0x00005338, [Instr.thumb("movs r0, #0"), Instr.thumb("nop")]),
                # BlobPatch(
                #    VirtualMemoryPointer(0x0007267C), new_content=int(0x00030E30).to_bytes(4, byteorder="little")
                # ),
                # No flash LLB
                InstructionPatch.quick(0x00007d64, Instr.thumb("b #0x7d7e")),
                # Don't claim the display
                InstructionPatch.quick(0x00009e14, [Instr.thumb("b #0xa044"), Instr.thumb_nop()], expected_length=4),
            ],
        ),
    )

    asr_shellcode_addr = 0x1FA60
    mediakit_shellcode_addr = 0x00032780
    patches = [
        DmgApplyTarPatch(
            tar_path=Path(
                "/Users/philliptennen/Documents/Jailbreak/tools/SSH-Ramdisk-Maker-and-Loader/resources/ssh_mod.tar",
            )
        ),
        DmgReplaceFileContentsPatch(
            file_path=Path("usr/bin/umount"),
            new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/umount/build/umount").read_bytes(),
            new_permissions=FilePermission.rwx(),
        ),
        DmgReplaceFileContentsPatch(
            file_path=Path("usr/bin/asr_wrapper"),
            new_content=Path("/Users/philliptennen/Documents/Jailbreak/gala/asr_wrapper/build/asr_wrapper").read_bytes(),
            new_permissions=FilePermission.rwx(),
        ),
        DmgBinaryPatch(
            binary_path=Path("usr/sbin/asr"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    BlobPatch(
                        address=VirtualMemoryPointer(0x1FA60),
                        new_content=Path(
                            "/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_asr/build/shellcode_in_asr_shellcode"
                        ).read_bytes(),
                    ),
                    # InstructionPatch.quick(0x00017df2, Instr.thumb(f"bl #{hex(asr_shellcode_addr)}")),
                ],
            ),
        ),
        DmgBinaryPatch(
            binary_path=Path("System/Library/PrivateFrameworks/MediaKit.framework/MediaKit"),
            inner_patch=PatchSet(
                name="",
                patches=[
                    BlobPatch(
                        address=VirtualMemoryPointer(mediakit_shellcode_addr),
                        new_content=Path(
                            "/Users/philliptennen/Documents/Jailbreak/gala/shellcode_in_mediakit/build/shellcode_in_mediakit_shellcode"
                        ).read_bytes(),
                    ),
                    # InstructionPatch.quick(0x0001b1b6, Instr.thumb(f"bl #{hex(mediakit_shellcode_addr)}")),
                ],
            ),
        ),
        restored_patches,
    ]

    if not should_create_disk_partitions:
        patches.append(
            DmgReplaceFileContentsPatch(
                file_path=Path("usr/local/share/restore/options.plist"),
                new_content=(
                    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>SystemPartitionSize</key>
	<integer>1024</integer>
	<key>CreateFilesystemPartitions</key>
	<false/>
</dict>
</plist>
"""
                ).encode()
            )
        )

    return [DmgPatchSet(patches=patches)]


