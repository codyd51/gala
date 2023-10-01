from pathlib import Path

from strongarm.macho import VirtualMemoryPointer

from gala.assemble import Instr
from gala.configuration import ASSETS_ROOT
from gala.configuration import GALA_ROOT
from gala.configuration import GalaConfig
from gala.patch_types import BlobPatch
from gala.patch_types import DmgApplyTarPatch
from gala.patch_types import DmgBinaryPatch
from gala.patch_types import DmgPatchSet
from gala.patch_types import DmgReplaceFileContentsPatch
from gala.patch_types import FilePermission
from gala.patch_types import InstructionPatch
from gala.patch_types import PatchSet


def get_restore_ramdisk_patches(config: GalaConfig) -> list[DmgPatchSet]:
    should_create_disk_partitions = config.patcher_config.should_create_disk_partitions
    restored_patches = DmgBinaryPatch(
        binary_path=Path("usr/local/bin/restored_external"),
        inner_patch=PatchSet(
            name="",
            patches=[
                # Invoke our controlled asr wrapper instead of invoking asr directly
                BlobPatch(address=VirtualMemoryPointer(0x00031F10), new_content="/usr/bin/asr_wrapper\0".encode()),
                BlobPatch(address=VirtualMemoryPointer(0x00031F28), new_content="\0".encode()),
                InstructionPatch(
                    address=VirtualMemoryPointer(0x00005338),
                    function_name="perform_restore",
                    reason="""
                        The restore would normally branch to a routine to update/flash the device's baseband.
                        We don't care about or handle the baseband, so this would normally fail. Neuter it so the 
                        restore doesn't try to touch the baseband.
                    """,
                    orig_instructions=[Instr.thumb("bl #0x7944")],
                    patched_instructions=[Instr.thumb("movs r0, #0"), Instr.thumb_nop()],
                    expected_length=4,
                ),
                InstructionPatch(
                    address=VirtualMemoryPointer(0x00007D64),
                    function_name="perform_restore",
                    reason="""
                        This is checking whether the LlbImageData key is specified in the restore metadata. 
                        If it is, the LLB will now be flashed to NOR. We want to specifically avoid flashing the LLB, 
                        because an unsigned LLB leads to the 'dead LCD bug'. Therefore, just skip past all this 
                        logic so that the LLB is never flashed.
                    """,
                    orig_instructions=[Instr.thumb("cbz r0, #0x7d74")],
                    patched_instructions=[Instr.thumb("b #0x7d7e")],
                ),
                InstructionPatch(
                    address=VirtualMemoryPointer(0x00009E14),
                    function_name="setup_display",
                    reason="""
                        When restored_external is initializing, it'll claim the display and render an Apple logo and
                        progress bar. If the display is claimed, our on-device asr_wrapper won't render anything to the 
                        screen. Stop restored_external from claiming the display so that asr_wrapper's graphics appear
                        directly on-screen.
                    """,
                    orig_instructions=[Instr.thumb("beq.w #0xa044")],
                    patched_instructions=[Instr.thumb("b #0xa044"), Instr.thumb_nop()],
                    expected_length=4,
                ),
            ],
        ),
    )

    patches = [
        DmgApplyTarPatch(tar_path=ASSETS_ROOT / "ssh_for_restore_ramdisk.tar"),
        DmgReplaceFileContentsPatch(
            file_path=Path("usr/bin/umount"),
            new_content=(GALA_ROOT / "ramdisk_programs" / "umount" / "build" / "umount").read_bytes(),
            new_permissions=FilePermission.rwx(),
        ),
        DmgReplaceFileContentsPatch(
            file_path=Path("usr/bin/asr_wrapper"),
            new_content=(GALA_ROOT / "ramdisk_programs" / "asr_wrapper" / "build" / "asr_wrapper").read_bytes(),
            new_permissions=FilePermission.rwx(),
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
                ).encode(),
            )
        )

    return [DmgPatchSet(patches=patches)]
