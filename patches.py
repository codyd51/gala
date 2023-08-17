from __future__ import annotations

import os
import plistlib
import shutil
import tempfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, auto
from math import ceil
from pathlib import Path
from typing import Iterable

from capstone import CS_ARCH_ARM, CS_MODE_THUMB, Cs
from strongarm.macho import (ArchitectureNotSupportedError, MachoParser,
                             VirtualMemoryPointer)

from assemble import Instr, assemble
from configuration import PATCHED_IMAGES_ROOT
from os_build import ImageType, OsBuildEnum
from utils import run_and_capture_output_and_check, run_and_check


@dataclass
class IpswPatcherConfig:
    os_build: OsBuildEnum
    replacement_pictures: dict[ImageType, Path]
    should_boot_to_restore_ramdisk: bool
    boot_args: str
    should_rebuild_root_filesystem: bool
    should_create_disk_partitions: bool


@dataclass
class Function:
    name: str
    address: VirtualMemoryPointer


class Patch(ABC):
    @abstractmethod
    def apply(
        self,
        patcher_config: IpswPatcherConfig,
        decrypted_image_path: Path,
        image_base_address: VirtualMemoryPointer,
        image_data: bytearray,
    ) -> None:
        ...


@dataclass
class InstructionPatch(Patch):
    """A 'structured' patch meant for small-scale patches of specific instructions.
    Provides various validations that the state of the binary described in the fields match reality.
    This helps sanity-check various assumptions about exactly what the patch is doing.

    For example, this type of patch requires the user to describe upfront which instructions they expect to be patching.
    This type of patch will disassemble the pre-patched instructions, to ensure that the actual bytes being patched
    match the expected instructions.
    Similarly, this type of patch will also disassemble the newly applied patch, to make sure the assembled patch code
    exactly matches what was described in the patch.
    This type of patch will also ensure that the patched instructions fit exactly into the number of bytes described
    by the original instructions (i.e. ensure the patch writer doesn't accidentally write out of bounds from what they
    were expecting).
    """

    function_name: str
    address: VirtualMemoryPointer
    orig_instructions: list[Instr]
    patched_instructions: list[Instr]
    expected_length: int | None = None

    @classmethod
    def shellcode(cls, addr: int) -> InstructionPatch:
        shellcode_addr = 0x8057A314
        branch_to_shellcode = Instr.thumb(f"bl #{hex(shellcode_addr)}")
        return cls(
            function_name="",
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[branch_to_shellcode],
        )

    @classmethod
    def shellcode2(cls, shellcode_addr: int, addr: int) -> InstructionPatch:
        branch_to_shellcode = Instr.thumb(f"bl #{hex(shellcode_addr)}")
        return cls(
            function_name="",
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[branch_to_shellcode],
        )

    @classmethod
    def quick(cls, addr: int, new_instr: Instr | list[Instr], expected_length: int | None = None) -> InstructionPatch:
        return cls(
            function_name="",
            address=VirtualMemoryPointer(addr),
            orig_instructions=[],
            patched_instructions=[new_instr] if isinstance(new_instr, Instr) else new_instr,
            expected_length=expected_length,
        )

    def apply(
        self,
        config: IpswPatcherConfig,
        decrypted_image_path: Path,
        image_base_address: VirtualMemoryPointer,
        data: bytearray,
    ) -> None:
        print()
        # function = patch.function
        # print(f'Patching {function.name}:')
        print(f"Applying patch at {self.address}")
        print(f"    {self.address} {self.orig_instructions}")
        print(f"   Patch ----> {self.patched_instructions}")
        # if len(patch.orig_instructions) != len(patch.patched_instructions):
        #    raise ValueError(f'Expected to have the same number of instructions in the pre- and post-patch state')

        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        cs.detail = True

        region_size = sum([i.format.typical_size for i in self.orig_instructions])

        try:
            macho_parser = MachoParser(decrypted_image_path)
            if macho_parser.is_magic_supported():
                print(f"Applying instruction patch to a Mach-O")
                binary = macho_parser.get_armv7_slice()
                patch_file_offset = binary.file_offset_for_virtual_address(self.address)
            else:
                raise ArchitectureNotSupportedError()
        except ArchitectureNotSupportedError:
            print(f"Applying instruction patch to a raw binary")
            patch_file_offset = self.address - image_base_address

        instr_bytes = data[patch_file_offset : patch_file_offset + region_size]
        actual_orig_instructions = list(cs.disasm(instr_bytes, self.address)) if len(self.orig_instructions) else []

        # Validate the original instructions are what we expect
        if len(actual_orig_instructions) != len(self.orig_instructions):
            raise ValueError(
                f"Expected to find {len(self.orig_instructions)} instructions, but found {len(actual_orig_instructions)}: {self.orig_instructions}, {actual_orig_instructions}"
            )
        for actual_orig_instruction, expected_orig_instruction in zip(actual_orig_instructions, self.orig_instructions):
            actual_orig_instruction_str = f"{actual_orig_instruction.mnemonic} {actual_orig_instruction.op_str}"
            if actual_orig_instruction_str != expected_orig_instruction.value:
                raise ValueError(
                    f'Expected to disassemble "{expected_orig_instruction}", but found "{actual_orig_instruction_str}"'
                )

        # Assemble the patched instructions
        patched_instr_address = self.address
        patch_length = 0
        for patched_instr in self.patched_instructions:
            try:
                assembled_bytes = assemble(patched_instr_address, patched_instr)
            except ValueError as e:
                raise ValueError(f"Failed to assemble instruction \"{patched_instr.value}\": {e}")
            # It's possible for assembled Thumb instructions to take up 4 bytes: for example, THUMB bl <offset>.
            # Therefore, check the length of the assembled bytes, rather than relying on size reported by the format
            assembled_bytes_len = len(assembled_bytes)
            # Validate that the instruction was assembled correctly
            disassembled_instrs = list(cs.disasm(assembled_bytes, patched_instr_address))
            if len(disassembled_instrs) != 1:
                raise ValueError(f"Expected to disassemble exactly one instruction, but got {disassembled_instrs}")
            disassembled_instr = disassembled_instrs[0]
            if not disassembled_instr.op_str:
                assembled_instr_str = disassembled_instr.mnemonic
            else:
                assembled_instr_str = f"{disassembled_instr.mnemonic} {disassembled_instr.op_str}"
            if assembled_instr_str != patched_instr.value:
                raise ValueError(f'Expected to assemble "{patched_instr.value}", but assembled "{assembled_instr_str}"')

            # Apply the patch to the binary
            data[patch_file_offset : patch_file_offset + assembled_bytes_len] = assembled_bytes

            # Iterate to the next instruction location
            patched_instr_address += assembled_bytes_len
            patch_file_offset += assembled_bytes_len
            patch_length += assembled_bytes_len

        if self.expected_length and patch_length != self.expected_length:
            raise ValueError(f"Expected a patch of {self.expected_length} bytes, but patch was {patch_length} bytes!")


@dataclass
class BlobPatch(Patch):
    """An 'unstructured' patch that allows the patch writer to drop raw bytes at a given location, with no validation
    on what's being overwritten or the contents of the patch.
    """

    address: VirtualMemoryPointer
    new_content: bytes

    def apply(
        self,
        config: IpswPatcherConfig,
        decrypted_image_path: Path,
        image_base_address: VirtualMemoryPointer,
        image_data: bytearray,
    ) -> None:
        print(f"Applying unstructured patch of {len(self.new_content)} bytes at {self.address}")
        # hexdump(patch.new_content)
        try:
            macho_parser = MachoParser(decrypted_image_path)
            if macho_parser.is_magic_supported():
                print(f"Applying blob patch to a Mach-O")
                binary = macho_parser.get_armv7_slice()
                patch_file_offset = binary.file_offset_for_virtual_address(self.address)
            else:
                raise ArchitectureNotSupportedError()
        except ArchitectureNotSupportedError:
            print(f"Applying instruction patch to a raw binary")
            patch_file_offset = self.address - image_base_address
        # patch_file_offset = self.address - image_base_address

        if patch_file_offset < 0 or patch_file_offset >= len(image_data):
            raise ValueError(f"Invalid offset {patch_file_offset}")
        print(f"File offset for {self.new_content} is {hex(patch_file_offset)}")
        image_data[patch_file_offset : patch_file_offset + len(self.new_content)] = self.new_content


@dataclass
class PatchSet(Patch):
    """A collection of patches that are logically grouped together.
    This has no difference in functionality to declaring top-level patches individually, and serves purely as an
    organizational tool.
    """

    name: str
    patches: list[Patch]

    def apply(
        self,
        config: IpswPatcherConfig,
        decrypted_image_path: Path,
        image_base_address: VirtualMemoryPointer,
        image_data: bytearray,
    ) -> None:
        print(f"Applying patch set {self.name}...")
        for patch in self.patches:
            patch.apply(config, decrypted_image_path, image_base_address, image_data)


@contextmanager
def _mount_dmg_old(path: Path) -> Iterable[Path]:
    print(f"Mounting {path.name}")
    hdiutil_output_raw = run_and_capture_output_and_check(
        [
            "hdiutil",
            "attach",
            "-plist",
            path.as_posix(),
        ]
    )
    hdiutil_output = plistlib.loads(hdiutil_output_raw)
    mounted_dmg_root = Path(hdiutil_output["system-entities"][0]["mount-point"])
    print(f"Mounted to {mounted_dmg_root.as_posix()}")

    try:
        yield mounted_dmg_root
    finally:
        # Unmount the disk
        run_and_check(
            [
                "hdiutil",
                "detach",
                mounted_dmg_root.as_posix(),
            ]
        )
        print(f"Unmounted {path.name}")


@dataclass
class DmgPatch:
    def apply(self, config: IpswPatcherConfig, mounted_dmg_path: Path) -> None:
        pass


@dataclass
class DmgPatchSet(Patch):
    patches: list[DmgPatch]

    def apply(
        self,
        config: IpswPatcherConfig,
        decrypted_image_path: Path,
        image_base_address: VirtualMemoryPointer,
        image_data: bytearray,
    ) -> None:
        # TODO(PT): Replace `ramdisk` nomenclature here
        with tempfile.TemporaryDirectory() as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            decrypted_ramdisk_with_dmg_extension = temp_dir / "ramdisk.dmg"
            decrypted_ramdisk_with_dmg_extension.write_bytes(image_data)

            # Resize the ramdisk so we have room to write to it
            # Ref: https://apple.stackexchange.com/questions/60613
            current_dmg_size = decrypted_ramdisk_with_dmg_extension.stat().st_size
            # Add in an extra 4MB. This should be more than enough for everything we do, but if ever necessary this
            # can be bumped.
            extra_room = 1024 * 1024 * 4
            increased_dmg_size = current_dmg_size + extra_room
            total_dmg_size_in_mb = ceil(increased_dmg_size / 1024 / 1024)
            print(f'Resizing .dmg from {current_dmg_size} bytes to {total_dmg_size_in_mb}MB')
            run_and_check(
                [
                    "hdiutil",
                    "resize",
                    "-size",
                    f"{total_dmg_size_in_mb}M",
                    decrypted_ramdisk_with_dmg_extension.as_posix(),
                ]
            )

            if True:
                with self._mount_dmg(decrypted_ramdisk_with_dmg_extension) as mounted_dmg_root:
                    print(f"Mounted {decrypted_image_path.name} to {mounted_dmg_root.as_posix()}")
                    for patch in self.patches:
                        patch.apply(config, mounted_dmg_root)
                image_data[:] = decrypted_ramdisk_with_dmg_extension.read_bytes()

    @staticmethod
    @contextmanager
    def _mount_dmg(path: Path) -> Iterable[Path]:
        print(f"Mounting {path.name}")
        with tempfile.TemporaryDirectory() as mount_dir_raw:
            mount_point = Path(mount_dir_raw) / "dmg_mount_point"
            run_and_check(
                [
                    "hdiutil",
                    "attach",
                    "-mountpoint",
                    f"{mount_point.as_posix()}/",
                    path.as_posix(),
                ]
            )
            print(f"Mounted to {mount_point.as_posix()}")

            try:
                yield mount_point
            finally:
                # Unmount the disk
                run_and_check(
                    [
                        "hdiutil",
                        "detach",
                        mount_point.as_posix(),
                    ]
                )
                print(f"Unmounted {path.name}")


@dataclass
class DmgApplyTarPatch(DmgPatch):
    tar_path: Path

    def apply(self, config: IpswPatcherConfig, mounted_ramdisk_path: Path) -> None:
        print(f"Applying tar {self.tar_path} to ramdisk...")
        run_and_check(
            [
                "tar",
                "--fflags",
                "--mac-metadata",
                "--same-owner",
                "--xattrs",
                "-xvpf",
                self.tar_path.as_posix(),
                "-C",
                mounted_ramdisk_path.as_posix(),
            ]
        )


@dataclass
class DmgRemoveTreePatch(DmgPatch):
    tree_path: Path

    def apply(self, config: IpswPatcherConfig, mounted_ramdisk_path: Path) -> None:
        print(f'Deleting tree {self.tree_path} from .dmg ({mounted_ramdisk_path / self.tree_path}')
        shutil.rmtree(mounted_ramdisk_path / self.tree_path)


class FilePermission(Enum):
    Read = auto()
    Write = auto()
    Execute = auto()

    @classmethod
    def rwx(cls) -> list['FilePermission']:
        return [
            FilePermission.Read,
            FilePermission.Write,
            FilePermission.Execute,
        ]

    def apply_to_file(self, file: Path) -> None:
        match self:
            case FilePermission.Read:
                chmod_flag = "r"
            case FilePermission.Write:
                chmod_flag = "w"
            case FilePermission.Execute:
                chmod_flag = "x"
            case _:
                raise ValueError(f'Unhandled variant {self}')
        run_and_check([
            'chmod',
            f'+{chmod_flag}',
            file.as_posix(),
        ])


@dataclass
class DmgReplaceFileContentsPatch(DmgPatch):
    file_path: Path
    new_content: bytes
    new_permissions: list[FilePermission] | None = None

    def apply(self, config: IpswPatcherConfig, mounted_ramdisk_path: Path) -> None:
        print(f"Replacing file {self.file_path} in ramdisk...")
        qualified_path = mounted_ramdisk_path / self.file_path
        qualified_path.write_bytes(self.new_content)
        if perms := self.new_permissions:
            print(f'Applying permissions to {qualified_path}...')
            for perm in perms:
                perm.apply_to_file(qualified_path)



@dataclass
class DmgBinaryPatch(DmgPatch):
    # PT: Instead of having the binary at the top level, this could just contain a PatchSet
    # Then we could apply the binary patches in the patch set, so we only mount the ramdisk once
    binary_path: Path
    inner_patch: Patch

    def apply(self, config: IpswPatcherConfig, ramdisk_root: Path) -> None:
        print(f"Applying ramdisk patch to binary {self.binary_path}")
        # Find the binary
        qualified_binary_path = ramdisk_root / self.binary_path
        if not qualified_binary_path.exists():
            raise RuntimeError(f"Failed to find {qualified_binary_path}")

        # Read the binary base address with strongarm
        virtual_base = MachoParser(qualified_binary_path).get_armv7_slice().get_virtual_base()
        print(f"Found virtual base for {self.binary_path.name}: {virtual_base}")

        # Apply the patch to the binary
        patched_binary_data = bytearray(qualified_binary_path.read_bytes())
        self.inner_patch.apply(config, qualified_binary_path, virtual_base, patched_binary_data)
        print(f"Writing patched binary...")

        qualified_binary_path.write_bytes(patched_binary_data)

        # To aid debugging, also output the patched binary to the working folder
        # TODO(PT): This needs to be refactored somehow
        output_dir = PATCHED_IMAGES_ROOT / config.os_build.unescaped_name
        safe_binary_name = self.binary_path.as_posix().replace("/", "_")
        saved_binary_path = output_dir / safe_binary_name
        saved_binary_path.write_bytes(patched_binary_data)

        # Run ldid
        if False:
            run_and_check(
                [
                    # "/Users/philliptennen/Documents/Jailbreak/tools/ldid/ldid",
                    # "/Users/philliptennen/Downloads/sbigner-ldid",
                    "/Users/philliptennen/Documents/Jailbreak/tools/proscurus-ldid/ldid",
                    "-S",
                    qualified_binary_path.as_posix(),
                ]
            )

    def apply_new(
        self, decrypted_image_path: Path, image_base_address: VirtualMemoryPointer, image_data: bytearray
    ) -> None:
        print(f"Applying ramdisk patch to binary {self.binary_path}")
        # Mount the ramdisk
        # (Note that we need to serialize the current ramdisk data to a .dmg, so we keep any previous patches we've applied
        with tempfile.TemporaryDirectory() as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            patched_ramdisk = temp_dir / "ramdisk.patched.dmg"
            patched_ramdisk.write_bytes(image_data)

            run_and_check(
                [
                    "/Users/philliptennen/Documents/Jailbreak/tools/xpwn-xerub/hfs/hfsplus",
                    patched_ramdisk.as_posix(),
                    "grow",
                    "24002560",
                ]
            )

            self._apply_patch(patched_ramdisk)

            image_data[:] = patched_ramdisk.read_bytes()

    def _apply_patch_new(self, ramdisk_root: Path) -> None:
        # Extract the binary
        binary_path = Path("/") / self.binary_path
        with tempfile.TemporaryDirectory() as tempdir_raw:
            tempdir = Path(tempdir_raw)
            extracted_binary_path = tempdir / f"extracted_{self.binary_path.name}"

            run_and_check(
                [
                    "/Users/philliptennen/Documents/Jailbreak/tools/xpwn-xerub/hfs/hfsplus",
                    ramdisk_root.as_posix(),
                    "extract",
                    binary_path.as_posix(),
                    extracted_binary_path.as_posix(),
                ]
            )
            print(f"Extracted {binary_path.as_posix()} to {extracted_binary_path.as_posix()}")

            # Read the binary base address with strongarm
            virtual_base = MachoParser(extracted_binary_path).get_armv7_slice().get_virtual_base()
            print(f"Found virtual base for {binary_path.name}: {virtual_base}")

            # Apply the patch to the binary
            patched_binary_data = bytearray(extracted_binary_path.read_bytes())
            # TODO(PT): Does this modify the underlying file or do we need to write it back?
            self.inner_patch.apply(extracted_binary_path, virtual_base, patched_binary_data)
            extracted_binary_path.write_bytes(patched_binary_data)
            # Run ldid
            if False:
                run_and_check(
                    [
                        "/Users/philliptennen/Documents/Jailbreak/tools/ldid/ldid2",
                        "-S",
                        extracted_binary_path.as_posix(),
                    ]
                )

            print(f"Writing patched binary...")
            run_and_check(
                [
                    "/Users/philliptennen/Documents/Jailbreak/tools/xpwn-xerub/hfs/hfsplus",
                    ramdisk_root.as_posix(),
                    "add",
                    extracted_binary_path.as_posix(),
                    binary_path.as_posix(),
                ]
            )
            run_and_check(
                [
                    "/Users/philliptennen/Documents/Jailbreak/tools/xpwn-xerub/hfs/hfsplus",
                    ramdisk_root.as_posix(),
                    "chmod",
                    "755",
                    binary_path.as_posix(),
                ]
            )

    def apply2(
        self, decrypted_image_path: Path, image_base_address: VirtualMemoryPointer, image_data: bytearray
    ) -> None:
        print(f"Applying ramdisk patch to binary {self.binary_path}")
        # Mount the ramdisk
        # hdiutil (annoyingly) requires that the ramdisk end in .dmg instead of .dmg.decrypted,
        # so create a temporary copy now with the correct extension
        with tempfile.TemporaryDirectory() as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            decrypted_ramdisk_with_dmg_extension = temp_dir / "ramdisk.dmg"
            shutil.copy(decrypted_image_path, decrypted_ramdisk_with_dmg_extension)

            # Resize the ramdisk so we have room to write to it
            # Ref: https://apple.stackexchange.com/questions/60613
            # TODO(PT): Shrink the ramdisk again
            run_and_check(
                [
                    "hdiutil",
                    "resize",
                    "-size",
                    "20M",
                    decrypted_ramdisk_with_dmg_extension.as_posix(),
                ]
            )

            with _mount_dmg(decrypted_ramdisk_with_dmg_extension) as mounted_dmg_root:
                # Find the binary
                qualified_binary_path = mounted_dmg_root / self.binary_path
                if not qualified_binary_path.exists():
                    raise RuntimeError(f"Failed to find {qualified_binary_path}")

                # Read the binary base address with strongarm
                virtual_base = MachoParser(qualified_binary_path).get_armv7_slice().get_virtual_base()
                print(f"Found virtual base for {self.binary_path.name}: {virtual_base}")

                # Apply the patch to the binary
                patched_binary_data = bytearray(qualified_binary_path.read_bytes())
                self.inner_patch.apply(qualified_binary_path, virtual_base, patched_binary_data)
                print(f"Writing patched binary...")

                patched_file = temp_dir / "patched_binary"
                patched_file.write_bytes(patched_binary_data)

                qualified_binary_path.write_bytes(patched_binary_data)

                # Run ldid
                if False:
                    run_and_check(
                        [
                            "/Users/philliptennen/Documents/Jailbreak/tools/ldid/ldid2",
                            "-S",
                            qualified_binary_path.as_posix(),
                        ]
                    )

                # Repack the ramdisk
                ramdisk_with_edits = Path(temp_dir_raw) / "edited_ramdisk.dmg"
                run_and_check(
                    [
                        "hdiutil",
                        "create",
                        ramdisk_with_edits.as_posix(),
                        "-srcfolder",
                        mounted_dmg_root.as_posix(),
                    ]
                )
                print("abc")
            image_data[:] = ramdisk_with_edits.read_bytes()
