import shutil
import tempfile
from dataclasses import dataclass
from enum import Enum
from enum import auto
from math import ceil
from pathlib import Path

from strongarm.macho import MachoParser
from strongarm.macho import VirtualMemoryPointer

from gala.configuration import IpswPatcherConfig
from gala.patch_types import Patch
from gala.utils import run_and_check, mount_dmg


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
        with tempfile.TemporaryDirectory() as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            # hdiutil requires that the file end in .dmg
            decrypted_dmg_with_dmg_extension = temp_dir / "disk.dmg"
            decrypted_dmg_with_dmg_extension.write_bytes(image_data)

            # Resize the disk image, so we have room to write to it
            # Ref: https://apple.stackexchange.com/questions/60613
            current_dmg_size = decrypted_dmg_with_dmg_extension.stat().st_size
            # Add in an extra 4MB. This should be more than enough for everything we do, but if ever necessary this
            # can be bumped.
            extra_room = 1024 * 1024 * 4
            increased_dmg_size = current_dmg_size + extra_room
            total_dmg_size_in_mb = ceil(increased_dmg_size / 1024 / 1024)
            print(f"Resizing .dmg from {current_dmg_size} bytes to {total_dmg_size_in_mb}MB")
            run_and_check(
                [
                    "hdiutil",
                    "resize",
                    "-size",
                    f"{total_dmg_size_in_mb}M",
                    decrypted_dmg_with_dmg_extension.as_posix(),
                ]
            )

            mounted_dmg_root: Path  # PT: Just to help mypy
            with mount_dmg(decrypted_dmg_with_dmg_extension) as mounted_dmg_root:
                print(f"Mounted {decrypted_image_path.name} to {mounted_dmg_root.as_posix()}")
                for patch in self.patches:
                    patch.apply(config, mounted_dmg_root)
            image_data[:] = decrypted_dmg_with_dmg_extension.read_bytes()


@dataclass
class DmgApplyTarPatch(DmgPatch):
    tar_path: Path

    def apply(self, config: IpswPatcherConfig, mounted_dmg_path: Path) -> None:
        print(f"Applying tar {self.tar_path} to dmg...")
        run_and_check(
            [
                "tar",
                "-xvf",
                self.tar_path.as_posix(),
                "-C",
                mounted_dmg_path.as_posix(),
            ]
        )


@dataclass
class DmgRemoveTreePatch(DmgPatch):
    tree_path: Path

    def apply(self, config: IpswPatcherConfig, mounted_dmg_path: Path) -> None:
        print(f"Deleting tree {self.tree_path} from .dmg ({mounted_dmg_path / self.tree_path}")
        shutil.rmtree(mounted_dmg_path / self.tree_path)


class FilePermission(Enum):
    Read = auto()
    Write = auto()
    Execute = auto()

    @classmethod
    def rwx(cls) -> list["FilePermission"]:
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
                raise ValueError(f"Unhandled variant {self}")
        run_and_check(
            [
                "chmod",
                f"+{chmod_flag}",
                file.as_posix(),
            ]
        )


@dataclass
class DmgReplaceFileContentsPatch(DmgPatch):
    file_path: Path
    new_content: bytes
    new_permissions: list[FilePermission] | None = None

    def apply(self, config: IpswPatcherConfig, mounted_dmg_path: Path) -> None:
        print(f"Replacing file {self.file_path} in dmg...")
        qualified_path = mounted_dmg_path / self.file_path
        qualified_path.parent.mkdir(parents=True, exist_ok=True)
        qualified_path.write_bytes(self.new_content)
        if perms := self.new_permissions:
            print(f"Applying permissions to {qualified_path}...")
            for perm in perms:
                perm.apply_to_file(qualified_path)


@dataclass
class DmgBinaryPatch(DmgPatch):
    binary_path: Path
    inner_patch: Patch

    def apply(self, config: IpswPatcherConfig, dmg_root: Path) -> None:
        print(f"Applying dmg patch to binary {self.binary_path}")
        # Find the binary
        qualified_binary_path = dmg_root / self.binary_path
        if not qualified_binary_path.exists():
            raise RuntimeError(f"Failed to find {qualified_binary_path}")

        # Read the binary base address with strongarm
        virtual_base = MachoParser(qualified_binary_path).get_armv7_slice().get_virtual_base()
        print(f"Found virtual base for {self.binary_path.name}: {virtual_base}")

        # Apply the patch to the binary
        patched_binary_data = bytearray(qualified_binary_path.read_bytes())
        self.inner_patch.apply(config, qualified_binary_path, virtual_base, patched_binary_data)
        print("Writing patched binary...")

        qualified_binary_path.write_bytes(patched_binary_data)

        # To aid debugging, also output the patched binary to the working folder
        output_dir = config.patched_images_root()
        safe_binary_name = self.binary_path.as_posix().replace("/", "_")
        saved_binary_path = output_dir / safe_binary_name
        saved_binary_path.write_bytes(patched_binary_data)
