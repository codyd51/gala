import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from typing import Sequence

from strongarm.macho import MachoParser
from strongarm.macho import VirtualMemoryPointer

from gala.configuration import IpswPatcherConfig
from gala.patch_types import Patch
from gala.utils import run_and_check


@dataclass
class DebPatch:
    def apply(self, config: IpswPatcherConfig, deb_path: Path) -> None:
        pass


@dataclass
class DebPatchSet(Patch):
    patches: Sequence[DebPatch]

    def apply(
        self,
        config: IpswPatcherConfig,
        image_path: Path,
        image_base_address: VirtualMemoryPointer,
        image_data: bytearray,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            copied_deb = temp_dir / "copy.deb"
            copied_deb.write_bytes(image_data)

            with self._mount_deb(copied_deb) as mounted_deb_root:
                print(f"Mounted {image_path.name} to {mounted_deb_root.as_posix()}")
                for patch in self.patches:
                    patch.apply(config, mounted_deb_root)
            image_data[:] = copied_deb.read_bytes()

    @staticmethod
    @contextmanager
    def _mount_deb(path: Path) -> Iterator[Path]:
        print(f"Mounting {path.name}")
        with tempfile.TemporaryDirectory() as mount_dir_raw:
            extracted_deb_dir = Path(mount_dir_raw) / "deb_mount_point"
            run_and_check(
                [
                    "/opt/homebrew/bin/dpkg-deb",
                    "-R",
                    path.as_posix(),
                    extracted_deb_dir.as_posix(),
                ]
            )

            try:
                print(f"Mounted .deb to {extracted_deb_dir.as_posix()}")
                yield extracted_deb_dir
            finally:
                # Repack the .deb
                run_and_check(
                    [
                        "/opt/homebrew/bin/dpkg-deb",
                        "-Zgzip",
                        "-b",
                        extracted_deb_dir.as_posix(),
                        path.as_posix(),
                    ]
                )
                print(f"Unmounted {path.name}")


@dataclass
class DebBinaryPatch(DebPatch):
    binary_path: Path
    inner_patch: Patch

    def apply(self, config: IpswPatcherConfig, deb_root: Path) -> None:
        print(f"Applying deb patch to binary {self.binary_path}")
        # Find the binary
        qualified_binary_path = deb_root / self.binary_path
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
