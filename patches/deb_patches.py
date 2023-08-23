import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from strongarm.macho import VirtualMemoryPointer

from configuration import IpswPatcherConfig
from patches.base import Patch
from utils import run_and_check


@dataclass
class DebPatch:
    def apply(self, config: IpswPatcherConfig, deb_path: Path) -> None:
        pass


@dataclass
class DebPatchSet(Patch):
    patches: list[DebPatch]

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
    def _mount_deb(path: Path) -> Iterable[Path]:
        print(f"Mounting {path.name}")
        with tempfile.TemporaryDirectory() as mount_dir_raw:
            extracted_deb_dir = Path(mount_dir_raw) / "deb_mount_point"
            run_and_check([
                "/opt/homebrew/bin/dpkg-deb",
                "-R",
                path.as_posix(),
                extracted_deb_dir.as_posix(),
            ])

            try:
                print(f"Mounted .deb to {extracted_deb_dir.as_posix()}")
                yield extracted_deb_dir
            finally:
                # Repack the .deb
                run_and_check([
                    "/opt/homebrew/bin/dpkg-deb",
                    "-Zgzip",
                    "-b",
                    extracted_deb_dir.as_posix(),
                    path.as_posix(),
                ])
                print(f"Unmounted {path.name}")
