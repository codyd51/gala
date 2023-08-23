from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from strongarm.macho import VirtualMemoryPointer

from configuration import IpswPatcherConfig


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
