from dataclasses import dataclass
from pathlib import Path

from os_build import OsBuildEnum, ImageType

JAILBREAK_ROOT = Path("/Users/philliptennen/Documents/Jailbreak")
PATCHED_IMAGES_ROOT = JAILBREAK_ROOT / "patched_images"

@dataclass
class IpswPatcherConfig:
    os_build: OsBuildEnum
    replacement_pictures: dict[ImageType, Path]
    should_send_restore_ramdisk: bool
    should_rebuild_root_filesystem: bool
    should_create_disk_partitions: bool


@dataclass
class DeviceBootConfig:
    boot_args: str


@dataclass
class GalaConfig:
    """High-level configuration object that stores the full gala option tree"""

    # XXX(PT): The divide between 'boot config' and 'IPSW patcher config' is purely conceptual, and there's a lot of
    # crossover between these two concepts; for example, boot arguments are specified /by/ components in the OS image,
    # and patches to the IPSW likewise obviously impact behavior during boot.
    boot_config: DeviceBootConfig
    patcher_config: IpswPatcherConfig
    # Useful for providing user-facing 'status updates' to the GUI
    log_high_level_events_to_file: Path | None = None
