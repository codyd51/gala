from dataclasses import dataclass
from pathlib import Path

from os_build import ImageType, OsBuildEnum

JAILBREAK_ROOT = Path("/Users/philliptennen/Documents/Jailbreak")
GALA_ROOT = Path(__file__).parent
PATCHED_IMAGES_ROOT = JAILBREAK_ROOT / "patched_images"
ASSETS_ROOT = JAILBREAK_ROOT / "gala" / "assets"


@dataclass
class IpswPatcherConfig:
    os_build: OsBuildEnum
    replacement_pictures: dict[ImageType, Path]
    should_rebuild_root_filesystem: bool
    should_create_disk_partitions: bool

    def patched_images_root(self) -> Path:
        return PATCHED_IMAGES_ROOT / self.os_build.unescaped_name


@dataclass
class Color:
    r: int
    g: int
    b: int


@dataclass
class DeviceBootConfig:
    boot_args: str
    should_send_restore_ramdisk: bool
    ibss_background_color: Color
    ibec_background_color: Color


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

    def log_event(self, event: str) -> None:
        """Although conceptually a bit odd, outputting logging directly from the Config is quite convenient,
        as it means that the logging is 'available' pretty much everywhere without extra scaffolding.
        """
        if not self.log_high_level_events_to_file:
            print(f'Will not log event to file, because no file has been specified: "{event}"')
            return

        print(f'Logging event to {self.log_high_level_events_to_file}: "{event}"')
        with open(self.log_high_level_events_to_file.as_posix(), "a") as f:
            f.write(f"{event}\n")
