import argparse
import time
from pathlib import Path

import usb
import usb.core

from gala.configuration import ASSETS_ROOT
from gala.configuration import DEPENDENCIES_ROOT
from gala.configuration import GALA_ROOT
from gala.configuration import UNZIPPED_IPSWS_ROOT
from gala.configuration import Color
from gala.configuration import DeviceBootConfig
from gala.configuration import GalaConfig
from gala.configuration import IpswPatcherConfig
from gala.device import DeviceMode
from gala.device import NoDfuDeviceFoundError
from gala.device import acquire_device_with_timeout
from gala.os_build import ImageType
from gala.os_build import OsBuildEnum
from gala.patcher import regenerate_patched_images
from gala.recompile_payloads import recompile_payloads
from gala.securerom import execute_securerom_payload
from gala.utils import run_and_check


def boot_device(config: GalaConfig) -> None:
    # We need to always recompile the payloads because they may impact what gets injected into the patched images
    config.log_event("Compiling payloads...")
    recompile_payloads()
    config.log_event("Generating patched image tree...")
    image_types_to_paths = regenerate_patched_images(config)

    # Run our payload in SecureROM on a connected DFU device
    securerom_shellcode_path = (
        GALA_ROOT / "shellcode_programs" / "securerom_payload" / "build" / "securerom_payload_shellcode"
    )
    securerom_shellcode = securerom_shellcode_path.read_bytes()
    print(f"SecureROM shellcode length: {len(securerom_shellcode)}")

    execute_securerom_payload(config, securerom_shellcode)

    # Give the on-device payload a chance to run
    time.sleep(3)

    # Re-acquire the device as our previous connection is invalidated after running the exploit
    # Allow the device a moment to await an image again
    ibss_path = image_types_to_paths[ImageType.iBSS]
    with acquire_device_with_timeout(DeviceMode.DFU, timeout=3) as dfu_device:
        # Send the iBSS
        print(f"Sending {ibss_path.name} to DFU device...")
        config.log_event("Starting iBSS...")
        dfu_device.upload_file(ibss_path)

    # Give the iBSS a moment to come up cleanly
    # Call this just for the side effect of waiting until the Recovery Mode device pops up
    # If it does, the iBSS has successfully launched
    acquire_device_with_timeout(DeviceMode.Recovery)
    time.sleep(1)

    # The exploit payload will load and jump to the iBSS, which will present as a Recovery Mode device
    with acquire_device_with_timeout(DeviceMode.Recovery) as recovery_device:
        # Upload and set the boot logo
        recovery_device.upload_file(image_types_to_paths[ImageType.AppleLogo])
        recovery_device.send_command("setpicture")
        ibss_bg = config.boot_config.ibss_background_color
        recovery_device.send_command(f"bgcolor {ibss_bg.r} {ibss_bg.g} {ibss_bg.b}")

        # Upload and jump to the iBEC
        config.log_event("Starting iBEC...")
        recovery_device.upload_file(image_types_to_paths[ImageType.iBEC])

        try:
            recovery_device.send_command("go")
        except usb.core.USBError:
            # The device may drop the connection when jumping to the iBEC, but it's no problem, and we'll reconnect
            # just below.
            pass

    # Give the iBEC a moment to come up cleanly
    time.sleep(3)
    with acquire_device_with_timeout(DeviceMode.Recovery) as recovery_device:
        print(f"Device is now running iBEC {recovery_device}")
        # Set the boot logo again
        recovery_device.upload_file(image_types_to_paths[ImageType.AppleLogo])
        recovery_device.send_command("setpicture")
        ibec_bg = config.boot_config.ibec_background_color
        recovery_device.send_command(f"bgcolor {ibec_bg.r} {ibec_bg.g} {ibec_bg.b}")

        # Upload the device tree, ramdisk, and kernelcache
        config.log_event("Starting kernel...")
        recovery_device.upload_file(
            # TODO(PT): Look this up using our modeling
            UNZIPPED_IPSWS_ROOT
            / "iPhone3,1_4.0_8A293"
            / "Firmware"
            / ("all_flash/all_flash.n90ap.production/DeviceTree.n90ap.img3")
        )
        recovery_device.send_command("devicetree")
        time.sleep(2)

        if config.boot_config.should_send_restore_ramdisk:
            print("Sending restore ramdisk...")
            recovery_device.upload_file(image_types_to_paths[ImageType.RestoreRamdisk])
            recovery_device.send_command("ramdisk")

        recovery_device.upload_file(image_types_to_paths[ImageType.KernelCache])

        try:
            recovery_device.send_command("bootx")
        except usb.core.USBError:
            # The device may drop the connection when jumping to the kernel, but it's no problem
            pass

    time.sleep(5)


def boot_device_with_infinite_retry(config: GalaConfig) -> None:
    while True:
        try:
            boot_device(config)
            break
        except NoDfuDeviceFoundError:
            print("No DFU device found")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--log_high_level_events_to_file", action="store", default=None)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--jailbreak", action="store_true")
    group.add_argument("--boot", action="store_true")

    args = parser.parse_args()

    # If a file was specified to write our progress to, ensure it doesn't already exist
    maybe_progress_file_path = args.log_high_level_events_to_file
    maybe_progress_file = None
    if maybe_progress_file_path:
        maybe_progress_file = Path(maybe_progress_file_path)

    if args.jailbreak:
        print("Performing downgrade / jailbreak...")
        print("(WARNING: This will wipe all data on the device!)")
        should_rebuild_root_filesystem = True
        boot_args = "rd=md0 amfi=0xff cs_enforcement_disable=1 serial=3"
    elif args.boot:
        print("Performing a tethered boot from disk...")
        should_rebuild_root_filesystem = False
        boot_args = "rd=disk0s1 amfi=0xff cs_enforcement_disable=1 serial=3"
    else:
        raise ValueError("No job specified")

    config = GalaConfig(
        boot_config=DeviceBootConfig(
            boot_args=boot_args,
            should_send_restore_ramdisk=True,
            ibss_background_color=Color(r=255, g=255, b=127),
            ibec_background_color=Color(r=185, g=240, b=193),
        ),
        patcher_config=IpswPatcherConfig(
            OsBuildEnum.iPhone3_1_4_0_8A293,
            replacement_pictures={
                ImageType.AppleLogo: ASSETS_ROOT / "boot_logo.png",
            },
            should_create_disk_partitions=True,
            should_rebuild_root_filesystem=should_rebuild_root_filesystem,
        ),
        log_high_level_events_to_file=maybe_progress_file,
    )
    boot_device_with_infinite_retry(config)

    if args.jailbreak:
        print("Device booted, flashing OS image...")
        config.log_event("Flashing OS image...")
        # Give restored_external a moment to come up
        time.sleep(5)

        try:
            run_and_check(
                [
                    (DEPENDENCIES_ROOT / "idevicerestore" / "src" / "idevicerestore").as_posix(),
                    "--restore-mode",
                    "-e",
                    # TODO(PT): Host this in the gala dir
                    "/Users/philliptennen/Documents/Jailbreak/zipped_ipsw/iPhone3,1_4.0_8A293_Restore.ipsw",
                ],
                # Inform our patched idevicerestore about gala's location
                # It needs this to know where to find gala's patched root filesystem, kernelcache, assets to send to the
                # device, sshpass dependency, etc.
                env_additions={
                    "GALA_ROOT": GALA_ROOT.as_posix(),
                },
            )
        except RuntimeError:
            config.log_event("Error: Restore failed.")
            raise
        config.log_event("Device flashed, all done!")
    elif args.boot:
        config.log_event("Device booted, all done!")
    else:
        raise ValueError("Unknown job")

    print("Done!")


if __name__ == "__main__":
    main()
