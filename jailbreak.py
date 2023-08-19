import argparse
import time
from pathlib import Path

import usb
import usb.core

from device import DeviceMode, acquire_device_with_timeout, NoDfuDeviceFoundError
from os_build import ImageType, OsBuildEnum
from patcher import (IpswPatcherConfig, regenerate_patched_images)
from recompile_payloads import recompile_payloads
from securerom import execute_securerom_payload
from utils import run_and_check


def boot_device(patcher_config: IpswPatcherConfig):
    # We need to always recompile the payloads because they may impact what gets injected into the patched images
    recompile_payloads()
    image_types_to_paths = regenerate_patched_images(patcher_config)

    # Run our payload in SecureROM on a connected DFU device
    securerom_shellcode_path = Path(__file__).parent / "payload_stage1" / "build" / "payload_stage1_shellcode"
    securerom_shellcode = securerom_shellcode_path.read_bytes()
    print(f"SecureROM shellcode length: {len(securerom_shellcode)}")

    execute_securerom_payload(securerom_shellcode)

    # Give the on-device payload a chance to run
    time.sleep(3)

    # Re-acquire the device as our previous connection is invalidated after running the exploit
    # Allow the device a moment to await an image again
    ibss_path = image_types_to_paths[ImageType.iBSS]
    with acquire_device_with_timeout(DeviceMode.DFU, timeout=3) as dfu_device:
        # Send the iBSS
        print(f"Sending {ibss_path.name} to DFU device...")
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
        recovery_device.send_command("bgcolor 255 255 127")

        # Upload and jump to the iBEC
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
        recovery_device.send_command("bgcolor 255 217 239")

        # Upload the device tree, ramdisk, and kernelcache
        recovery_device.upload_file(
            Path(
                "/Users/philliptennen/Documents/Jailbreak/unzipped_ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/all_flash/all_flash.n90ap.production/DeviceTree.n90ap.img3"
            )
        )
        recovery_device.send_command("devicetree")
        time.sleep(2)

        if patcher_config.should_boot_to_restore_ramdisk:
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


def boot_device_with_infinite_retry(patcher_config: IpswPatcherConfig):
    while True:
        try:
            boot_device(patcher_config)
            break
        except NoDfuDeviceFoundError:
            print('No DFU device found')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-progress-steps-to-file", action="store")

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--jailbreak', action='store_true')
    group.add_argument('--boot', action='store_true')

    args = parser.parse_args()

    # If a file was specified to write our progress to, ensure it doesn't already exist
    maybe_progress_file = args.write_progress_steps_to_file
    if maybe_progress_file:
        progress_file = Path(maybe_progress_file)
        if progress_file.exists():
            raise ValueError(f"Refusing to write progress to {progress_file} because the file already exists")
        progress_file.touch()

    if args.jailbreak:
        print('Performing downgrade / jailbreak...')
        print('(WARNING: This will wipe all data on the device!)')
        should_rebuild_root_filesystem = True
        boot_args = "rd=md0 amfi=0xff cs_enforcement_disable=1 serial=3"
    elif args.boot:
        print(f'Performing a tethered boot from disk...')
        should_rebuild_root_filesystem = False
        boot_args = "rd=disk0s1 amfi=0xff cs_enforcement_disable=1 serial=3"
    else:
        raise ValueError(f'No job specified')

    # TODO(PT): Split this into a 'patcher config' vs. a 'boot config'
    patcher_config = IpswPatcherConfig(
        OsBuildEnum.iPhone3_1_4_0_8A293,
        replacement_pictures={
            ImageType.AppleLogo: Path(__file__).parent / "assets" / "boot_logo.png",
        },
        should_boot_to_restore_ramdisk=True,
        should_create_disk_partitions=True,
        should_rebuild_root_filesystem=should_rebuild_root_filesystem,
        boot_args=boot_args,
    )
    boot_device_with_infinite_retry(patcher_config)

    if args.jailbreak:
        print('Device booted, flashing OS image...')
        # Give restored_external a moment to come up
        time.sleep(5)

        run_and_check([
            "/Users/philliptennen/Documents/Jailbreak/tools/idevicerestore/src/idevicerestore",
            "--restore-mode",
            "-e",
            "/Users/philliptennen/Documents/Jailbreak/zipped_ipsw/iPhone3,1_4.0_8A293_Restore.ipsw",
        ])

    print('Done!')


if __name__ == "__main__":
    main()
