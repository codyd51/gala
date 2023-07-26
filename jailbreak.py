import subprocess
import time
from pathlib import Path

import usb
import usb.core

from device import DeviceMode, acquire_device, acquire_device_with_timeout
from os_build import OsBuildEnum, ImageType
from patcher import regenerate_patched_images, IpswPatcherConfig, generate_patched_ipsw
from recompile_payloads import recompile_payloads
from securerom import execute_securerom_payload
from utils import run_and_check


def exploit_and_upload_image(image_path: Path):
    with acquire_device(DeviceMode.DFU) as dfu_device:
        securerom_shellcode_path = Path(__file__).parent / "payload_stage1" / "build" / "payload_stage1_shellcode"
        securerom_shellcode = securerom_shellcode_path.read_bytes()
        print(f'SecureROM shellcode length: {len(securerom_shellcode)}')
        execute_securerom_payload(dfu_device, securerom_shellcode)

    # Give the on-device payload a chance to run
    time.sleep(3)

    # Re-acquire the device as our previous connection is invalidated after running the exploit
    # Allow the device a moment to await an image again
    with acquire_device_with_timeout(DeviceMode.DFU, timeout=3) as dfu_device:
        # Send the image (in DFU mode)
        print(f'Sending {image_path.name} to DFU device...')
        dfu_device.upload_file(image_path)

    # Call this just for the side effect of waiting until the Recovery Mode device pops up
    # If it does, everything worked, and we're all done here
    acquire_device_with_timeout(DeviceMode.Recovery)


def main():
    #dump_usb_devices()
    #return
    patcher_config = IpswPatcherConfig(
        OsBuildEnum.iPhone3_1_4_0_8A293,
        replacement_pictures={
            ImageType.AppleLogo: Path(__file__).parent / "assets" / "boot_logo.png",
        }
    )
    # We need to always recompile the payloads because they may impact what gets injected into the patched images
    recompile_payloads()
    image_types_to_paths = regenerate_patched_images(patcher_config)
    generate_patched_ipsw(patcher_config.os_build, image_types_to_paths)

    # Wait for a DFU device to connect
    print('Awaiting DFU device...')
    with acquire_device_with_timeout(DeviceMode.DFU, timeout=100):
        print(f'Got DFU device')

    exploit_and_upload_image(image_types_to_paths[ImageType.iBSS])
    time.sleep(2)

    # The exploit payload will load and jump to the iBSS, which will present as a Recovery Mode device
    with acquire_device(DeviceMode.Recovery) as recovery_device:
        # Upload and set the boot logo
        recovery_device.upload_file(image_types_to_paths[ImageType.AppleLogo])
        recovery_device.send_command("setpicture")
        recovery_device.send_command("bgcolor 255 255 0")

        # Upload and jump to the iBEC
        recovery_device.upload_file(image_types_to_paths[ImageType.iBEC])

        try:
            recovery_device.send_command("go")
        except usb.core.USBError:
            # The device may drop the connection when jumping to the iBEC, but it's no problem, and we'll reconnect
            # just below.
            pass

    # Give the device a moment to disconnect and reconnect
    time.sleep(5)

    with acquire_device(DeviceMode.Recovery) as recovery_device:
        print(f'Device is now running iBEC {recovery_device}')
        # Set the Apple logo again
        recovery_device.upload_file(image_types_to_paths[ImageType.AppleLogo])
        recovery_device.send_command("setpicture")
        recovery_device.send_command("bgcolor 255 0 255")

        recovery_device.upload_file(Path("/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/all_flash/all_flash.n90ap.production/DeviceTree.n90ap.img3"))
        recovery_device.send_command("devicetree")
        time.sleep(2)
        # recovery_device.upload_file(Path("/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/018-6306-403.dmg"))
        recovery_device.upload_file(image_types_to_paths[ImageType.RestoreRamdisk])
        #recovery_device.upload_file(Path("/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/018-6305-405.dmg"))
        #recovery_device.upload_file(Path("/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/018-6303-385.dmg"))
        recovery_device.send_command("ramdisk")
        time.sleep(2)
        recovery_device.upload_file(Path("/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/kernelcache.release.n90"))
        # PT: Should replace with below, just didn't want to ry 2 things tat once
        #recovery_device.upload_file(image_types_to_paths[ImageType.KernelCache])

        try:
            recovery_device.send_command("bootx")
        except usb.core.USBError:
            # The device may drop the connection when jumping to the kernel, but it's no problem
            pass

    time.sleep(5)

    # Start the restore process with the modified IPSW
    # TODO(PT): Repack into an ipsw as below
    if False:
        run_and_check([
            "/Users/philliptennen/Documents/Jailbreak/tools/idevicerestore/src/idevicerestore",
            "--restore-mode",
            "/Users/philliptennen/Documents/Jailbreak/patched_images/iPhone3,1_4.0_8A293/patched.ipsw",
        ])
    # ./xpwntool /Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/018-6306-403.dmg decrypted_ramdisk -k 62aabe3e763eb3669b4922468be2acb787199c6b0ef8ae873c312e458d9b9be3 -iv 0ab135879934fdd0d689b3d0f8cf8374

    # dump_usb_devices()


if __name__ == '__main__':
    main()
