import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional, Mapping
from collections.abc import Iterator

import usb
import usb.core
from usb.backend import libusb1
from usb.backend.libusb1 import _LibUSB

from os_build import OsBuildEnum, ImageType
from patcher import regenerate_patched_images, IpswPatcherConfig, generate_patched_ipsw
from recompile_payloads import recompile_payloads
from utils import TotalEnumMapping, chunks, run_and_check


def get_libusb_backend() -> _LibUSB:
    libusb_path = "/opt/homebrew/Cellar/libusb/1.0.26/lib/libusb-1.0.dylib"
    backend = libusb1.get_backend(find_library=lambda x: libusb_path)
    if not backend:
        raise RuntimeError(f"Failed to find libusb backend at {libusb_path}")
    return backend


def dump_usb_devices():
    for dev in usb.core.find(find_all=True, backend=get_libusb_backend()):
        print(dev)


class DeviceMode(Enum):
    DFU = auto()
    Recovery = auto()

    @property
    def usb_product_id(self):
        return TotalEnumMapping({
            DeviceMode.DFU: 0x1227,
            DeviceMode.Recovery: 0x1281,
        })[self]


@dataclass
class Device:
    handle: usb.core.Device
    mode: DeviceMode

    def upload_file(self, path: Path) -> None:
        print(f'Uploading {path.name} to connected {self.mode.name} Mode device...')
        data = path.read_bytes()
        match self.mode:
            case DeviceMode.DFU:
                self._upload_data_dfu(data)
            case DeviceMode.Recovery:
                self._upload_data_recovery(data)

    def send_command(self, command: str) -> None:
        if self.mode != DeviceMode.Recovery:
            raise ValueError(f"Sending commands is only supported in Recovery Mode")
        self.handle.ctrl_transfer(0x40, 0, data_or_wLength=command.encode() + b'\x00', timeout=30000)

    def _upload_data_dfu(self, data: bytes) -> None:
        max_dfu_upload_chunk_size = 0x800
        for chunk in chunks(data, max_dfu_upload_chunk_size):
            print(f'Uploading chunk of {len(chunk)} bytes...')
            ret = self.handle.ctrl_transfer(0x21, 1, 0, 0, chunk, 3000)
            print(f'\tret {ret}')
        print(f'Informing the DFU device that the upload has finished...')
        self.handle.ctrl_transfer(0x21, 1, 0, 0, 0, timeout=100)
        # Send a 'Get Status' three times
        time.sleep(1)
        for _ in range(3):
            out = bytearray(6)
            ret = self.handle.ctrl_transfer(0xa1, 3, 0, 0, out, timeout=100)
            print(f'get_status ret = {ret}')

        try:
            self.handle.reset()
        except usb.core.USBError:
            # Sometimes this throws an error, but the image load starts anyway
            pass

    def _upload_data_recovery(self, data):
        max_recovery_upload_chunk_size = 0x4000
        if self.handle.ctrl_transfer(0x41, 0, 0, timeout=1000) != 0:
            raise ValueError(f'Expected a response of 0')
        for chunk in chunks(data, max_recovery_upload_chunk_size):
            print(f'Uploading chunk of {len(chunk)} bytes...')
            wrote_bytes = self.handle.write(0x04, chunk, timeout=1000)
            if wrote_bytes != len(chunk):
                raise RuntimeError(f"Expected to write {len(chunk)} bytes, but only wrote {wrote_bytes}")


@contextmanager
def maybe_acquire_device(mode: DeviceMode) -> Iterator[Optional[Device]]:
    """Technically doesn't need to be a context manager,
    but helps describe the semantics of how we interact with the device.
    """
    device_handle = usb.core.find(idVendor=0x5ac, idProduct=mode.usb_product_id, backend=get_libusb_backend())
    if not device_handle:
        yield None
    else:
        yield Device(
            handle=device_handle,
            mode=mode
        )


@contextmanager
def acquire_device(mode: DeviceMode) -> Iterator[Device]:
    with maybe_acquire_device(mode) as maybe_device:
        if not maybe_device:
            raise RuntimeError(f"Unable to find a {mode.name} Mode device")
        yield maybe_device


@contextmanager
def acquire_device_with_timeout(mode: DeviceMode, timeout: int = 10) -> Iterator[Device]:
    start = time.time()
    while time.time() < start + timeout:
        with maybe_acquire_device(mode) as maybe_device:
            if maybe_device:
                yield maybe_device
                return
        print(f'{int(time.time())%100}: Waiting for {mode.name} Mode device to appear...')
        time.sleep(1)
    raise RuntimeError(f"No {mode.name} Mode device appeared after {timeout} seconds")


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

        print(f'Running exploit because we detected a DFU-mode device')

        # Only bother recompiling the payload just before we send the exploit
        jailbreak_folder = Path(__file__).parent / "jailbreak"
        jailbreak_build_folder = jailbreak_folder / "build"
        jailbreak_build_folder.mkdir(exist_ok=True)
        recompile_exploit_runner(jailbreak_folder)
        jailbreak_binary = jailbreak_build_folder / "jailbreak"

        proc: subprocess.CompletedProcess = subprocess.run(jailbreak_binary.as_posix())
        if proc.returncode != 0:
            raise ValueError(f"Jailbreak runner exited with code {proc.returncode}")

    # Give it a chance to run
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
