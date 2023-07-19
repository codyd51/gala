import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional
from collections.abc import Iterator

import usb
import usb.core
from usb.backend import libusb1
from usb.backend.libusb1 import _LibUSB

from os_build import OsBuildEnum, ImageType
from patcher import regenerate_patched_images, IpswPatcherConfig
from recompile_payloads import recompile_payloads
from utils import TotalEnumMapping, chunks


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

    def upload_data(self, data: bytes) -> None:
        match self.mode:
            case DeviceMode.DFU:
                self._upload_data_dfu(data)
            case DeviceMode.Recovery:
                self._upload_data_recovery(data)

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
        dfu_device.upload_data(image_path.read_bytes())

    # Call this just for the side effect of waiting until the Recovery Mode device pops up
    # If it does, everything worked, and we're all done here
    acquire_device_with_timeout(DeviceMode.Recovery)


def main():
    patcher_config = IpswPatcherConfig(
        OsBuildEnum.iPhone3_1_4_0_8A293,
        replacement_pictures={
            ImageType.AppleLogo: Path("/Users/philliptennen/Downloads/mango_logo.png"),
        }
    )
    # We need to always recompile the payloads because they may impact what gets injected into the patched images
    recompile_payloads()
    image_types_to_paths = regenerate_patched_images(patcher_config)

    # Wait for a DFU device to connect
    print('Awaiting DFU device...')
    with acquire_device_with_timeout(DeviceMode.DFU, timeout=100):
        print(f'Got DFU device')

    exploit_and_upload_image(image_types_to_paths[ImageType.iBSS])

    # Send iBEC
    with acquire_device(DeviceMode.Recovery) as recovery_device:
        #recovery_device.upload_data(Path("/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/all_flash/all_flash.n90ap.production/applelogo-640x960.s5l8930x.img3").read_bytes())
        recovery_device.upload_data(image_types_to_paths[ImageType.AppleLogo].read_bytes())
        if True:
            print("Writing setpicture command")
            recovery_device.handle.ctrl_transfer(0x40, 0, data_or_wLength="setpicture".encode() + b'\x00', timeout=30000)
            print("Wrote setpicture command!")
            print("Writing bgcolor...")
            #recovery_device.handle.ctrl_transfer(0x40, 0, data_or_wLength="bgcolor 130 150 220".encode() + b'\x00', timeout=30000)
            recovery_device.handle.ctrl_transfer(0x40, 0, data_or_wLength="bgcolor 255 255 0".encode() + b'\x00', timeout=30000)
            print("Wrote bgcolor!")

        return
        recovery_device.upload_data(image_types_to_paths[ImageType.iBEC].read_bytes())
        print(f'Sent iBEC!')
        time.sleep(3)

        # TODO: Add assert?
        print("Writing go command")
        recovery_device.handle.ctrl_transfer(0x40, 0, data_or_wLength="go".encode() + b'\x00', timeout=30000)
        print("Wrote go command!")


if __name__ == '__main__':
    main()
