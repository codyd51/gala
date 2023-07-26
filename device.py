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

from os_build import DeviceModel
from utils import TotalEnumMapping, chunks


def _get_libusb_backend() -> _LibUSB:
    libusb_path = "/opt/homebrew/Cellar/libusb/1.0.26/lib/libusb-1.0.dylib"
    backend = libusb1.get_backend(find_library=lambda x: libusb_path)
    if not backend:
        raise RuntimeError(f"Failed to find libusb backend at {libusb_path}")
    return backend


def dump_usb_devices():
    for dev in usb.core.find(find_all=True, backend=_get_libusb_backend()):
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

    @property
    def model(self) -> DeviceModel:
        # TODO(PT): Figure this out dynamically
        return DeviceModel.iPhone3_1

    def upload_file(self, path: Path) -> None:
        print(f'Uploading {path.name} to connected {self.mode.name} Mode device...')
        data = path.read_bytes()
        match self.mode:
            case DeviceMode.DFU:
                self.dfu_upload_data(data)
                # For DFU devices, immediately ask the device to validate the file.
                self.dfu_notify_upload_finished()
            case DeviceMode.Recovery:
                self.recovery_upload_data(data)
                # For Recovery Mode devices, the logic to notify the device that the upload is ready will differ
                # depending on what the image is for, so allow them to deal with it.

    def send_command(self, command: str) -> None:
        if self.mode != DeviceMode.Recovery:
            raise ValueError(f"Sending commands is only supported in Recovery Mode")
        self.handle.ctrl_transfer(0x40, 0, data_or_wLength=command.encode() + b'\x00', timeout=30000)

    def dfu_upload_data(self, data: bytes, timeout_ms: int = 3000) -> None:
        max_dfu_upload_chunk_size = 0x800
        for chunk in chunks(data, max_dfu_upload_chunk_size):
            print(f'Uploading chunk of {len(chunk)} bytes...')
            sent_bytes_count = self.handle.ctrl_transfer(0x21, 1, 0, 0, chunk, timeout_ms)
            if sent_bytes_count != len(chunk):
                raise ValueError(f'Expected to transfer {len(chunk)} bytes, but only managed to send {sent_bytes_count} bytes')

    def dfu_notify_upload_finished(self) -> None:
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

    def recovery_upload_data(self, file_data: bytes) -> None:
        max_recovery_upload_chunk_size = 0x4000
        if self.handle.ctrl_transfer(0x41, 0, 0, timeout=1000) != 0:
            raise ValueError(f'Expected a response of 0')
        for chunk in chunks(file_data, max_recovery_upload_chunk_size):
            print(f'Uploading chunk of {len(chunk)} bytes...')
            wrote_bytes = self.handle.write(0x04, chunk, timeout=1000)
            if wrote_bytes != len(chunk):
                raise RuntimeError(f"Expected to write {len(chunk)} bytes, but only wrote {wrote_bytes}")


@contextmanager
def maybe_acquire_device(mode: DeviceMode) -> Iterator[Optional[Device]]:
    """Technically doesn't need to be a context manager,
    but helps describe the semantics of how we interact with the device.
    """
    device_handle = usb.core.find(idVendor=0x5ac, idProduct=mode.usb_product_id, backend=_get_libusb_backend())
    if not device_handle:
        yield None
    else:
        yield Device(
            handle=device_handle,
            mode=mode
        )
        usb.util.dispose_resources(device_handle)


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
