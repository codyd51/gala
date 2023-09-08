import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Optional

import usb
import usb.core
from usb.backend import libusb1
from usb.backend.libusb1 import _LibUSB

from gala.os_build import DeviceModel
from gala.utils import TotalEnumMapping, chunks


class NoDfuDeviceFoundError(Exception):
    """We expected to find a connected DFU device, but none was found."""


class NoRecoveryDeviceFoundError(Exception):
    """We expected to find a connected Recovery device, but none was found."""


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
        return TotalEnumMapping(
            {
                DeviceMode.DFU: 0x1227,
                DeviceMode.Recovery: 0x1281,
            }
        )[self]


@dataclass
class Device:
    handle: usb.core.Device
    mode: DeviceMode

    @property
    def model(self) -> DeviceModel:
        # TODO(PT): Figure this out dynamically
        return DeviceModel.iPhone3_1

    def upload_file(self, path: Path) -> None:
        print(f"Uploading {path.name} to connected {self.mode.name} Mode device...")
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
        self.handle.ctrl_transfer(0x40, 0, data_or_wLength=command.encode() + b"\x00", timeout=30000)

    def dfu_upload_data(self, data: bytes, timeout_ms: int = 3000) -> None:
        max_dfu_upload_chunk_size = 0x800
        sent_bytes_counter = 0
        for chunk in chunks(data, max_dfu_upload_chunk_size):
            percent_complete = int((sent_bytes_counter / len(data)) * 100)
            print(f"Uploading chunk of {len(chunk)} bytes ({percent_complete}%)...")
            sent_bytes_count = self.handle.ctrl_transfer(0x21, 1, 0, 0, chunk, timeout_ms)
            if sent_bytes_count != len(chunk):
                raise ValueError(
                    f"Expected to transfer {len(chunk)} bytes, but only managed to send {sent_bytes_count} bytes"
                )
            sent_bytes_counter += len(chunk)

    def dfu_notify_upload_finished(self) -> None:
        #  Ref: https://archive.conference.hitb.org/hitbsecconf2013kul/materials/D2T1%20-%20Joshua%20'p0sixninja'%20Hill%20-%20SHAttered%20Dreams.pdf
        # "Image validation starts whenever the global “file received” variable has been set."
        # "This can be caused by sending 1 empty “Send Data” packet, and 3 “Get Status” packets followed by a USB reset."
        print(f"Informing the DFU device that the upload has finished...")
        self.handle.ctrl_transfer(0x21, 1, 0, 0, 0, timeout=100)
        # Send a 'Get Status' three times
        for _ in range(3):
            out = bytearray(6)
            self.handle.ctrl_transfer(0xA1, 3, 0, 0, out, timeout=100)

        try:
            self.handle.reset()
        except usb.core.USBError:
            # Sometimes this throws an error, but the image load starts anyway
            pass

    def recovery_upload_data(self, file_data: bytes) -> None:
        max_recovery_upload_chunk_size = 0x4000
        try:
            if self.handle.ctrl_transfer(0x41, 0, 0, timeout=1000) != 0:
                raise ValueError(f"Expected a response of 0")
        except Exception as e:
            print(f"Skipping exception {e}")
        sent_bytes_counter = 0
        for chunk in chunks(file_data, max_recovery_upload_chunk_size):
            percent_complete = int((sent_bytes_counter / len(file_data)) * 100)
            print(f"Uploading chunk of {len(chunk)} bytes ({percent_complete}%)...")
            wrote_bytes = self.handle.write(0x04, chunk, timeout=1000)
            if wrote_bytes != len(chunk):
                raise RuntimeError(f"Expected to write {len(chunk)} bytes, but only wrote {wrote_bytes}")
            sent_bytes_counter += wrote_bytes


@contextmanager
def maybe_acquire_device(mode: DeviceMode) -> Iterator[Optional[Device]]:
    """Technically doesn't need to be a context manager,
    but helps describe the semantics of how we interact with the device.
    """
    device_handle = usb.core.find(idVendor=0x5AC, idProduct=mode.usb_product_id, backend=_get_libusb_backend())
    if not device_handle:
        yield None
    else:
        device_handle.set_configuration()
        yield Device(handle=device_handle, mode=mode)
        usb.util.dispose_resources(device_handle)


@contextmanager
def acquire_device(mode: DeviceMode) -> Iterator[Device]:
    with maybe_acquire_device(mode) as maybe_device:
        if not maybe_device:
            # Use an exception class corresponding to the requested device type
            exception_type = TotalEnumMapping(
                {
                    DeviceMode.DFU: NoDfuDeviceFoundError,
                    DeviceMode.Recovery: NoRecoveryDeviceFoundError,
                }
            )[mode]
            raise exception_type(f"Unable to find a {mode.name} Mode device")
        yield maybe_device


@contextmanager
def acquire_device_with_timeout(mode: DeviceMode, timeout: int = 10) -> Iterator[Device]:
    start = time.time()
    while (now := time.time()) < start + timeout:
        with maybe_acquire_device(mode) as maybe_device:
            if maybe_device:
                yield maybe_device
                return
        print(f"{int(now - start)}: Waiting for {mode.name} Mode device to appear...")
        time.sleep(1)
    raise NoDfuDeviceFoundError(f"No {mode.name} Mode device appeared after {timeout} seconds")
