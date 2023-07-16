import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Generator, Optional
from collections.abc import Iterator

import usb
from usb import Device
from usb.backend import libusb1
from usb.backend.libusb1 import _LibUSB

from os_build import OsBuildEnum, ImageType
from patcher import regenerate_patched_images
from recompile_payloads import recompile_payloads
from utils import TotalEnumMapping


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


@contextmanager
def acquire_device(mode: DeviceMode) -> Iterator[Optional[Device]]:
    """Technically doesn't need to be a context manager,
    but helps describe the semantics of how we interact with the device.
    """
    yield usb.core.find(idVendor=0x5ac, idProduct=mode.usb_product_id, backend=get_libusb_backend())

    #if not device:
    #    raise RuntimeError(f"Failed to find a {mode.name} device")


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


def main():
    os_build = OsBuildEnum.iPhone3_1_5_0_9A334
    recompile_payloads()
    image_types_to_paths = regenerate_patched_images(os_build)

    jailbreak_folder = Path(__file__).parent / "jailbreak"
    jailbreak_build_folder = jailbreak_folder / "build"
    jailbreak_build_folder.mkdir(exist_ok=True)
    recompile_exploit_runner(jailbreak_folder)
    jailbreak_binary = jailbreak_build_folder / "jailbreak"

    with acquire_device(DeviceMode.DFU) as maybe_dfu_device:
        if _dfu_device := maybe_dfu_device:
            print(f'Running exploit because we detected a DFU-mode device')
            proc: subprocess.CompletedProcess = subprocess.run(jailbreak_binary.as_posix())
            if proc.returncode != 0:
                raise ValueError(f"Jailbreak runner exited with code {proc.returncode}")

            # Send iBSS (in DFU mode)
            ibss_path = image_types_to_paths[ImageType.iBSS]
            print(f'Sending iBSS from {ibss_path.as_posix()}...')

        else:
            print(f'No DFU-mode device detected')

    # Send iBEC
    with acquire_device(DeviceMode.Recovery) as maybe_recovery_device:
        if recovery_device := maybe_recovery_device:
            print(f'Got recovery-mode device {recovery_device}')
            print(type(recovery_device))

            if False:
                step = 20
                while True:
                    for red in range(0, 255, step):
                        for green in range(0, 255, step):
                            for blue in range(0, 255, step):
                                recovery_device.ctrl_transfer(0x40, 0, data_or_wLength=f"bgcolor {red} {green} {blue}".encode() + b'\x00', timeout=30000)

            def send_data(device, data):
                MAX_PACKET_SIZE = 0x4000
                if device.ctrl_transfer(0x41, 0, 0, timeout=1000) != 0:
                    raise ValueError(f'Expected a response of 0')
                index = 0
                while index < len(data):
                    amount = min(len(data) - index, MAX_PACKET_SIZE)
                    assert device.write(0x04, data[index:index + amount], timeout=1000) == amount
                    print(f'sending chunk {index}')
                    #assert device.ctrl_transfer(0x21, 1, i, 0, data[index:index + amount], timeout=5000) == amount
                    index += amount
            #file_path = Path("/Users/philliptennen/Documents/Jailbreak/patched_images/iPhone3,1_4.0_8A293/iBEC.n90ap.RELEASE.dfu.reencrypted")
            #file_path = Path("/Users/philliptennen/Documents/Jailbreak/patched_images/iPhone3,1_4.1_8B117/iBEC.n90ap.RELEASE.dfu.reencrypted")
            #file_path = Path("/Users/philliptennen/Documents/Jailbreak/patched_images/iPhone3,1_4.1_8B117/iBEC.n90ap.RELEASE.dfu.reencrypted")
            file_path = Path("/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_5.0_9A334_Restore.ipsw.unzipped/Firmware/dfu/iBEC.n90ap.RELEASE.dfu")

            file_data = file_path.read_bytes()
            send_data(recovery_device, file_data)
            print(f'Sent iBEC!')
            time.sleep(3)

            # TODO: Add assert?
            print("Writing go command")
            recovery_device.ctrl_transfer(0x40, 0, data_or_wLength="go".encode() + b'\x00', timeout=30000)
            print("Wrote go command!")

        else:
            raise RuntimeError(f'Expected to find a Recovery-mode device')


if __name__ == '__main__':
    main()
