import subprocess
from pathlib import Path

import usb
from usb.backend import libusb1
from usb.backend.libusb1 import _LibUSB

from recompile_payloads import recompile_payloads


def get_libusb_backend() -> _LibUSB:
    libusb_path = "/opt/homebrew/Cellar/libusb/1.0.26/lib/libusb-1.0.dylib"
    backend = libusb1.get_backend(find_library=lambda x: libusb_path)
    print(type(backend))
    if not backend:
        raise RuntimeError(f"Failed to find libusb backend at {libusb_path}")
    return backend


def dump_usb_devices():
    for dev in usb.core.find(find_all=True, backend=get_libusb_backend()):
        print(dev)


def main():
    recompile_payloads()

    jailbreak_folder = Path(__file__).parent / "jailbreak"
    jailbreak_build_folder = jailbreak_folder / "build"
    jailbreak_build_folder.mkdir(exist_ok=True)

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
    jailbreak_binary = jailbreak_build_folder / "jailbreak"
    proc: subprocess.CompletedProcess = subprocess.run(jailbreak_binary.as_posix())
    if proc.returncode != 0:
        raise ValueError(f"Jailbreak runner exited with code {proc.returncode}")


if __name__ == '__main__':
    main()
