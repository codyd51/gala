import logging
import os
import subprocess
from pathlib import Path

from configuration import GALA_ROOT

_logger = logging.getLogger(__file__)


def build_shellcode_program(payload_folder: Path):
    payload_name = payload_folder.name
    _logger.info(f"Compiling payload: {payload_name}...")

    build_folder = payload_folder / "build"
    build_folder.mkdir(exist_ok=True)
    # Delete the contents of build/
    for f in build_folder.iterdir():
        _logger.info(f"Deleting build output {f.relative_to(payload_folder.parent)}")
        os.remove(f.as_posix())

    # Use a Makefile if possible
    makefile_path = payload_folder / "Makefile"
    if makefile_path.exists():
        subprocess.run("make", shell=True, cwd=payload_folder)
    else:
        subprocess.run("./compile.sh", shell=True, cwd=payload_folder)

    payload_shellcode = build_folder / f"{payload_name}_shellcode"
    if not payload_shellcode.exists():
        raise RuntimeError(f"Expected packed shellcode to be produced at {payload_shellcode.as_posix()}")
    _logger.info(f"Produced output shellcode {payload_shellcode.relative_to(payload_folder.parent)}")


def build_shellcode_programs() -> None:
    shellcode_programs_root = GALA_ROOT / "shellcode_programs"
    for maybe_program_dir in shellcode_programs_root.iterdir():
        if not maybe_program_dir.is_dir():
            continue
        build_shellcode_program(maybe_program_dir)


def build_ramdisk_program(program_folder: Path) -> Path:
    program_name = program_folder.name
    print(f"Compiling program: {program_name}...")

    build_folder = program_folder / "build"
    build_folder.mkdir(exist_ok=True)
    # Delete the contents of build/
    for f in build_folder.iterdir():
        print(f"Deleting build output {f.relative_to(program_folder.parent)}")
        os.remove(f.as_posix())

    subprocess.run("./compile.sh", shell=True, cwd=program_folder)
    compiled_program = build_folder / program_name
    if not compiled_program.exists():
        raise ValueError(f"Expected to produce compiled program at {compiled_program}")
    return compiled_program


def build_ramdisk_programs() -> None:
    ramdisk_programs_root = GALA_ROOT / "ramdisk_programs"
    for maybe_program_dir in ramdisk_programs_root.iterdir():
        if not maybe_program_dir.is_dir():
            continue
        build_ramdisk_program(maybe_program_dir)


def recompile_payloads():
    build_shellcode_programs()
    build_ramdisk_programs()


if __name__ == "__main__":
    recompile_payloads()
