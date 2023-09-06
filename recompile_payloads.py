import os
import subprocess
from pathlib import Path


def build(payload_folder: Path):
    payload_name = payload_folder.name
    print(f"Compiling payload: {payload_name}...")

    build_folder = payload_folder / "build"
    build_folder.mkdir(exist_ok=True)
    # Delete the contents of build/
    for f in build_folder.iterdir():
        print(f"Deleting build output {f.relative_to(payload_folder.parent)}")
        os.remove(f.as_posix())

    # Use a Makefile if possible
    makefile_path = payload_folder / "Makefile"
    if makefile_path.exists():
        subprocess.run("make", shell=True, cwd=payload_folder)
    else:
        subprocess.run("./compile.sh", shell=True, cwd=payload_folder)

    payload_shellcode = build_folder / f"{payload_name}_shellcode"
    assert payload_shellcode.exists()
    print(f"Produced output shellcode {payload_shellcode.relative_to(payload_folder.parent)}")


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
        raise ValueError(f'Expected to produce compiled program at {compiled_program}')
    return compiled_program


def recompile_payloads():
    root = Path(__file__).parent
    build(root / "payload_stage1")
    build(root / "payload_stage2")
    build(root / "shellcode_within_ibss")
    build(root / "shellcode_in_asr")
    build(root / "shellcode_within_ibec")
    build(root / "shellcode_within_kernelcache")
    build(root / "kernelcache_set_debug_enabled")
    build(root / "shellcode_in_mediakit")
    build_ramdisk_program(root / "umount")
    build_ramdisk_program(root / "asr_wrapper")


if __name__ == "__main__":
    recompile_payloads()
