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

    subprocess.run("./compile.sh", shell=True, cwd=payload_folder)
    payload_shellcode = build_folder / f"{payload_name}_shellcode"
    assert payload_shellcode.exists()
    print(f"Produced output shellcode {payload_shellcode.relative_to(payload_folder.parent)}")


def recompile_payloads():
    root = Path(__file__).parent
    build(root / "payload_stage1")
    build(root / "payload_stage2")
    build(root / "shellcode_within_ibss")
    build(root / "shellcode_in_asr")
    build(root / "shellcode_within_ibec")
    build(root / "kernelcache_set_debug_enabled")


if __name__ == "__main__":
    recompile_payloads()
