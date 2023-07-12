import os
import subprocess
from pathlib import Path


def build(payload_folder: Path):
    payload_name = payload_folder.name
    print(f"Compiling payload: {payload_name}...")

    build_folder = payload_folder / "build"
    # Delete the contents of build/
    for f in build_folder.iterdir():
        print(f'Deleting build output {f.relative_to(payload_folder.parent)}')
        os.remove(f.as_posix())

    subprocess.run("./compile.sh", shell=True, cwd=payload_folder)
    payload_shellcode = build_folder / f"{payload_name}_shellcode"
    assert payload_shellcode.exists()
    print(f'Produced output shellcode {payload_shellcode.relative_to(payload_folder.parent)}')


if __name__ == '__main__':
    root = Path(__file__).parent
    build(root / "payload_stage1")
    build(root / "payload_stage2")

    # dump_text_section_to_file
