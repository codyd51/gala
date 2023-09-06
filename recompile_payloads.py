import os
import subprocess
import tempfile
from pathlib import Path

from strongarm.macho import MachoAnalyzer, VirtualMemoryPointer, MachoParser


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


def build_securerom_payload(payload_folder: Path) -> Path:
    payload_name = payload_folder.name
    print(f"Compiling Rust payload: {payload_name}...")
    subprocess.run("cargo build --target armv7-apple-ios", cwd=payload_folder, shell=True)
    return payload_folder
    if False:
        output_archive_path = payload_folder / "target" / "armv7-apple-ios" / "debug" / "libsecurerom_payload.a"
        with tempfile.TemporaryDirectory() as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            subprocess.run(f"ar xv {output_archive_path.as_posix()}", cwd=temp_dir, shell=True)
            payload_object_file = temp_dir / "securerom_payload-fac652acc7cf1e46.2x8uhrdatlm0r72b.rcgu.o"
            parser = MachoParser(payload_object_file)
            binary = parser.get_armv7_slice()
            # PT: There's just one unnamed segment, so we can't use segment_with_name()
            text_section = binary.sections[0]
            if text_section.name != "__text" or text_section.segment_name != "__TEXT":
                raise ValueError(f'Expected the first section to be __text,__TEXT')

            # Sanity check: ensure _await_image is the first symbol, which is important as we'll map the file and jump directly into it
            analyzer = MachoAnalyzer.get_analyzer(binary)
            if analyzer.exported_symbol_pointers_to_names[VirtualMemoryPointer(0x0)] != '_await_image':
                raise ValueError("Expected an exported symbol named _await_image at 0x0")

            payload_contents = binary.get_contents_from_address(text_section.offset, text_section.size, is_virtual=False)
            output_path = payload_folder / "stripped_rust_payload"
            output_path.write_bytes(payload_contents)
        return output_path


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

    securerom_payload_path = build_securerom_payload(root / "securerom_payload")
    print(securerom_payload_path)

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
