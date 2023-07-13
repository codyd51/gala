import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from strongarm.macho import MachoParser, VirtualMemoryPointer
import argparse


def run_and_check(cmd_list: list[str], cwd: Path = None, env_additions: dict[str, str] | None = None) -> None:
    print(" ".join(cmd_list), cwd)
    env = os.environ.copy()
    if env_additions:
        for k, v in env_additions.items():
            env[k] = v

    status = subprocess.run(cmd_list, cwd=cwd.as_posix() if cwd else None, env=env)
    if status.returncode != 0:
        raise RuntimeError(f'Running "{" ".join(cmd_list)}" failed with exit code {status.returncode}')


def dump_text_section(input_file: Path) -> bytes:
    parser = MachoParser(input_file)
    binary = parser.get_armv7_slice()
    text_section = binary.section_with_name("__text", "__TEXT")
    return binary.get_content_from_virtual_address(text_section.address, text_section.size)


@dataclass
class Function:
    name: str
    address: VirtualMemoryPointer


@dataclass
class PatchRegion:
    function: Function
    address: VirtualMemoryPointer
    orig_instructions: list[str]
    patched_instructions: list[str]


def main():
    jailbreak_root = Path("/Users/philliptennen/Documents/Jailbreak")
    output_dir = jailbreak_root / "patched_images" / "iPhone3,1_6.1_10B144"
    output_dir.mkdir(parents=True, exist_ok=True)
    iBSS = jailbreak_root / "ipsw" / "iPhone3,1_6.1_10B144_Restore.ipsw.unzipped" / "Firmware" / "dfu" / "iBSS.n90ap.RELEASE.dfu"
    decrypted_iBSS = output_dir / "iBSS.n90ap.RELEASE.dfu.decrypted"

    iBEC = jailbreak_root / "ipsw" / "iPhone3,1_6.1_10B144_Restore.ipsw.unzipped" / "Firmware" / "dfu" / "iBEC.n90ap.RELEASE.dfu"
    decrypted_iBEC = output_dir / "iBEC.n90ap.RELEASE.dfu.decrypted"

    xpwntool = jailbreak_root / "xpwn" / "build" / "ipsw-patch" / "xpwntool"

    # Decrypt the iBSS and iBEC images
    # (And delete any decrypted image we already produced)
    decrypted_iBSS.unlink(missing_ok=True)
    decrypted_iBEC.unlink(missing_ok=True)
    run_and_check(
        [
            xpwntool.as_posix(),
            iBSS.as_posix(),
            decrypted_iBSS.as_posix(),
            "-k",
            "f7f5fd61ea0792f13ea84126c3afe33944ddc543b62b552e009cbffaf7e34e28",
            "-iv",
            "24af28537e544ebf981ce32708a7e21f",
        ],
    )
    if not decrypted_iBSS.exists():
        raise RuntimeError(f"Expected decrypted iBSS to be produced at {decrypted_iBSS.as_posix()}")
    run_and_check(
        [
            xpwntool.as_posix(),
            iBEC.as_posix(),
            decrypted_iBEC.as_posix(),
            "-k",
            "061695b0ba878657ae195416cff88287f222b50baabb9f72e0c2271db6b58db5",
            "-iv",
            "1168b9ddb4c5df062892810fec574f55",
        ],
    )
    if not decrypted_iBEC.exists():
        raise RuntimeError(f"Expected decrypted iBEC to be produced at {decrypted_iBEC.as_posix()}")

    image3_load_validate_signature = Function(
        name="image3_load_validate_signature",
        address=VirtualMemoryPointer(0x8400568e),
    )
    patches = [
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x84005694),
            # PT: This comment is unverified
            # This test is followed by a `bne`. The taken direction is a "validation failed" path, so we want to stay here.
            orig_instructions=["tst.w r0, #1"],
            patched_instructions=["cmp r0, r0", "nop"],
        ),
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x840056ac),
            # PT: This comment is unverified
            # The branch just preceding this calls a validation function,
            # and the comparison following this branches away to a failure path. We want the validation to always succeed.
            orig_instructions=["cmp r0, #0"],
            patched_instructions=["cmp r0, r0"],
        ),
        # More comparison patches follow
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x8400570e),
            orig_instructions=["cmp r0, #1"],
            patched_instructions=["cmp r0, r0"],
        ),
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x84005712),
            # Replace the call to the 'image3_validate_constraints' function with a direct return value
            # This return value is compared to 0x1 just below, so set it upfront
            orig_instructions=["beq 0x84005746"],
            patched_instructions=["movs r0, #0x1"],
        ),
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x84005726),
            orig_instructions=["cmp r0, #0x0"],
            patched_instructions=["cmp r0, r0"],
        ),
        PatchRegion(
            function=image3_load_validate_signature,
            address=VirtualMemoryPointer(0x8400573a),
            orig_instructions=["cmp r0, #1"],
            patched_instructions=["cmp r0, r0"],
        ),
    ]

    main_ibss = Function(
        name="main_ibss",
        address=VirtualMemoryPointer(0x840008c8),
    )
    patches = [
        PatchRegion(
            function=main_ibss,
            address=VirtualMemoryPointer(0x84000940),
            # Just above is a function call, maybe to dfu_parse_ticket?
            # If the call returns zero, we jump back to the 'receive a DFU image' loop, and don't do further
            # processing. We always want to process the image.
            orig_instructions=["cbnz r0, loc_84000964"],
            patched_instructions=["b #0x20"],
        )
    ]
    # PT: I think this is enough patches to get going and load an image...




if __name__ == '__main__':
    main()
