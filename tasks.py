import shutil
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from typing import Iterator

import requests
from invoke import task
from invoke.context import Context

from gala.configuration import DEPENDENCIES_ROOT, SDKS_ROOT
from gala.configuration import DEPENDENCY_PATCHES_ROOT
from gala.configuration import GALA_ROOT
from gala.configuration import UNZIPPED_IPSWS_ROOT
from gala.configuration import ZIPPED_IPSWS_ROOT
from gala.os_build import OsBuildEnum
from gala.utils import mount_dmg


@task
def autoformat(ctx: Context) -> None:
    path = GALA_ROOT
    print("\U000027A1 Autoformatting code...")
    ctx.run(
        f"autoflake -r --in-place --remove-all-unused-imports {path}",
        pty=True,
        echo=True,
    )
    ctx.run(f"isort {path}", pty=True, echo=True)
    ctx.run(f"black {path}", pty=True, echo=True)
    print("Finished autoformatting.\U0001F389")


@task
def autoformat_lint(ctx: Context) -> None:
    path = GALA_ROOT
    ctx.run(f"mypy {path}", pty=True, echo=True)
    print("\U000027A1Running linters and code quality checks...")
    ctx.run(f"autoflake -cr --remove-all-unused-imports {path} --quiet", hide="out", echo=True)
    ctx.run(f"isort --check --diff {path}", pty=True, echo=True)
    ctx.run(f"mypy {path}", pty=True, echo=True)
    ctx.run(f"flake8 {path}", pty=True, echo=True)
    ctx.run(f"black --check {path}", pty=True, echo=True)
    print("Finished running code quality checks! \U0001F389")


def embolden(s: str) -> str:
    """Surround with ASCII control codes to request that the text be rendered in bold"""
    return f"\033[1;37m{s}\033[0m"


@dataclass
class DependencyInfo:
    repo_url: str
    # To prevent conflicts and to keep things predictable, the user must declare the name of the directory that the
    # tool should be cloned to
    cloned_directory_name: str
    git_revision: str
    # These will be executed from within the cloned directory
    compile_commands: list[str]

    # Git patch files that should be applied to the cloned tool before we attempt to compile it
    patch_files: list[Path] | None = None


def _ensure_pre_dependencies_are_installed() -> None:
    # Ensure all the pre-dependencies we need are already installed...
    pre_dependencies = [
        "git",
        "irecovery",
        "openssl",
        "rustup",
        "dpkg-deb",
    ]
    print(f"Verifying that {embolden(str(len(pre_dependencies)))} pre-dependencies are installed...")

    for pre_dependency in pre_dependencies:
        print(f'Checking for pre-dependency "{embolden(pre_dependency)}"')
        if shutil.which(pre_dependency) is None:
            print(
                f"{embolden('Toolchain setup failed: ')} pre-dependency "
                f'"{embolden(pre_dependency)}" not found. Is it installed and in $PATH?'
            )
            sys.exit(1)

    print(embolden("Verified pre-dependencies."))
    print()


def _install_required_rust_toolchain(ctx: Context) -> None:
    print(f"Installing the Rust toolchain that supports {embolden('armv7-apple-ios')}...")
    ctx.run("rustup toolchain add nightly-2020-01-01 --profile minimal", pty=True, echo=True)
    print(f"Installed the Rust toolchain that supports {embolden('armv7-apple-ios')}...")
    print()


def _clone_and_build_dependencies(ctx: Context) -> None:
    DEPENDENCIES_ROOT.mkdir(exist_ok=True)

    dependencies = [
        DependencyInfo(
            repo_url="https://github.com/planetbeing/xpwn",
            cloned_directory_name="xpwn",
            git_revision="ac362d4ffe4d0489a26144a1483ebf3b431da899",
            patch_files=[DEPENDENCY_PATCHES_ROOT / "xpwn.patch"],
            compile_commands=[
                # PT: -fcommon is required to build on Ubuntu
                'cmake . -DCMAKE_C_FLAGS="-fcommon"',
                "make",
            ],
        ),
        DependencyInfo(
            repo_url="https://github.com/xerub/xpwn",
            cloned_directory_name="xpwn-xerub",
            git_revision="5b5ce71ea14761a53029ff41367905bc939c098c",
            patch_files=[
                DEPENDENCY_PATCHES_ROOT / "xpwn-xerub.patch",
                DEPENDENCY_PATCHES_ROOT / "xpwn-xerub2.patch",
            ],
            compile_commands=[
                # PT: -fcommon is required to build on Ubuntu
                'cmake . -DCMAKE_C_FLAGS="-fcommon"',
                "make",
            ],
        ),
        DependencyInfo(
            repo_url="https://github.com/libimobiledevice/idevicerestore",
            cloned_directory_name="idevicerestore",
            git_revision="609f7f058487596597e8e742088119fdd46729df",
            patch_files=[
                DEPENDENCY_PATCHES_ROOT / "idevicerestore.patch",
            ],
            compile_commands=[
                "./autogen.sh",
                "make",
            ],
        ),
        DependencyInfo(
            repo_url="https://github.com/kevinburke/sshpass",
            cloned_directory_name="sshpass",
            git_revision="ca7baa670d799b85ff91b4056e0a2bf9772cb2cf",
            compile_commands=[
                "./configure",
                "make",
            ],
        ),
    ]
    print(f"Building {embolden(str(len(dependencies)))} dependencies...")
    for dependency_info in dependencies:
        print(f"Cloning {embolden(dependency_info.repo_url)} to revision {embolden(dependency_info.git_revision)}...")

        with ctx.cd(DEPENDENCIES_ROOT):
            ctx.run(f"git clone {dependency_info.repo_url} {dependency_info.cloned_directory_name}")

        with ctx.cd(DEPENDENCIES_ROOT / dependency_info.cloned_directory_name):
            ctx.run(f"git checkout {dependency_info.git_revision}")

            for patch in dependency_info.patch_files or []:
                # Ensure the patch is valid and can be applied
                print(f"Validating {embolden(patch.relative_to(GALA_ROOT).as_posix())}...")
                ctx.run(f"git apply --check {patch.as_posix()}")
                print(f"Applying {embolden(patch.relative_to(GALA_ROOT).as_posix())}...")
                ctx.run(f"git apply {patch.as_posix()}")

            for command in dependency_info.compile_commands:
                print(f'Running compile command "{embolden(command)}"...')
                ctx.run(command)

        print(f'Successfully built "{embolden(dependency_info.cloned_directory_name)}"...')
    print()
    print(f"Successfully cloned and built {embolden(str(len(dependencies)))} dependencies.")


def _iter_bytes_received_by_chunk_size(chunk_size: int) -> Iterator[int]:
    bytes_received_so_far = 0
    while True:
        yield bytes_received_so_far
        bytes_received_so_far += chunk_size


def _download_file(
    url: str, dest_path: Path, percent_completed_callback: Callable[[float], None] | None = None
) -> None:
    print(f"Downloading {embolden(url)}...")
    chunk_size = 1024 * 8
    with requests.get(url, stream=True) as resp:
        resp.raise_for_status()
        content_length = resp.raw.length_remaining
        with dest_path.open("wb") as dest_file:
            for bytes_received_so_far, chunk in zip(
                _iter_bytes_received_by_chunk_size(chunk_size), resp.iter_content(chunk_size=chunk_size)
            ):
                dest_file.write(chunk)

                if percent_completed_callback:
                    percent_complete = bytes_received_so_far / float(content_length)
                    percent_completed_callback(percent_complete)


def _download_file_and_report_progress(url: str, dest_path: Path) -> None:
    report_completion_at_percentage_interval = 5
    reported_percentages = []
    start_time = time.time()

    def _time_elapsed() -> str:
        return f"{int(time.time() - start_time): <3} seconds"

    def _progress_callback(percent_completed: float) -> None:
        # Scale 0.15 => 15
        percent_completed *= 100
        # Truncate 43.4 -> 40
        boundary = int(percent_completed) - (int(percent_completed) % report_completion_at_percentage_interval)
        if boundary not in reported_percentages:
            reported_percentages.append(boundary)
            print(f'{_time_elapsed()}: {embolden(f"{boundary}%")}...')

    _download_file(url, dest_path, _progress_callback)
    _progress_callback(1)


def _download_and_unzip_ipsw(os_build: OsBuildEnum) -> None:
    ZIPPED_IPSWS_ROOT.mkdir(exist_ok=True)
    downloaded_path = ZIPPED_IPSWS_ROOT / f"{os_build.unescaped_name}.zip"
    _download_file_and_report_progress(os_build.download_url, downloaded_path)
    print("IPSW download complete.")
    print()

    unzipped_path = UNZIPPED_IPSWS_ROOT / os_build.unescaped_name
    print(
        f"Unzipping {embolden(downloaded_path.relative_to(GALA_ROOT).as_posix())}"
        f" to {embolden(unzipped_path.relative_to(GALA_ROOT).as_posix())}..."
    )
    shutil.unpack_archive(downloaded_path.as_posix(), unzipped_path.as_posix())
    print(f"Unzipped IPSW to {embolden(unzipped_path.relative_to(GALA_ROOT).as_posix())}.")


def _download_and_unzip_sdk(ctx: Context, os_build: OsBuildEnum) -> None:
    build_folder = SDKS_ROOT / os_build.unescaped_name
    build_folder.parent.mkdir(parents=True, exist_ok=True)

    # First, ensure the Xcode .dmg is downloaded (which also includes the iOS SDK)
    # The user must download this themselves as Apple requires the user to be authenticated
    xcode_download_path = SDKS_ROOT / os_build.unescaped_name / "xcode_download.dmg"

    sdk_download_info = os_build.sdk_download_info
    sdk_download_name = sdk_download_info.download_name
    sdk_download_url = sdk_download_info.download_url
    if not xcode_download_path.exists():
        print(f'You must download {embolden(sdk_download_name)} from Apple.')
        print(f'Save it to {embolden(xcode_download_path.as_posix())}.')
        print(f'Download from Apple here: {embolden(sdk_download_url)}.')
        sys.exit(0)

    print(f"Mounting {embolden(xcode_download_path.as_posix())}...")
    with mount_dmg(xcode_download_path) as mount_point:
        print(f'Mounted to {embolden(mount_point.as_posix())}.')
        sdk_package_path = mount_point / sdk_download_info.interior_sdk_package_path
        if not sdk_package_path.exists():
            raise RuntimeError(f"Expected to find an SDK package at {sdk_package_path}")

        # Unpack and save the SDK
        with tempfile.TemporaryDirectory() as temp_dir_raw:
            temp_dir = Path(temp_dir_raw)
            print(f'Unpacking SDK package at {embolden(sdk_package_path.as_posix())}...')
            ctx.run(f"xar -x -f {sdk_package_path} -C {temp_dir.as_posix()}")
            sdk_payload_zip_path = temp_dir / "Payload"
            if not sdk_payload_zip_path.exists():
                raise RuntimeError(f"Expected to find {sdk_payload_zip_path.as_posix()}")

            # Unzip the Payload
            # First, extract the gzip archive. Then, extract the cpio archive to a filesystem node
            with ctx.cd(temp_dir):
                print(f'Unpacking SDK at {embolden(sdk_payload_zip_path.as_posix())}...')
                ctx.run(f"gzcat {sdk_payload_zip_path.as_posix()} | cpio -id")

            sdk_path = temp_dir / sdk_download_info.sdk_path_within_sdk_package
            if not sdk_path.exists():
                raise RuntimeError(f"Expected to find {sdk_path.as_posix()}")

            # Finally, copy the SDK to the gala working directory
            dest_sdk_path = build_folder / sdk_path.name
            print(f'Relocating SDK to {embolden(dest_sdk_path.relative_to(GALA_ROOT).as_posix())}...')
            # PT: This throws some errors due to wonky symlinks in the SDK, but mostly copies fine.
            try:
                shutil.copytree(sdk_path.as_posix(), dest_sdk_path)
            except shutil.Error:
                pass

    print(f'Successfully extracted SDK for {embolden(os_build.unescaped_name)} at {embolden(dest_sdk_path.relative_to(GALA_ROOT))}.')


@task
def setup_toolchain(ctx: Context) -> None:
    print(embolden("Setting up gala toolchain..."))

    _ensure_pre_dependencies_are_installed()
    _install_required_rust_toolchain(ctx)
    _clone_and_build_dependencies(ctx)
    _download_and_unzip_ipsw(OsBuildEnum.iPhone3_1_4_0_8A293)
    _download_and_unzip_sdk(ctx, OsBuildEnum.iPhone3_1_4_0_8A293)


@task
def launch_gui(ctx: Context) -> None:
    with ctx.cd(GALA_ROOT / "runner_app"):
        # ctx.run("xcodebuild build")
        ctx.run(
            "/Users/philliptennen/Library/Developer/Xcode/DerivedData/Gala_Runner-hcnfjxscvipvrwgekpiwczqhxkfu/Build/Products/Debug/Gala\ Runner.app/Contents/MacOS/Gala\ Runner"
        )
