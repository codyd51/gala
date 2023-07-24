import io
import os
import selectors
import subprocess
import sys
from collections.abc import Collection
from enum import Enum
from pathlib import Path
from typing import TypeVar, Mapping, Set, Iterator, Any

from more_itertools import all_equal

_EnumType = TypeVar("_EnumType", bound=Enum)
_MapValueType = TypeVar("_MapValueType")


class TotalEnumMapping(Mapping[_EnumType, _MapValueType]):
    """Helper to ensure that an Enum -> Any map is total over the Enum.
    This helps prevent bugs when an enum map isn't updated after enum values are added.
    """

    def __init__(
            self, enum_mapping: dict[_EnumType, _MapValueType], omitted_variants: list[_EnumType] | None = None
    ) -> None:
        # Sanity check - ensure all keys in the enum are the same type
        keys = list(enum_mapping.keys())
        key_types = map(type, keys)
        if not all_equal(key_types):
            raise TypeError(
                f"TotalEnumMapping is only for maps over a single enum type, found multiple types: {set(key_types)}"
            )

        # Ensure the mapping is total over the Enum, excluding whatever was explicitly ignored
        all_enum_values: Set[_EnumType] = set(type(keys[0]))
        if set(keys) != all_enum_values - set(omitted_variants or []):
            raise ValueError(
                "Config error! Map does not define the following keys defined in the enum: "
                f"{all_enum_values.difference(set(keys))}"
            )

        self.enum_mapping = enum_mapping

    def __getitem__(self, key: _EnumType) -> _MapValueType:
        return self.enum_mapping[key]

    def __iter__(self) -> Iterator:
        return self.enum_mapping.__iter__()

    def __len__(self) -> int:
        return len(self.enum_mapping)


def run_and_check(cmd_list: list[str], cwd: Path = None, env_additions: dict[str, str] | None = None) -> None:
    print(" ".join(cmd_list), cwd)
    env = os.environ.copy()
    if env_additions:
        for k, v in env_additions.items():
            env[k] = v

    status = subprocess.run(cmd_list, cwd=cwd.as_posix() if cwd else None, env=env)
    if status.returncode != 0:
        raise RuntimeError(f'Running "{" ".join(cmd_list)}" failed with exit code {status.returncode}')


def run_and_capture_output_and_check(cmd_list: list[str], cwd: Path = None) -> bytes:
    """Beware this will strip ASCII escape codes, so you'll lose colors."""
    # https://gist.github.com/nawatts/e2cdca610463200c12eac2a14efc0bfb
    # Start subprocess
    # bufsize = 1 means output is line buffered
    # universal_newlines = True is required for line buffering
    process = subprocess.Popen(
        cmd_list,
        cwd=cwd.as_posix() if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if return_code := process.wait() != 0:
        raise RuntimeError(f'Running "{" ".join(cmd_list)}" failed with exit code {return_code}')

    return process.stdout.read()


def hexdump(src: bytes) -> None:
    length = 16
    sep = '.'
    filter = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c: c + length]
        hex_ = ' '.join(['{:02x}'.format(x) for x in chars])
        if len(hex_) > 24:
            hex_ = '{} {}'.format(hex_[:24], hex_[24:])
        printable = ''.join(['{}'.format((x <= 127 and filter[x]) or sep) for x in chars])
        lines.append('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(c, hex_, length * 3, printable, length))
    for line in lines:
        print(line)


def chunks(lst: Collection[Any], n: int) -> Iterator[Collection[Any]]:
    """Yield successive n-sized chunks from lst"""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]
