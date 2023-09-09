import os
import subprocess
from collections.abc import Collection
from enum import Enum
from pathlib import Path
from typing import Any
from typing import Iterator
from typing import Mapping
from typing import Set
from typing import TypeVar

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


def hexdump(src: bytes) -> None:
    length = 16
    sep = "."
    filter = "".join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
    lines = []
    for c in range(0, len(src), length):
        chars = src[c : c + length]
        hex_ = ""
        for word in range(0, len(chars), 4):
            for j in range(0, 4):
                hex_ += f"{chars[word + j]:02x}"
            hex_ += " "

        printable = "".join(["{}".format((x <= 127 and filter[x]) or sep) for x in chars])
        lines.append(f"{c:08x}: {hex_}  {printable}")
    for line in lines:
        print(line)


def chunks(lst: Collection[Any], n: int) -> Iterator[Collection[Any]]:
    """Yield successive n-sized chunks from lst"""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]
