#!/usr/bin/env python3
"""Require the complete source license texts in every release archive."""
import argparse
from pathlib import Path, PurePosixPath
import tarfile

ROOT = Path(__file__).resolve().parent.parent
NAMES = ("LICENSE-MIT", "LICENSE-APACHE")


def check(archive):
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        prefixes = set()
        for name in NAMES:
            matches = [member for member in members if PurePosixPath(member.name).name == name]
            if len(matches) != 1:
                raise ValueError(f"{archive}: require exactly one {name}")
            member = matches[0]
            parts = PurePosixPath(member.name).parts
            if not member.isfile() or len(parts) != 2 or not parts[0].startswith("sakimori-"):
                raise ValueError(f"{archive}: {name} must be a regular file in the release root")
            prefixes.add(parts[0])
            expected = (ROOT / name).read_bytes()
            if member.size != len(expected) or tar.extractfile(member).read() != expected:
                raise ValueError(f"{archive}: {name} text differs from the complete source license")
        if len(prefixes) != 1:
            raise ValueError(f"{archive}: license files must share the release root")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()
    for filename in args.archives:
        check(filename)
        print(f"{filename.name}: both complete license texts verified")
