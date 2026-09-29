#!/usr/bin/env python3
"""Copy public ingestion instructions into one explicitly selected skill root."""

import argparse
import shutil
import sys
from pathlib import Path


SKILLS = Path(__file__).resolve().parents[1] / "skills"


def files(root):
    """Compare exact instruction trees; reject links and unexpected payloads."""
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"refusing symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file() or path.suffix not in {".md", ".yaml", ".json"}:
            raise ValueError(f"unexpected skill file: {path}")
        result[path.relative_to(root).as_posix()] = path.read_bytes()
    if "SKILL.md" not in result:
        raise ValueError(f"missing SKILL.md: {root}")
    return result


def install(destination, names, dry_run=False, source=SKILLS):
    available = {p.name for p in source.glob("hc-ingest*") if p.is_dir()}
    selected = set(names) if names else available
    if not selected or selected - available:
        raise ValueError("unknown ingestion skill; use --list")
    selected.add("hc-ingest")
    destination = destination.expanduser().absolute()
    if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
        raise ValueError(f"destination must be a directory, not a symlink: {destination}")

    plans = []
    # Check every selected destination before creating any directories.
    for name in sorted(selected):
        origin, target = source / name, destination / name
        if origin.is_symlink():
            raise ValueError(f"refusing source symlink: {origin}")
        expected = files(origin)
        if target.is_symlink():
            raise ValueError(f"refusing installed symlink: {target}")
        if target.exists():
            if not target.is_dir() or files(target) != expected:
                raise ValueError(f"existing skill differs; review it before replacing: {target}")
            plans.append((name, "unchanged"))
        else:
            plans.append((name, "install"))

    if not dry_run:
        for name, action in plans:
            if action == "unchanged":
                continue
            destination.mkdir(parents=True, exist_ok=True)
            target = destination / name
            # Exclusive creation prevents overwriting a concurrently installed skill.
            target.mkdir()
            try:
                shutil.copytree(source / name, target, dirs_exist_ok=True)
                if files(target) != files(source / name):
                    raise ValueError(f"readback differs: {target}")
            except Exception:
                shutil.rmtree(target)
                raise
    return plans


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", type=Path, help="one harness's skill directory")
    parser.add_argument("--skill", action="append", default=[], help="repeat to select skills; default all")
    parser.add_argument("--dry-run", action="store_true", help="inspect without creating files")
    parser.add_argument("--list", action="store_true", help="list available ingestion skills")
    args = parser.parse_args()
    if args.list:
        print("\n".join(sorted(p.name for p in SKILLS.glob("hc-ingest*") if p.is_dir())))
        return
    if args.dest is None:
        parser.error("--dest is required; no default harness is modified")
    try:
        plans = install(args.dest, args.skill, args.dry_run)
    except (ValueError, OSError) as error:
        parser.exit(1, f"{error}\n")
    for name, action in plans:
        print(f"{'would ' if args.dry_run else ''}{action}: {name}")
    print("Instructions only. No account connected, records imported, or service started.")


if __name__ == "__main__":
    main()
