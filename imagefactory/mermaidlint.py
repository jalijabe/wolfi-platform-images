"""Prove every Mermaid block in the repository's Markdown parses.

Extracts each ```mermaid fenced block from Markdown files and renders it with the
pinned mermaid-cli in tools/mermaid (a real parse, not a regex check).

Usage: python -m imagefactory.mermaidlint --root . --mmdc tools/mermaid/node_modules/.bin/mmdc
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


def list_files(root: Path) -> list[str]:
    """Tracked and untracked-but-not-ignored files; a plain walk outside git."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            cwd=root,
            check=True,
            capture_output=True,
        ).stdout
        return sorted({p for p in out.decode("utf-8").split("\0") if p and (root / p).is_file()})
    except (subprocess.CalledProcessError, FileNotFoundError):
        skip = {".git", ".venv", "node_modules", ".build", ".bin"}
        return sorted(
            p.relative_to(root).as_posix()
            for p in root.rglob("*")
            if p.is_file() and not skip & set(p.relative_to(root).parts)
        )


FENCE_OPEN = re.compile(r"^(?P<indent>\s*)(?P<fence>`{3,}|~{3,})\s*mermaid\s*$")


@dataclass(frozen=True)
class Block:
    path: str
    line: int  # 1-based line of the opening fence
    source: str


def extract_blocks(path: str, text: str) -> list[Block]:
    blocks: list[Block] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = FENCE_OPEN.match(lines[i])
        if not m:
            i += 1
            continue
        fence, start = m.group("fence"), i
        body: list[str] = []
        i += 1
        while i < len(lines) and not lines[i].strip().startswith(fence):
            body.append(lines[i])
            i += 1
        if i == len(lines):
            raise ValueError(f"{path}:{start + 1}: unterminated mermaid block")
        blocks.append(Block(path, start + 1, "\n".join(body) + "\n"))
        i += 1
    return blocks


def render(block: Block, mmdc: Path, puppeteer_cfg: Path | None, workdir: Path) -> str | None:
    """Return None on success, else the parser's error message."""
    src = workdir / "diagram.mmd"
    src.write_text(block.source, encoding="utf-8")
    cmd = [str(mmdc), "-q", "-i", str(src), "-o", str(workdir / "diagram.svg")]
    if puppeteer_cfg:
        cmd += ["-p", str(puppeteer_cfg)]
    res = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if res.returncode == 0:
        return None
    lines = [
        ln for ln in (res.stderr + res.stdout).splitlines() if ln.strip() and not ln.startswith("    at ")
    ]
    return "\n".join(lines[:6]) or f"mmdc exited {res.returncode}"


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=Path())
    ap.add_argument("--mmdc", type=Path, required=True)
    ap.add_argument("--puppeteer-config", type=Path)
    args = ap.parse_args(argv)
    root: Path = args.root.resolve()

    blocks: list[Block] = []
    for rel in list_files(root):
        if rel.endswith(".md") and "/node_modules/" not in f"/{rel}":
            blocks += extract_blocks(rel, (root / rel).read_text(encoding="utf-8"))

    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        for b in blocks:
            err = render(b, args.mmdc, args.puppeteer_config, Path(tmp))
            if err:
                failures += 1
                print(f"{b.path}:{b.line}: mermaid block does not parse:\n{err}", file=sys.stderr)
    if failures:
        print(f"lint:mermaid: {failures} of {len(blocks)} block(s) failed", file=sys.stderr)
        return 1
    print(f"lint:mermaid: OK ({len(blocks)} block(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
