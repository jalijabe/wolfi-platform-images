"""Extraction tests for the Mermaid lint (rendering itself runs in `task lint:mermaid`)."""

from __future__ import annotations

import pytest

from imagefactory.mermaidlint import extract_blocks

DOC = """# Title
```mermaid
flowchart TB
  A --> B
```
text
````mermaid
sequenceDiagram
  A->>B: hi
````
```python
print("not mermaid")
```
"""


def test_extracts_each_mermaid_block_with_its_line() -> None:
    blocks = extract_blocks("doc.md", DOC)
    assert [(b.line, b.source.splitlines()[0]) for b in blocks] == [
        (2, "flowchart TB"),
        (7, "sequenceDiagram"),
    ]


def test_ignores_other_languages() -> None:
    assert extract_blocks("x.md", "```python\nx = 1\n```\n") == []


def test_unterminated_block_is_an_error() -> None:
    with pytest.raises(ValueError, match="unterminated"):
        extract_blocks("x.md", "```mermaid\nflowchart TB\n")
