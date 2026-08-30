"""Build an asciinema v2 .cast recording from a captured ANSI output.

Usage: venv/bin/python tools/make_cast.py <output.ansi> <demo.cast> [command]

The cast types the command (e.g. `tf-eu-guard scan examples/vulnerable-aws/ --output dev`)
with per-keystroke timing, then streams the captured report output in realistic chunks.
Play with `asciinema play <demo.cast>` or embed via https://asciinema.org.
"""
import json
import sys
import time
from pathlib import Path


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    command = sys.argv[3] if len(sys.argv) > 3 else "tf-eu-guard scan examples/vulnerable-aws/ --output dev"
    ansi = src.read_text()

    events: list[list] = []  # [elapsed, "o", data]
    t = 0.0

    def emit(data: str, dt: float) -> None:
        nonlocal t
        t += dt
        events.append([round(t, 6), "o", data])

    # Prompt + typed command (fast human typing, jittered)
    emit("$ ", 0.3)
    for ch in command:
        emit(ch, 0.03 + (0.05 if ch == " " else 0.0) + (hash(ch) % 7) / 200)
    emit("\r\n", 0.2)

    # Report output: stream line groups, faster than reading speed
    lines = ansi.splitlines(keepends=True)
    chunk: list[str] = []
    for i, line in enumerate(lines):
        chunk.append(line)
        if len(chunk) >= 6 or i == len(lines) - 1:
            emit("".join(chunk), 0.05 + len(chunk) * 0.01)
            chunk = []

    emit("\r\n", 0.1)
    emit("$ ", 0.5)

    header = {
        "version": 2,
        "width": 110,
        "height": 30,
        "timestamp": int(time.time()),
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    }
    with dst.open("w", encoding="utf-8") as f:
        f.write(json.dumps(header) + "\n")
        for ev in events:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    print(f"wrote {dst} ({len(events)} events, {t:.1f}s)")


if __name__ == "__main__":
    main()
