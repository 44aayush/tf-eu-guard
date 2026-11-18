"""Subcommand dispatcher for commands that bypass the scan parser."""

import json
import sys
from collections.abc import Callable
from pathlib import Path

from tf_eu_guard.baseline import entry_key, read_entries
from tf_eu_guard.cli.errors import handle_scan_error
from tf_eu_guard.cli.pipeline import default_registry_dir
from tf_eu_guard.constants import EXIT_FINDINGS, EXIT_INVALID_INPUT, EXIT_OK
from tf_eu_guard.mapping.loader import (
    load_overlay_file,
    load_registry,
    overlay_files_in,
    validate_all,
)


def _explain(argv: list[str], registry_path: Path | None) -> int:
    """Print the registry entry for one Checkov check ID."""
    if len(argv) != 1:
        print("usage: tf-eu-guard explain CHECK_ID", file=sys.stderr)
        return EXIT_INVALID_INPUT
    registry = load_registry(registry_path or default_registry_dir())
    check_id = argv[0].upper()
    mapping = registry.get(check_id)
    if mapping is None:
        print(f"{argv[0]} is not in the registry", file=sys.stderr)
        return EXIT_INVALID_INPUT
    print(f"{mapping.check_id}: {mapping.check_name}")
    print(f"Severity: {mapping.severity}")
    print("Articles:")
    for article in mapping.articles:
        print(f"  {article.framework} {article.article} — {article.title}")
    print(f"Risk: {mapping.risk_explanation.strip()}")
    print(f"Remediation:\n{mapping.remediation.rstrip()}")
    return EXIT_OK


def _registry(argv: list[str], registry_path: Path | None) -> int:
    """``registry validate [DIR ...]``: check overlay dirs, or the bundled registry."""
    if not argv or argv[0] != "validate":
        print("usage: tf-eu-guard registry validate [DIR ...]", file=sys.stderr)
        return EXIT_INVALID_INPUT
    if len(argv) == 1:
        counts = validate_all(registry_path or default_registry_dir())
    else:
        counts = {
            path.name: len(load_overlay_file(path))
            for directory in argv[1:]
            for path in overlay_files_in(Path(directory))
        }
    for name, count in counts.items():
        print(f"{name}: {count} entries")
    print(f"Total: {sum(counts.values())} entries in {len(counts)} files")
    return EXIT_OK


def _diff(argv: list[str], registry_path: Path | None) -> int:
    """``diff OLD.json NEW.json [--json]``: new, fixed and unchanged findings."""
    as_json = "--json" in argv
    files = [a for a in argv if a != "--json"]
    if len(files) != 2:
        print(
            "usage: tf-eu-guard diff OLD.json NEW.json [--json]\n"
            "Compares the active findings of two JSON reports by check, resource and "
            "file (line numbers ignored); suppressed and waived entries are skipped, "
            "baselined ones count as present. Exit 1 when NEW has findings OLD lacks.",
            file=sys.stderr,
        )
        return EXIT_INVALID_INPUT
    old, new = ({entry_key(e): e for e in read_entries(Path(f))[0]} for f in files)
    added = [new[k] for k in sorted(new.keys() - old.keys())]
    fixed = [old[k] for k in sorted(old.keys() - new.keys())]
    unchanged = len(old.keys() & new.keys())

    def brief(entry: dict[str, object]) -> dict[str, object]:
        return {k: entry.get(k) for k in ("check_id", "resource", "file_path")}

    if as_json:
        document = {
            "new": [brief(e) for e in added],
            "fixed": [brief(e) for e in fixed],
            "unchanged": unchanged,
        }
        print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(f"New: {len(added)}\nFixed: {len(fixed)}\nUnchanged: {unchanged}")
        for label, entries in (("New", added), ("Fixed", fixed)):
            for e in entries:
                print(f"  {label}: {e['check_id']} {e.get('resource')} {e.get('file_path')}")
    return EXIT_FINDINGS if added else EXIT_OK


SUBCOMMANDS: dict[str, Callable[[list[str], Path | None], int]] = {
    "diff": _diff,
    "explain": _explain,
    "registry": _registry,
}


def run_subcommand(argv: list[str], registry_path: Path | None) -> int | None:
    """Run a subcommand and return its exit code, or None for the scan parser."""
    handler = SUBCOMMANDS.get(argv[0]) if argv else None
    if handler is None:
        return None
    try:
        return handler(argv[1:], registry_path)
    except Exception as error:
        return handle_scan_error(error)
