#!/usr/bin/env python3
"""Generate docs/checkov-coverage.md: which checks of the installed Checkov are mapped.

Checkov ships many hundreds of AWS/Azure/GCP/Kubernetes/Terraform checks (the
exact count is in the generated table's summary) and the registries map only a
deliberate subset. This table lists every check of the
installed Checkov release as ``mapped``, ``intentionally unmapped`` (with a
reason from ``tools/checkov_triage.yaml``) or ``untriaged`` (nobody has
decided yet; that is a fact, not an error). The catalogue comes from Checkov's
own Python registries (Terraform resource, data, module and provider checks, the
graph checks that carry the ``CKV2_`` IDs, and the Kubernetes checks).

``--check`` exits 1 when the committed doc is stale, when a registry ID
with a Checkov prefix no longer exists in the installed Checkov, when an ID
is both mapped and listed as intentionally unmapped, or when a triage ID
(``intentionally_unmapped`` or ``known_stale``) is neither in the installed
catalogue nor in a registry. ``--doc PATH`` reads or writes another doc file. A Checkov bump changes
the catalogue, so regenerate the doc in the same change:

    python3 tools/generate_checkov_coverage.py          # regenerate in place
    python3 tools/generate_checkov_coverage.py --check  # CI drift check

Exit codes: 0 = generated / in sync, 1 = out of sync or a registry/triage problem.
"""

import re
import sys
from pathlib import Path
from typing import NamedTuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tf_eu_guard.mapping.loader import load_registry  # noqa: E402

DOC_PATH = REPO_ROOT / "docs" / "checkov-coverage.md"
TRIAGE_PATH = Path(__file__).resolve().parent / "checkov_triage.yaml"

# Prefix -> provider heading. Order is the order of the per-provider sections.
PROVIDERS = {
    "AWS": ("CKV_AWS_", "CKV2_AWS_"),
    "Azure": ("CKV_AZURE_", "CKV2_AZURE_"),
    "GCP": ("CKV_GCP_", "CKV2_GCP_"),
    "Kubernetes": ("CKV_K8S_", "CKV2_K8S_"),
    "Terraform (cloud-agnostic)": ("CKV_TF_",),
}
PREFIXES = tuple(p for prefixes in PROVIDERS.values() for p in prefixes)

MAPPED = "mapped"
UNMAPPED = "intentionally unmapped"
UNTRIAGED = "untriaged"


class Row(NamedTuple):
    check_id: str
    name: str
    provider: str
    status: str
    reason: str


def _provider(check_id: str) -> str | None:
    for provider, prefixes in PROVIDERS.items():
        if check_id.startswith(prefixes):
            return provider
    return None


def _natural_key(check_id: str) -> list[object]:
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", check_id)]


def catalogue() -> dict[str, str]:
    """Check ID -> check name for the installed Checkov, restricted to the mapped prefixes."""
    # Imported here so the pure functions work without Checkov installed.
    # Importing the registries alone does not load the check modules.
    import checkov.kubernetes.checks.resource  # noqa: F401
    import checkov.terraform.checks.data  # noqa: F401
    import checkov.terraform.checks.module  # noqa: F401
    import checkov.terraform.checks.provider  # noqa: F401
    import checkov.terraform.checks.resource  # noqa: F401
    from checkov.common.checks_infra.registry import get_graph_checks_registry
    from checkov.kubernetes.checks.resource.registry import registry as k8s_registry
    from checkov.terraform.checks.data.registry import data_registry
    from checkov.terraform.checks.module.registry import module_registry
    from checkov.terraform.checks.provider.registry import provider_registry
    from checkov.terraform.checks.resource.registry import resource_registry

    found: dict[str, str] = {}
    for registry in (
        resource_registry,
        data_registry,
        module_registry,
        provider_registry,
        k8s_registry,
    ):
        for checks in registry.checks.values():
            for check in checks:
                found[check.id] = check.name
    for check_type in ("terraform", "kubernetes"):
        graph_registry = get_graph_checks_registry(check_type)
        graph_registry.load_checks()
        for graph_check in graph_registry.checks:
            found[graph_check.id] = graph_check.name
    return {cid: name for cid, name in found.items() if cid.startswith(PREFIXES)}


def classify(catalogue: dict[str, str], mapped_ids: set[str], triage: dict[str, str]) -> list[Row]:
    rows = []
    for check_id in sorted(catalogue, key=_natural_key):
        provider = _provider(check_id)
        if provider is None:
            continue
        if check_id in mapped_ids:
            status, reason = MAPPED, ""
        elif check_id in triage:
            status, reason = UNMAPPED, triage[check_id]
        else:
            status, reason = UNTRIAGED, ""
        rows.append(Row(check_id, catalogue[check_id], provider, status, reason))
    return rows


def stale_ids(catalogue: dict[str, str], mapped_ids: set[str]) -> list[str]:
    """Registry IDs with a Checkov prefix that the installed Checkov does not define."""
    return sorted(
        (i for i in mapped_ids if i.startswith(PREFIXES) and i not in catalogue),
        key=_natural_key,
    )


def problems(
    catalogue: dict[str, str],
    mapped_ids: set[str],
    triage: dict[str, str],
    known_stale: dict[str, str],
) -> list[str]:
    found = []
    for check_id in stale_ids(catalogue, mapped_ids):
        if check_id not in known_stale:
            found.append(f"{check_id}: in a registry but not in this Checkov release")
    for name, ids in (("intentionally_unmapped", triage), ("known_stale", known_stale)):
        for check_id in sorted(ids, key=_natural_key):
            # A known_stale ID may still be mapped; it only has to be accounted for somewhere.
            if check_id not in catalogue and check_id not in mapped_ids:
                found.append(f"{check_id}: listed in {name} but not in this Checkov release")
    for check_id in sorted(set(triage) & mapped_ids, key=_natural_key):
        found.append(f"{check_id}: both mapped in a registry and listed as intentionally unmapped")
    return found


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").strip()


def render(rows: list[Row], checkov_version: str) -> str:
    lines = [
        "# Checkov coverage by release",
        "",
        "> Generated file. `tools/generate_checkov_coverage.py` renders it from the "
        "installed Checkov catalogue, the mapping registries and "
        "`tools/checkov_triage.yaml`. Do not edit it by hand; CI (via `--check`) "
        "fails if it drifts, so a Checkov bump regenerates it.",
        "",
        f"Checkov {checkov_version}. Every check of this release with a `CKV_` / `CKV2_` "
        "AWS, Azure, GCP, Kubernetes or `CKV_TF_` ID is listed once:",
        "",
        "- **mapped**: has a registry entry with article references.",
        "- **intentionally unmapped**: reviewed and left out on purpose; the reason is given.",
        "- **untriaged**: not reviewed yet. This is the default and is not a defect; the "
        "mapping is deliberately a subset (see "
        "[Checks still intentionally unmapped](check-mapping-table.md#checks-still-intentionally-unmapped)).",
        "",
        "## Summary",
        "",
        "| Provider | Total | Mapped | Intentionally unmapped | Untriaged |",
        "|----------|------:|-------:|-----------------------:|----------:|",
    ]
    totals = [0, 0, 0, 0]
    for provider in PROVIDERS:
        mine = [r for r in rows if r.provider == provider]
        counts = [len(mine)] + [
            sum(r.status == s for r in mine) for s in (MAPPED, UNMAPPED, UNTRIAGED)
        ]
        totals = [a + b for a, b in zip(totals, counts, strict=True)]
        lines.append(f"| {provider} | {counts[0]} | {counts[1]} | {counts[2]} | {counts[3]} |")
    lines.append(f"| **All** | {totals[0]} | {totals[1]} | {totals[2]} | {totals[3]} |")
    for provider in PROVIDERS:
        mine = [r for r in rows if r.provider == provider]
        if not mine:
            continue
        lines += [
            "",
            f"## {provider}",
            "",
            "| Check | Name | Status | Reason |",
            "|-------|------|--------|--------|",
        ]
        for r in mine:
            lines.append(f"| {r.check_id} | {_cell(r.name)} | {r.status} | {_cell(r.reason)} |")
    return "\n".join(lines) + "\n"


def load_triage(path: Path = TRIAGE_PATH) -> tuple[dict[str, str], dict[str, str]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    unknown = set(data) - {"intentionally_unmapped", "known_stale"}
    if unknown:
        raise SystemExit(f"{path.name}: unknown key(s): {', '.join(sorted(unknown))}")
    return data.get("intentionally_unmapped") or {}, data.get("known_stale") or {}


def _shown(path: Path) -> str:
    return str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path)


def main(argv: list[str]) -> int:
    from checkov.version import version

    check = "--check" in argv
    doc_path = Path(argv[argv.index("--doc") + 1]) if "--doc" in argv else DOC_PATH
    mapped_ids = set(load_registry(REPO_ROOT / "tf_eu_guard" / "mapping"))
    triage, known_stale = load_triage()
    cat = catalogue()
    found = problems(cat, mapped_ids, triage, known_stale)
    for line in found:
        print(f"ERROR: {line}", file=sys.stderr)
    doc = render(classify(cat, mapped_ids, triage), version)
    if check:
        current = doc_path.read_text(encoding="utf-8") if doc_path.exists() else ""
        if current != doc:
            print(
                f"ERROR: {_shown(doc_path)} is stale; run "
                "python3 tools/generate_checkov_coverage.py",
                file=sys.stderr,
            )
            return 1
        return 1 if found else 0
    doc_path.write_text(doc, encoding="utf-8")
    print(f"wrote {_shown(doc_path)} ({len(cat)} checks, Checkov {version})")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
