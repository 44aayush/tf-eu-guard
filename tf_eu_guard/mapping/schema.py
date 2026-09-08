"""Schema constants for the compliance-mapping registries.

Pure data: what a valid ``registry-*.yaml`` entry must look like. The loader
(:mod:`tf_eu_guard.mapping.loader`) imports these instead of defining them
inline, so the registry format is specified in one reviewable place.
"""

from tf_eu_guard.models import Framework, Severity

#: Top-level fields every registry entry must carry, non-empty.
REQUIRED_FIELDS = ("check_name", "articles", "risk", "remediation", "severity")

#: Valid ``severity`` values (mirrors :class:`tf_eu_guard.models.Severity`).
VALID_SEVERITIES = {s.value for s in Severity}

#: Valid ``framework`` values inside ``articles`` (mirrors
#: :class:`tf_eu_guard.models.Framework`).
VALID_FRAMEWORKS = {f.value for f in Framework}
