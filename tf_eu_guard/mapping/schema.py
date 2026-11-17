"""Schema constants for the compliance-mapping registries.

Pure data: what a valid ``registry-*.yaml`` entry must look like. The loader
(:mod:`tf_eu_guard.mapping.loader`) imports these instead of defining them
inline, so the registry format is specified in one reviewable place.
"""

import re

from tf_eu_guard.models import Framework, Severity

#: Top-level fields every registry entry must carry, non-empty.
REQUIRED_FIELDS = ("check_name", "articles", "risk", "remediation", "severity")

#: Valid ``severity`` values (mirrors :class:`tf_eu_guard.models.Severity`).
VALID_SEVERITIES = {s.value for s in Severity}

#: Valid ``framework`` values inside ``articles`` (mirrors
#: :class:`tf_eu_guard.models.Framework`).
VALID_FRAMEWORKS = {f.value for f in Framework}

#: Keys an entry may carry (the required ones; nothing else is accepted).
ENTRY_KEYS = frozenset(REQUIRED_FIELDS)

#: Keys an ``articles`` item may carry.
ARTICLE_KEYS = frozenset({"framework", "article", "title"})

#: Shape of a check ID: stock Checkov (``CKV_AWS_21``, ``CKV2_AWS_6``,
#: ``CKV_TF_1``, ``CKV_K8S_16``, ``CKV2_K8S_6``) or a tf-eu-guard custom check
#: (``EUGUARD_<NIS2|GDPR|POLICY>_<NNN>``).
CHECK_ID_RE = re.compile(r"^(CKV\d?_(AWS|AZURE|GCP|K8S|TF)_\d+|EUGUARD_(NIS2|GDPR|POLICY)_\d{3})$")
