## Summary

<!-- What changes and why. Link the issue (new mappings need one opened first). -->

## Checklist

- [ ] Tests added or updated, and the suite passes (`bash install_and_test.sh` or `pytest`)
- [ ] Docs and `CHANGELOG.md` (`## [Unreleased]`) updated where behaviour changed

### Mapping changes (skip if this PR does not touch `tf_eu_guard/mapping/`)

- [ ] Each `risk` cites the specific article and the requirement it imposes, not just a restatement of the check
- [ ] Article and sub-point letters were cross-checked against `docs/nis2-mapping.md` and `docs/gdpr-mapping.md`
- [ ] `remediation` is copy-pasteable Terraform (or manifest) code, not prose
- [ ] The Checkov ID was verified against a real scan (`checkov -d <dir> --framework terraform --quiet -o json`)
- [ ] A fixture under `examples/` triggers the check and a test asserts the ID is in the enriched output
- [ ] Documented counts still match (`python tools/check_doc_counts.py`; `python tools/generate_coverage_doc.py --check`)
