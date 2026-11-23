FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SOURCE_DATE_EPOCH=0

WORKDIR /src
COPY requirements-ci.lock /tmp/requirements-ci.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements-ci.lock \
    && rm -f /tmp/requirements-ci.lock

# The build backend is supplied by the hash-locked CI environment above. Do
# not let pip create an unpinned network-isolated build environment.
COPY pyproject.toml README.md /src/
COPY tf_eu_guard /src/tf_eu_guard
RUN python -m build --wheel --no-isolation --outdir /dist


FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

# Links the GHCR package to the repository (Packages sidebar). publish.yml
# overrides the version label with the release tag and adds the revision label
# at build time; the default below keeps local builds correctly labelled.
ARG VERSION=0.9.0
LABEL org.opencontainers.image.title="tf-eu-guard" \
      org.opencontainers.image.description="EU compliance security linter for Terraform and Kubernetes: NIS2 and GDPR mapping" \
      org.opencontainers.image.source="https://github.com/44aayush/tf-eu-guard" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /src
COPY requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock
COPY --from=build /dist/tf_eu_guard-*.whl /tmp/
RUN python -m pip install --no-cache-dir --no-deps /tmp/tf_eu_guard-*.whl \
    && rm -f /tmp/tf_eu_guard-*.whl \
    && useradd --create-home --uid 10001 tfeguard

USER tfeguard
ENTRYPOINT ["tf-eu-guard", "scan"]
