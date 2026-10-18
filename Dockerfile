FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS build

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


FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

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
