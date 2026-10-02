FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src
COPY requirements.lock /tmp/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock \
    && rm -f /tmp/requirements.lock
COPY . /src
RUN python -m pip install --no-cache-dir --no-deps /src \
    && useradd --create-home --uid 10001 tfeguard

USER tfeguard
ENTRYPOINT ["tf-eu-guard", "scan"]
