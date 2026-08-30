FROM python:3.12-slim

COPY . /src
RUN pip install --no-cache-dir /src

ENTRYPOINT ["tf-eu-guard", "scan"]
