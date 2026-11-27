"""Terraform stack helper for the emulator tier (importable without LocalStack)."""

import logging
import os
import subprocess
import urllib.request
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

LOG = logging.getLogger(__name__)
EMULATOR_CREDENTIALS = {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}
STDERR_TAIL = 4000
LOCALSTACK_HINT = (
    "docker run -d --rm -p 127.0.0.1:4566:4566 "
    "-e SERVICES=s3,sqs,dynamodb,sts,iam localstack/localstack:4.9"
)


class TerraformError(RuntimeError):
    """A terraform invocation exited non-zero; the message carries its stderr tail."""


class EmulatorUnavailable(RuntimeError):  # noqa: N818
    """The emulator endpoint did not answer its health check."""


def require_endpoint(endpoint: str, timeout: float = 5.0) -> None:
    """Raise EmulatorUnavailable unless LocalStack answers 200 on its health URL."""
    url = f"{endpoint}/_localstack/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            status = response.status
    except Exception as exc:
        reason = f"{type(exc).__name__}: {exc}"
    else:
        if status == 200:
            return
        reason = f"HTTP {status}"
    raise EmulatorUnavailable(
        f"emulator endpoint {endpoint} is not reachable ({reason}). "
        f"Start LocalStack as the CI service does: {LOCALSTACK_HINT}"
    )


def emulator_env(region: str, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environment for Terraform: no ambient AWS_* except the region and test credentials."""
    source = os.environ if base is None else base
    env = {k: v for k, v in source.items() if not k.startswith("AWS_")}
    env.update(EMULATOR_CREDENTIALS)
    env["AWS_REGION"] = region
    env["AWS_CONFIG_FILE"] = os.devnull
    env["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    env["TF_IN_AUTOMATION"] = "1"
    return env


class Stack:
    """A fixture copied into a temporary directory with the emulator override."""

    def __init__(self, work: Path, env: dict[str, str]) -> None:
        self.work = work
        self.env = env
        self.bucket = f"tf-eu-guard-emulator-{uuid.uuid4().hex[:12]}"
        self.env["TF_VAR_bucket_name"] = self.bucket

    def terraform(self, *args: str) -> str:
        done = subprocess.run(
            ["terraform", *args],
            cwd=self.work,
            env=self.env,
            check=False,
            capture_output=True,
            text=True,
        )
        if done.returncode != 0:
            raise TerraformError(
                f"terraform {' '.join(args)} failed (exit {done.returncode}):\n"
                f"{(done.stderr or '')[-STDERR_TAIL:]}"
            )
        return done.stdout

    def plan_json(self) -> Path:
        self.terraform("init", "-input=false", "-no-color")
        self.terraform("plan", "-input=false", "-no-color", "-out=tfplan")
        plan = self.work / "plan.json"
        plan.write_text(self.terraform("show", "-json", "tfplan"), encoding="utf-8")
        return plan

    def apply(self) -> None:
        self.terraform("apply", "-input=false", "-no-color", "-auto-approve", "tfplan")

    def destroy(self) -> None:
        self.terraform("destroy", "-input=false", "-no-color", "-auto-approve")

    @contextmanager
    def applied(self) -> Iterator[None]:
        """Apply, yield, and always destroy; a destroy failure never hides the original error."""
        try:
            self.apply()
            yield
        except BaseException:
            try:
                self.destroy()
            except Exception:
                LOG.exception("emulator cleanup (terraform destroy) failed")
            raise
        self.destroy()
