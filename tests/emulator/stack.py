"""Terraform stack helper for the emulator tier (importable without LocalStack)."""

import logging
import os
import subprocess
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

LOG = logging.getLogger(__name__)
EMULATOR_CREDENTIALS = {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}


def emulator_env(region: str, base: Mapping[str, str] | None = None) -> dict[str, str]:
    """Environment for Terraform: no ambient AWS_* except the region and test credentials."""
    source = os.environ if base is None else base
    env = {k: v for k, v in source.items() if not k.startswith("AWS_")}
    env.update(EMULATOR_CREDENTIALS)
    env["AWS_REGION"] = region
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
            check=True,
            capture_output=True,
            text=True,
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
