"""Emulator-tier helpers; these run without LocalStack or terraform."""

import logging

import pytest
from emulator.stack import Stack, emulator_env


class StubStack(Stack):
    def __init__(self, tmp_path, fail=()):
        super().__init__(tmp_path, {})
        self.fail = set(fail)
        self.calls = []

    def terraform(self, *args):
        self.calls.append(args[0])
        if args[0] in self.fail:
            raise RuntimeError(f"{args[0]} failed")
        return ""


def test_stack_destroys_after_failed_apply(tmp_path):
    stack = StubStack(tmp_path, fail={"apply"})
    with pytest.raises(RuntimeError, match="apply failed"):
        with stack.applied():
            pytest.fail("body must not run after a failed apply")
    assert stack.calls == ["apply", "destroy"]


def test_failed_destroy_does_not_hide_the_original_error(tmp_path, caplog):
    stack = StubStack(tmp_path, fail={"destroy"})
    with caplog.at_level(logging.ERROR):
        with pytest.raises(AssertionError, match="original"):
            with stack.applied():
                raise AssertionError("original")
    assert "terraform destroy" in caplog.text


def test_failed_destroy_after_success_is_raised(tmp_path):
    stack = StubStack(tmp_path, fail={"destroy"})
    with pytest.raises(RuntimeError, match="destroy failed"):
        with stack.applied():
            pass


def test_bucket_name_is_unique_per_stack(tmp_path):
    a, b = StubStack(tmp_path), StubStack(tmp_path)
    assert a.bucket != b.bucket
    assert a.env["TF_VAR_bucket_name"] == a.bucket


def test_emulator_env_scrubs_aws_variables():
    base = {
        "PATH": "/bin",
        "AWS_PROFILE": "prod",
        "AWS_ACCESS_KEY_ID": "AKIAREAL",
        "AWS_SECRET_ACCESS_KEY": "real",
        "AWS_SESSION_TOKEN": "tok",
        "AWS_DEFAULT_REGION": "eu-west-1",
        "AWS_ENDPOINT_URL": "https://example.invalid",
        "AWS_REGION": "eu-central-1",
    }
    env = emulator_env("us-east-1", base)
    assert {k: v for k, v in env.items() if k.startswith("AWS_")} == {
        "AWS_ACCESS_KEY_ID": "test",
        "AWS_SECRET_ACCESS_KEY": "test",
        "AWS_REGION": "us-east-1",
    }
    assert env["PATH"] == "/bin"
