"""Emulator-tier helpers; these run without LocalStack or terraform."""

import logging
import os
import subprocess

import pytest
from emulator import stack as stack_module
from emulator.stack import (
    EmulatorUnavailable,
    Stack,
    TerraformError,
    emulator_env,
    require_endpoint,
)


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
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    }
    assert env["PATH"] == "/bin"


def test_terraform_failure_includes_stderr(tmp_path, monkeypatch):
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, stdout="", stderr="Error: boom")

    monkeypatch.setattr(stack_module.subprocess, "run", fake_run)
    with pytest.raises(TerraformError) as excinfo:
        Stack(tmp_path, {}).terraform("apply")
    assert "boom" in str(excinfo.value)
    assert "exit 1" in str(excinfo.value)


def test_emulator_env_points_aws_files_at_devnull():
    env = emulator_env("eu-west-1", {})
    assert env["AWS_CONFIG_FILE"] == os.devnull
    assert env["AWS_SHARED_CREDENTIALS_FILE"] == os.devnull


def test_emulator_env_default_reads_os_environ(monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "prod")
    monkeypatch.setenv("KEEP_ME", "1")
    env = emulator_env("eu-west-1")
    assert "AWS_PROFILE" not in env
    assert env["KEEP_ME"] == "1"


def test_require_endpoint_unreachable():
    with pytest.raises(EmulatorUnavailable, match=r"localstack/localstack:4\.9"):
        require_endpoint("http://127.0.0.1:9", timeout=1.0)


def test_require_endpoint_ignores_proxy_env(monkeypatch):
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/_localstack/health" else 404)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.delenv("NO_PROXY", raising=False)
    try:
        require_endpoint(f"http://127.0.0.1:{server.server_address[1]}")
    finally:
        server.shutdown()
        server.server_close()
