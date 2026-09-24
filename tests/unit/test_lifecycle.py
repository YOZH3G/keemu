"""Failure semantics for the one-shot lifecycle without requiring Docker."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from keemu.docker_runtime import Output
from keemu.lifecycle import StageFailure, _probe_stopped, _residual
from keemu.scenarios import HTTPProbe


@dataclass
class StubRuntime:
    output: Output

    def exec(self, _container, _argv, **_kwargs):
        return self.output


def test_residual_exempts_only_exact_opkg_bookkeeping() -> None:
    baseline = ("A /opt/tmp/existing",)
    actual = (
        "A /opt/tmp/existing",
        "C /opt/lib/opkg/status",
        "A /opt/tmp/opt/lib/opkg/info",
        "A /opt/tmp/opt/lib/opkg/info/foreign.list",
        "A /opt/tmp/opt/lib/opkg/status.backup",
        "A /opt/secret",
    )
    assert _residual(actual, baseline, ("/opt/etc/allowed",)) == (
        "A /opt/tmp/opt/lib/opkg/info/foreign.list",
        "A /opt/tmp/opt/lib/opkg/status.backup",
        "A /opt/secret",
    )


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (Output(b"", b"wget: Connection refused", exit_code=1), "PASS"),
        (Output(b"", b"HTTP/1.1 503 Unavailable", exit_code=1), "FAIL"),
        (Output(b"", b"wget: not found", exit_code=127), "BLOCKED"),
    ],
)
def test_stopped_endpoint_distinguishes_refused_from_failed_readiness(
    output: Output, expected: str
) -> None:
    probe = HTTPProbe(
        kind="http",
        vantage="target_loopback",
        url="http://127.0.0.1:8080/health",
        expected_status=(200,),
        body_contains="ready",
    )
    runtime = StubRuntime(output)
    if expected == "PASS":
        assert "connection refused" in _probe_stopped(runtime, "container", probe)
    else:
        with pytest.raises(StageFailure) as caught:
            _probe_stopped(runtime, "container", probe)
        assert caught.value.status == expected
