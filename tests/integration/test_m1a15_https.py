"""Opt-in, isolated AArch64 HTTPS + HTTP/UDP live probe.

KEEMU_M1A15_LIVE=1 uv run pytest -q tests/integration/test_m1a15_https.py
Only run-labeled containers are created; constrained observer uses host vantage.
Generated private keys live exclusively under ignored .runtime/m1a15/live-*/.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

import pytest

from keemu.init_cache import init_locked
from keemu.lifecycle import run_scenario
from keemu.scenarios import HTTPProbe, UDPProbe
from tests.integration.test_lifecycle import inputs

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:fa618afa80cab7d081e8012ed8209cf16d95507263c412ba119d131510e888bc"
CLIENT_IMAGE = "sha256:7956ad1f365ad2ce4454673cb3f3ab31798703b2a3ea1d1329c509250f974bee"
BINARY = ROOT / ".runtime/m1a15/https-frontend-aarch64"
FRONTEND_LOCK = ROOT / "locks/m1a15-https-frontend-aarch64.json"


def call(*argv: str, timeout: int = 45, check: bool = True) -> str:
    result = subprocess.run(  # noqa: S603 -- argv-only fixed binaries; no shell.
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and result.returncode:
        raise AssertionError(
            f"{argv[:4]}: rc={result.returncode}: {result.stderr[-1500:]}"
        )
    return result.stdout.strip()


def make_certs(directory: Path) -> tuple[Path, Path, Path]:
    directory.mkdir(parents=True, exist_ok=False, mode=0o700)
    ca = directory / "ca.crt"
    ca_key = directory / "ca.key"
    cert = directory / "server.crt"
    key = directory / "server.key"
    csr = directory / "server.csr"
    extension = directory / "server.ext"
    extension.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n",
        encoding="ascii",
    )
    call(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-noenc",
        "-days",
        "1",
        "-subj",
        "/CN=KEEMU m1a15 isolated CA",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout",
        str(ca_key),
        "-out",
        str(ca),
    )
    call(
        "openssl",
        "req",
        "-newkey",
        "rsa:2048",
        "-noenc",
        "-subj",
        "/CN=localhost",
        "-keyout",
        str(key),
        "-out",
        str(csr),
    )
    call(
        "openssl",
        "x509",
        "-req",
        "-in",
        str(csr),
        "-CA",
        str(ca),
        "-CAkey",
        str(ca_key),
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        str(extension),
        "-out",
        str(cert),
    )
    return ca, cert, key


CLIENT_CODE = r"""
import json, os, socket, ssl, time
ca = os.environ['KEEMU_CA']
expected = os.environ['KEEMU_EXPECTED_STATE']
https_port = int(os.environ['KEEMU_HTTPS_PORT'])
http_port = int(os.environ['KEEMU_HTTP_PORT'])
udp_port = int(os.environ['KEEMU_UDP_PORT'])
trusted = ssl.create_default_context(cadata=ca)

def request(ctx, hostname, line=b'GET /health HTTP/1.1\r\n'):
    with socket.create_connection(('127.0.0.1', https_port), timeout=6) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            tls.settimeout(6)
            tls.sendall(line + b'Host: localhost\r\nConnection: close\r\n\r\n')
            chunks = []
            while True:
                data = tls.recv(2048)
                if not data: break
                chunks.append(data)
            return b''.join(chunks).decode('ascii')

for attempt in range(15):
    try:
        response = request(trusted, 'localhost')
        break
    except (OSError, ssl.SSLError):
        if attempt == 14: raise
        time.sleep(0.2)
assert response.startswith('HTTP/1.1 200 OK'), response
assert 'state='+expected+'\n' in response, response
assert 'state='+expected+'\n' in request(trusted, '127.0.0.1')
try:
    request(ssl.create_default_context(), 'localhost')
    raise AssertionError('untrusted CA accepted')
except ssl.SSLCertVerificationError: pass
try:
    request(trusted, 'wrong.local')
    raise AssertionError('wrong hostname accepted')
except ssl.SSLCertVerificationError: pass
if os.environ['KEEMU_WRITE_STATE'] == '1':
    post = request(trusted, 'localhost', b'POST /state?value=secure HTTP/1.1\r\n')
    assert 'state=secure\n' in post, post
    assert 'state=secure\n' in request(trusted, 'localhost')
    expected = 'secure'
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.settimeout(3)
    udp.sendto(b'm1a15', ('127.0.0.1', udp_port))
    data, _ = udp.recvfrom(512)
    assert data == b'keemu-udp:m1a15', data
with socket.create_connection(('127.0.0.1', http_port), timeout=3) as http:
    http.sendall(b'GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n')
    plain = http.recv(2048)
    assert plain.startswith(b'HTTP/1.1 200 OK'), plain
    assert b'keemu-web-demo\n' in plain and ('state='+expected+'\n').encode() in plain
print(json.dumps({'trusted_tls':'PASS','untrusted_ca':'REJECTED',
                  'wrong_hostname':'REJECTED','https_state':expected,
                  'http':'PASS','udp':'PASS','vantage':'docker_host_loopback'}))
"""


def observe_host(
    run_id: str,
    target: str,
    ca: Path,
    ports: dict[str, str],
    state: str,
    write: bool,
    stage: str,
) -> dict:
    name = target + "-client-" + stage
    created = False
    try:
        call(
            "docker",
            "create",
            "--name",
            name,
            "--platform",
            "linux/amd64",
            "--network",
            "host",
            "--read-only",
            "--pull",
            "never",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--label",
            "org.keemu.role=m1a15-client",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=0.5",
            "--pids-limit=64",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--env",
            "KEEMU_CA=" + ca.read_text(encoding="ascii"),
            "--env",
            "KEEMU_EXPECTED_STATE=" + state,
            "--env",
            "KEEMU_WRITE_STATE=" + str(int(write)),
            "--env",
            "KEEMU_HTTP_PORT=" + ports["8080/tcp"].rsplit(":", 1)[1],
            "--env",
            "KEEMU_HTTPS_PORT=" + ports["8443/tcp"].rsplit(":", 1)[1],
            "--env",
            "KEEMU_UDP_PORT=" + ports["8081/udp"].rsplit(":", 1)[1],
            "--entrypoint",
            "/usr/bin/python3",
            CLIENT_IMAGE,
            "-c",
            CLIENT_CODE,
        )
        created = True
        info = json.loads(call("docker", "inspect", name))[0]
        host = info["HostConfig"]
        assert info["Image"] == CLIENT_IMAGE
        assert host["NetworkMode"] == "host" and host["ReadonlyRootfs"]
        assert not host["Privileged"] and host["Binds"] in (None, [])
        assert host["PortBindings"] in (None, {})
        assert host["CapAdd"] in (None, []) and "ALL" in host["CapDrop"]
        call("docker", "start", info["Id"])
        code = call("docker", "wait", info["Id"], timeout=90)
        logs = subprocess.run(  # noqa: S603 -- fixed Docker argv, no shell.
            ("docker", "logs", info["Id"]),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert code == "0", (
            f"host-vantage observer {stage}: {logs.stdout} {logs.stderr}"
        )
        result = json.loads(logs.stdout)
        assert result == {
            "trusted_tls": "PASS",
            "untrusted_ca": "REJECTED",
            "wrong_hostname": "REJECTED",
            "https_state": "secure" if write else state,
            "http": "PASS",
            "udp": "PASS",
            "vantage": "docker_host_loopback",
        }
        return result
    finally:
        if created:
            info = json.loads(call("docker", "inspect", name))[0]
            labels = info["Config"]["Labels"]
            assert labels["org.keemu.owner"] == "keemu"
            assert labels["org.keemu.run-id"] == run_id
            assert labels["org.keemu.role"] == "m1a15-client"
            if info["State"]["Running"]:
                call("docker", "stop", "-t", "5", info["Id"])
            call("docker", "rm", info["Id"])
            assert call("docker", "container", "inspect", info["Id"], check=False) in (
                "",
                "[]",
            )


def start_services(target: str, key_user: str) -> None:
    call(
        "docker",
        "exec",
        target,
        "/bin/sh",
        "-c",
        "/opt/bin/web-demo-p006 8080 8081 /opt/etc/web-demo/state.txt "
        ">/opt/var/m1a15-http.log 2>&1 & echo $! >/opt/tmp/m1a15-http.pid",
    )
    call(
        "docker",
        "exec",
        "--user",
        key_user,
        target,
        "/bin/sh",
        "-c",
        "/opt/bin/https-frontend-m1a15 8443 8080 /opt/etc/web-demo/server.crt "
        "/opt/etc/web-demo/server.key >/dev/null 2>&1 & "
        "echo $! >/tmp/m1a15-https.pid",
    )


@pytest.mark.skipif(
    os.environ.get("KEEMU_M1A15_LIVE") != "1", reason="opt-in Docker/binfmt probe"
)
def test_https_aarch64_with_local_ca() -> None:
    assert BINARY.is_file(), (
        "build fixture with fixtures/recipes/aarch64/https-frontend-m1a15.mk"
    )
    pinned = json.loads(FRONTEND_LOCK.read_text())
    for key, file in (
        ("source_sha256", ROOT / "fixtures/sources/web-demo/https_frontend_m1a15.c"),
        ("recipe_sha256", ROOT / "fixtures/recipes/aarch64/https-frontend-m1a15.mk"),
        ("binary_sha256", BINARY),
    ):
        assert hashlib.sha256(file.read_bytes()).hexdigest() == pinned[key]
    assert call("docker", "image", "inspect", IMAGE, "--format", "{{.Id}}") == IMAGE
    assert (
        call("docker", "image", "inspect", CLIENT_IMAGE, "--format", "{{.Id}}")
        == CLIENT_IMAGE
    )
    run_id = "m1a15-" + uuid4().hex[:12]
    target = "keemu-" + run_id

    runtime = ROOT / ".runtime/m1a15" / ("live-" + run_id)
    ca, cert, key = make_certs(runtime)
    created: list[str] = []
    observations: dict[str, dict] = {}
    try:
        call(
            "docker",
            "create",
            "--name",
            target,
            "--platform",
            "linux/amd64",
            "--label",
            "org.keemu.owner=keemu",
            "--label",
            f"org.keemu.run-id={run_id}",
            "--label",
            "org.keemu.role=m1a15-target",
            "--memory=256m",
            "--memory-swap=256m",
            "--cpus=1",
            "--pids-limit=128",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--restart=no",
            "--publish",
            "127.0.0.1::8443/tcp",
            "--publish",
            "127.0.0.1::8080/tcp",
            "--publish",
            "127.0.0.1::8081/udp",
            IMAGE,
        )
        created.append(target)
        inspected = json.loads(call("docker", "inspect", target))[0]
        assert inspected["Image"] == IMAGE
        assert inspected["HostConfig"]["Privileged"] is False
        assert inspected["HostConfig"]["Binds"] in (None, [])
        for bindings in inspected["HostConfig"]["PortBindings"].values():
            assert all(binding["HostIp"] == "127.0.0.1" for binding in bindings)
        call("docker", "start", target)
        call(
            "docker",
            "exec",
            target,
            "/bin/sh",
            "-c",
            "mkdir -p /opt/etc/web-demo /opt/var; "
            "echo initial >/opt/etc/web-demo/state.txt",
        )
        for source, destination in (
            (BINARY, "/opt/bin/https-frontend-m1a15"),
            (cert, "/opt/etc/web-demo/server.crt"),
            (key, "/opt/etc/web-demo/server.key"),
        ):
            call("docker", "cp", str(source), target + ":" + destination)
        key_stat = call(
            "docker",
            "exec",
            target,
            "/opt/bin/busybox",
            "ls",
            "-ln",
            "/opt/etc/web-demo/server.key",
        )
        key_fields = key_stat.split()
        assert key_fields[0] == "-rw-------" and len(key_fields) >= 4, key_stat
        key_user = key_fields[2] + ":" + key_fields[3]
        start_services(target, key_user)
        published = {
            protocol: call("docker", "port", target, protocol)
            for protocol in ("8443/tcp", "8080/tcp", "8081/udp")
        }
        assert all(value.startswith("127.0.0.1:") for value in published.values())
        expected_bindings = {
            port: [{"HostIp": "127.0.0.1", "HostPort": value.rsplit(":", 1)[1]}]
            for port, value in published.items()
        }
        inspected = json.loads(call("docker", "inspect", target))[0]
        assert inspected["HostConfig"]["PortBindings"] == {
            port: [{"HostIp": "127.0.0.1", "HostPort": ""}]
            for port in expected_bindings
        }
        assert inspected["NetworkSettings"]["Ports"] == expected_bindings
        probes: list[HTTPProbe | UDPProbe] = [
            HTTPProbe(
                kind="http",
                vantage="host_publish",
                url="http://" + published["8080/tcp"] + "/health",
                expected_status=(200,),
                body_contains="keemu-web-demo",
            ),
            HTTPProbe(
                kind="https",
                vantage="host_publish",
                url="https://" + published["8443/tcp"] + "/health",
                expected_status=(200,),
                body_contains="keemu-web-demo",
                ca_cert=str(ca.relative_to(ROOT)),
            ),
        ]
        probes.append(
            UDPProbe(
                kind="udp",
                vantage="host_publish",
                host="127.0.0.1",
                port=int(published["8081/udp"].rsplit(":", 1)[1]),
                request="m1a15",
                expected_response="keemu-udp:m1a15",
            )
        )
        assert all(probe.vantage == "host_publish" for probe in probes)
        observations["initial"] = observe_host(
            run_id, target, ca, published, "initial", True, "initial"
        )
        # Explicit service restart: same target container, no package reinstall.
        call(
            "docker",
            "exec",
            "--user",
            key_user,
            target,
            "/bin/sh",
            "-c",
            "/opt/bin/busybox kill -TERM $(/opt/bin/busybox cat /tmp/m1a15-https.pid)",
        )
        call(
            "docker",
            "exec",
            target,
            "/bin/sh",
            "-c",
            "/opt/bin/busybox kill -TERM "
            "$(/opt/bin/busybox cat /opt/tmp/m1a15-http.pid)",
        )
        start_services(target, key_user)
        observations["service_restart"] = observe_host(
            run_id, target, ca, published, "secure", False, "service-restart"
        )
        call("docker", "stop", "-t", "5", target)
        stopped = json.loads(call("docker", "inspect", target))[0]
        assert stopped["State"]["Running"] is False
        call("docker", "start", target)
        assert json.loads(call("docker", "inspect", target))[0]["Id"] == inspected["Id"]
        start_services(target, key_user)
        restarted_ports = {
            protocol: call("docker", "port", target, protocol) for protocol in published
        }
        assert all(value.startswith("127.0.0.1:") for value in restarted_ports.values())
        observations["container_restart"] = observe_host(
            run_id, target, ca, restarted_ports, "secure", False, "container-restart"
        )
        state = call(
            "docker",
            "exec",
            target,
            "/opt/bin/busybox",
            "cat",
            "/opt/etc/web-demo/state.txt",
        )
        assert state == "secure"
        evidence = {
            "run_id": run_id,
            "container_id": inspected["Id"],
            "target_image": IMAGE,
            "client_image": CLIENT_IMAGE,
            "binary_sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
            "ca_cert_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
            "server_cert_sha256": hashlib.sha256(cert.read_bytes()).hexdigest(),
            "published": published,
            "published_after_restart": restarted_ports,
            "vantage": "docker_host_loopback",
            "probe_contracts": [probe.model_dump(mode="json") for probe in probes],
            "state_sha256": hashlib.sha256(b"secure\n").hexdigest(),
            "observations": observations,
        }
        (runtime / "evidence.json").write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print("m1a15 live:", json.dumps(evidence, sort_keys=True))
    finally:
        cleanup_errors: list[str] = []
        for name in reversed(created):
            try:
                details = json.loads(call("docker", "inspect", name))[0]
                labels = details["Config"]["Labels"]
                if not (
                    labels.get("org.keemu.owner") == "keemu"
                    and labels.get("org.keemu.run-id") == run_id
                    and labels.get("org.keemu.role") == "m1a15-target"
                ):
                    raise AssertionError(
                        f"ownership mismatch: {name}; refusing removal"
                    )
                if details["State"]["Running"]:
                    call("docker", "stop", "-t", "5", details["Id"])
                call("docker", "rm", details["Id"])
                absence = call(
                    "docker", "container", "inspect", details["Id"], check=False
                )
                assert absence in ("", "[]"), f"not absent: {name}"
            except (AssertionError, ValueError, subprocess.TimeoutExpired) as exc:
                cleanup_errors.append(f"{name}: {exc}")
        for private in (runtime / "ca.key", key):
            private.unlink(missing_ok=True)
        assert not cleanup_errors, "; ".join(cleanup_errors)
        evidence_path = runtime / "evidence.json"
        if evidence_path.exists():
            data = json.loads(evidence_path.read_text(encoding="utf-8"))
            data["cleanup"] = {
                "target_absent": call(
                    "docker",
                    "container",
                    "inspect",
                    data["container_id"],
                    check=False,
                )
                in ("", "[]"),
                "private_keys_absent": not (runtime / "ca.key").exists()
                and not key.exists(),
            }
            assert all(data["cleanup"].values())
            evidence_path.write_text(
                json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )


@pytest.mark.docker
def test_aarch64_hello_offline_locked_repeat(monkeypatch: pytest.MonkeyPatch) -> None:
    if os.environ.get("KEEMU_M1A15_LIVE") != "1":
        pytest.skip("opt in to real offline Docker/binfmt fixture repeat")

    def no_fetch(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline fixture tried to fetch from network")

    monkeypatch.setattr("urllib.request.urlopen", no_fetch)
    init = init_locked(ROOT, offline=True)
    with tempfile.TemporaryDirectory(
        dir=ROOT / ".runtime", prefix="m1a15-hello-"
    ) as folder:
        scenario, lock = inputs(Path(folder))
        locked_scenario = hashlib.sha256(scenario.read_bytes()).hexdigest()
        locked_ipk = hashlib.sha256(
            (Path(folder) / "hello.ipk").read_bytes()
        ).hexdigest()
        reports = []
        for _ in range(2):
            result = run_scenario(
                scenario,
                lock,
                project_root=ROOT,
                run_id="m1a15-hello-" + uuid4().hex[:12],
            )
            assert result.report.overall == "PASS", result.paths.json
            assert result.report.scenario is not None
            assert result.report.artifact is not None
            assert result.report.scenario.sha256 == locked_scenario
            assert result.report.artifact.sha256 == locked_ipk
            assert result.report.runtime.oci_digest == init["oci_digest"]
            assert result.report.partial_failure is None
            assert result.report.checks[-1].id == "cleanup"
            assert result.report.checks[-1].status == "PASS"
            assert {
                "check-postinst-once",
                "check-executable",
                "installed-state",
                "remove-exit",
                "residual",
            }.issubset(
                {check.id for check in result.report.checks if check.status == "PASS"}
            )
            assert result.paths.json.read_text()
            assert result.paths.markdown.read_text()
            reports.append(str(result.paths.json))
        assert reports[0] != reports[1]
        assert hashlib.sha256(scenario.read_bytes()).hexdigest() == locked_scenario
        assert (
            hashlib.sha256((Path(folder) / "hello.ipk").read_bytes()).hexdigest()
            == locked_ipk
        )
        print(
            json.dumps(
                {
                    "offline_hello_reports": reports,
                    "scenario_sha256": locked_scenario,
                    "ipk_sha256": locked_ipk,
                }
            )
        )
