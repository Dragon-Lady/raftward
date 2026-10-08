import json
import os
from pathlib import Path

import pytest

from raftward import alerts
from raftward.safety import SafeError, Store


def test_aggregate_no_paths_secrets_and_dedupe(monkeypatch):
    store = Store(Path(os.environ["XDG_STATE_HOME"]) / "raftward")
    token = "gh" + "p_" + "CANARYVALUE" * 4
    monkeypatch.setenv("TEST_WEBHOOK", "https://hooks.example.invalid/" + token)
    cfg = {"alert_channels": ["slack"], "alert_slack_webhook_env": "TEST_WEBHOOK"}
    payloads = []
    monkeypatch.setattr(alerts, "post", lambda url, body, headers: payloads.append(body.decode()))
    findings = [{"rule": "RF-INTEGRITY", "severity": "critical", "entry": "/private/" + token}]
    assert alerts.deliver(cfg, store, findings, [], now=100)["delivered"] == ["slack"]
    assert alerts.deliver(cfg, store, findings, [], now=101)["deduped"] == ["slack"]
    assert len(payloads) == 1 and "RF-INTEGRITY" in payloads[0] and "critical=1" in payloads[0]
    assert "run `raftward report` locally for details" in payloads[0]
    assert token not in payloads[0] and "/private/" not in payloads[0]
    assert token not in (store.path / "alerts.json").read_text()


def test_network_error_not_echoed_or_persisted(monkeypatch):
    store = Store(Path(os.environ["XDG_STATE_HOME"]) / "raftward")
    def fail(*args):
        raise RuntimeError("PRIVATE-ERROR-CONTENT")
    monkeypatch.setattr(alerts, "send_one", fail)
    result = alerts.deliver({"alert_channels": ["ntfy"]}, store, [{"rule": "RF-MODE", "severity": "high", "entry": "a"}], [])
    assert result["failed"] == ["ntfy"]
    assert "PRIVATE-ERROR-CONTENT" not in json.dumps(result)


@pytest.mark.parametrize("url,ok", [("http://127.0.0.1:8000/topic", True), ("https://example.invalid/topic", True),
                                     ("http://example.invalid/topic", False), ("https://user:pass@example.invalid", False)])
def test_endpoints(url, ok):
    if ok:
        assert alerts.endpoint(url) == url
    else:
        with pytest.raises(SafeError):
            alerts.endpoint(url)
