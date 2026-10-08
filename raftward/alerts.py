"""Aggregate alerts, matching Net Ward channel names; never send inventory."""
from collections import Counter
from email.message import EmailMessage
import json
import os
import smtplib
import ssl
import time
from urllib.parse import quote, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

from .audit import RULES
from .safety import SafeError, fingerprint


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def endpoint(value):
    parsed = urlsplit(value)
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise SafeError("invalid alert endpoint")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise SafeError("alert endpoint must use HTTPS except on loopback")
    return value


def env_secret(cfg, field):
    name = cfg.get(field)
    if not isinstance(name, str) or not os.environ.get(name):
        raise SafeError("alert credential environment variable is missing")
    return os.environ[name]


def summary(findings, diff):
    counts = Counter(f["rule"] for f in findings if f.get("rule") in RULES)
    severities = Counter(f["severity"] for f in findings if f.get("severity") in {"info", "warn", "high", "critical"})
    detail = ", ".join(f"{rule}={counts[rule]}" for rule in sorted(counts)) or "no new findings"
    severity = ", ".join(f"{key}={severities[key]}" for key in sorted(severities))
    if any(f.get("rule") == "RF-DEFERRED" and f.get("reason") == "transfer-running" for f in findings):
        detail += "; transfer-running: configured transfers, including persistent mounts/daemons, keep checks deferred"
    return f"Raft Ward: {detail}; changes={len(diff)}; {severity or 'severity=none'}. run `raftward report` locally for details"


def post(url, body, headers):
    request = Request(endpoint(url), data=body, headers=headers, method="POST")
    with build_opener(NoRedirect).open(request, timeout=5) as response:
        response.read(1024)


def send_one(channel, cfg, message):
    if channel == "stdout":
        return  # Returned as structured output by CLI, never mixed into JSON.
    if channel == "slack":
        url = env_secret(cfg, "alert_slack_webhook_env")
        post(url, json.dumps({"text": message}).encode(), {"Content-Type": "application/json"})
    elif channel == "ntfy":
        topic = cfg.get("alert_ntfy_topic", "")
        if not topic:
            raise SafeError("ntfy topic missing")
        url = topic if "://" in topic else "https://ntfy.sh/" + quote(topic, safe="")
        headers = {"Content-Type": "text/plain; charset=utf-8"}
        if cfg.get("alert_ntfy_token_env"):
            headers["Authorization"] = "Bearer " + env_secret(cfg, "alert_ntfy_token_env")
        post(url, message.encode(), headers)
    elif channel == "email":
        host = cfg.get("alert_smtp_host", "")
        security = cfg.get("alert_smtp_security", "starttls")
        if security not in {"ssl", "starttls", "none"} or not host:
            raise SafeError("invalid SMTP configuration")
        if security == "none" and host not in {"localhost", "127.0.0.1", "::1"}:
            raise SafeError("SMTP encryption is required off loopback")
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = cfg["alert_smtp_from"], cfg["alert_email"], "Raft Ward aggregate alert"
        msg.set_content(message)
        client = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP
        kwargs = {"context": ssl.create_default_context()} if security == "ssl" else {}
        with client(host, int(cfg.get("alert_smtp_port", 465 if security == "ssl" else 587)), timeout=5, **kwargs) as smtp:
            if security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if cfg.get("alert_smtp_username"):
                smtp.login(cfg["alert_smtp_username"], env_secret(cfg, "alert_smtp_password_env"))
            smtp.send_message(msg)
    else:
        raise SafeError("unsupported alert channel")


def deliver(cfg, store, findings, diff, now=None):
    now = time.time() if now is None else now
    channels = cfg.get("alert_channels") or ["stdout"]
    if any(c not in {"stdout", "slack", "ntfy", "email"} for c in channels) or len(channels) != len(set(channels)):
        raise SafeError("invalid alert_channels")
    receipts = store.read("alerts.json", {})
    receipts = {k: v for k, v in receipts.items() if isinstance(v, (int, float)) and now - v < 86400}
    result = {"delivered": [], "failed": [], "deduped": [], "messages": []}
    for channel in channels:
        destination = {k: v for k, v in cfg.items() if k.startswith("alert_")}
        # A rotated webhook should get a fresh receipt, never be written in state.
        for k in list(destination):
            if k.endswith("_env"):
                destination[k] = os.environ.get(str(destination[k]), "")
        prefix = fingerprint(store.key, json.dumps([channel, destination], sort_keys=True))
        new_f, new_d, keys = [], [], []
        for item, collection in [(f, new_f) for f in findings] + [(d, new_d) for d in diff]:
            identity = [prefix, item.get("rule", "change"), item.get("entry"), item.get("change")]
            key = fingerprint(store.key, json.dumps(identity))
            if key not in receipts:
                keys.append(key)
                collection.append(item)
        if not keys:
            result["deduped"].append(channel)
            continue
        message = summary(new_f, new_d)
        try:
            send_one(channel, cfg, message)
        except Exception:
            # Network libraries' exceptions may contain credential-bearing URLs.
            result["failed"].append(channel)
        else:
            result["delivered"].append(channel)
            if channel == "stdout":
                result["messages"].append(message)
            receipts.update({key: now for key in keys})
    store.save("alerts.json", receipts)
    return result
