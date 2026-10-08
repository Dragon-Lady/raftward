import html
import json


def render(data, format):
    if format == "text" and set(data) == {"raftward.service", "raftward.timer"}:
        return "\n".join("# " + name + "\n" + value for name, value in data.items())
    value = json.dumps(data, ensure_ascii=True, indent=2, sort_keys=True)
    if format == "json":
        return value + "\n"
    if format == "html":
        return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Raft Ward</title><h1>Raft Ward</h1><pre>' + html.escape(value) + "</pre></html>\n"
    if format == "md":
        # HTML escape markup instead of placing untrusted names into Markdown fences.
        return "# Raft Ward\n\n<pre>" + html.escape(value) + "</pre>\n"
    return "Raft Ward\n" + value + "\n"
