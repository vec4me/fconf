"""Parse standard DNS zone files and Cloudflare comment annotations."""

from __future__ import annotations

import json
import pathlib
import shlex
from typing import Any, cast
import dns.rdatatype
import dns.zone


def readZoneLines(path: pathlib.Path, included: set[pathlib.Path] | None = None) -> list[tuple[pathlib.Path, str]]:
    """Return zone lines with local include directives expanded."""
    resolved = path.resolve()
    visited = set() if included is None else included
    if resolved in visited:
        raise ValueError(f"{path}: recursive zone include")
    visited.add(resolved)
    lines: list[tuple[pathlib.Path, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("$INCLUDE"):
            words = shlex.split(stripped)
            if len(words) != 2:
                raise ValueError(f"{path}: include must contain exactly one path: {line}")
            lines.extend(readZoneLines(path.parent / words[1], visited))
            continue
        lines.append((path, line))
    visited.remove(resolved)
    return lines


def readAnnotations(path: pathlib.Path) -> dict[str, object]:
    """Return Cloudflare relationships declared by whole-line zone comments."""
    annotations: dict[str, object] = {"settings": {}}
    for sourcepath, line in readZoneLines(path):
        stripped = line.strip()
        if not stripped.startswith("; cloudflare "):
            continue
        declaration = stripped[len("; cloudflare "):]
        if declaration.startswith("setting "):
            assignment = declaration[len("setting "):]
            key, separator, source = assignment.partition("=")
            if not separator or not key or not source:
                raise ValueError(f"{sourcepath}: invalid Cloudflare setting: {line}")
            try:
                value = json.loads(source)
            except json.JSONDecodeError:
                value = source
            cast("dict[str, object]", annotations["settings"])[key] = value
            continue
        words = shlex.split(declaration)
        if words and words[0] == "redirect":
            if len(words) != 4 or words[1] not in {"301", "302", "307", "308"}:
                raise ValueError(f"{sourcepath}: invalid Cloudflare redirect: {line}")
            redirects = cast("list[tuple[int, str, str]]", annotations.setdefault("redirect_rules", []))
            redirects.append((int(words[1]), words[2], words[3]))
            continue
        if len(words) != 2:
            raise ValueError(f"{sourcepath}: invalid Cloudflare annotation: {line}")
        relationship, value = words
        if relationship in {"page-domain", "route", "worker-domain"}:
            values = cast("list[str]", annotations.setdefault(f"{relationship.replace('-', '_')}s", []))
            values.append(value)
            continue
        normalized = relationship.replace("-", "_")
        annotations[normalized] = value
    return annotations


def readProxiedRecords(path: pathlib.Path, origin: str) -> set[tuple[str, str, str]]:
    """Return the identities of records carrying an inline proxy annotation."""
    marker = "; cloudflare proxied"
    proxied: set[tuple[str, str, str]] = set()
    for _sourcepath, line in readZoneLines(path):
        source, separator, annotation = line.partition(";")
        if not separator or f";{annotation}".strip() != marker:
            continue
        zone = dns.zone.from_text(source, origin=origin, relativize=True, check_origin=False, allow_include=False)
        for dnsname, node in zone.nodes.items():
            name = dnsname.to_text() or "@"
            for rdataset in node.rdatasets:
                recordtype = dns.rdatatype.to_text(rdataset.rdtype)
                for rdata in rdataset:
                    proxied.add((name, recordtype, rdata.to_text()))
    return proxied


def readRecords(path: pathlib.Path, origin: str) -> list[dict[str, object]]:
    """Return normalized DNS records from a zone file."""
    text = "\n".join(line for _sourcepath, line in readZoneLines(path))
    zone = dns.zone.from_text(text, origin=origin, relativize=True, check_origin=False, allow_include=False)
    proxied = readProxiedRecords(path, origin)
    records: list[dict[str, object]] = []
    for dnsname, node in zone.nodes.items():
        name = dnsname.to_text() or "@"
        for rdataset in node.rdatasets:
            recordtype = dns.rdatatype.to_text(rdataset.rdtype)
            for rdata in rdataset:
                record: dict[str, object] = {
                    "name": name,
                    "type": recordtype,
                    "ttl": rdataset.ttl,
                    "proxied": (name, recordtype, rdata.to_text()) in proxied,
                }
                if recordtype == "MX":
                    record["priority"] = cast("Any", rdata).preference
                    record["content"] = cast("Any", rdata).exchange.to_text().rstrip(".")
                elif recordtype == "SRV":
                    record["priority"] = cast("Any", rdata).priority
                    record["weight"] = cast("Any", rdata).weight
                    record["port"] = cast("Any", rdata).port
                    target = cast("Any", rdata).target
                    record["target"] = target.to_text().rstrip(".") if target.is_absolute() else f"{target.to_text()}.{origin}"
                else:
                    record["content"] = rdata.to_text().rstrip(".")
                records.append(record)
    return records
