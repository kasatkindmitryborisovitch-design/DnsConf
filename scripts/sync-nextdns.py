#!/usr/bin/env python3
"""Plan and apply managed rewrites for the DnsConf NextDNS profile."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import struct
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "https://raw.githubusercontent.com/Internet-Helper/GeoHideDNS/refs/heads/main/hosts/hosts"
MANAGED = {
    "chatgpt.com": "/",
    "ab.chatgpt.com": "/",
    "api.openai.com": "/v1/models",
    "auth.openai.com": "/",
    "platform.openai.com": "/",
    "oaistatic.com": "/",
    "cdn.oaistatic.com": "/",
    "oaiusercontent.com": "/",
    "files.oaiusercontent.com": "/",
    "claude.ai": "/",
    "api.claude.ai": "/",
    "api.anthropic.com": "/v1/models",
    "anthropic.com": "/",
}
VERIFY = ("chatgpt.com", "api.openai.com", "claude.ai", "api.anthropic.com")
# Fixed migration scope. Re-running this action cannot remove another batch.
APPROVED_DISCORD = tuple(f"finland{i}.discord.media" for i in range(10167, 10200))
LEGACY_DISCORD_IP = "104.25.158.178"
LIMIT = 500
TARGET = 480
TLS = ssl.create_default_context()


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


HTTP = build_opener(NoRedirect())


def read(request, retry=True, maximum=1_000_000):
    for attempt in range(3 if retry else 1):
        try:
            with HTTP.open(request, timeout=12) as response:
                content = response.read(maximum + 1)
            if len(content) > maximum:
                raise RuntimeError("Response exceeds size limit")
            return content
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            status = getattr(error, "code", None)
            if not retry or attempt == 2 or status not in (None, 429, 500, 502, 503, 504):
                raise RuntimeError(f"HTTP request failed ({status or type(error).__name__})") from None
            time.sleep(2 ** attempt)


class NextDNS:
    def __init__(self):
        self.profile = os.environ["CLIENT_ID"].strip()
        if not re.fullmatch("[a-z0-9]{6}", self.profile):
            raise RuntimeError("Expected one NextDNS profile ID")
        self.url = f"https://api.nextdns.io/profiles/{self.profile}/rewrites"
        self.key = os.environ["AUTH_SECRET"].strip()
        if not self.key:
            raise RuntimeError("Missing NextDNS API key")

    def request(self, method, suffix="", payload=None):
        data = None if payload is None else json.dumps(payload).encode()
        request = Request(self.url + suffix, data=data, method=method, headers={
            "X-Api-Key": self.key, "Content-Type": "application/json",
        })
        body = read(request, retry=method == "GET")
        result = json.loads(body) if body else {}
        if result.get("errors"):
            raise RuntimeError("NextDNS returned errors")
        return result

    def entries(self):
        result = self.request("GET")
        if (result.get("meta") or {}).get("pagination", {}).get("cursor"):
            raise RuntimeError("NextDNS returned a partial rewrite list")
        rows = {}
        for entry in result["data"]:
            name = entry["name"].lower().rstrip(".")
            if name in rows:
                raise RuntimeError("Duplicate rewrite names; review the profile")
            rows[name] = {"id": entry["id"], "content": entry["content"]}
        return rows

    def delete(self, entry):
        self.request("DELETE", "/" + quote(str(entry["id"]), safe=""))

    def add(self, name, content):
        self.request("POST", payload={"name": name, "content": content})


def hosts(content):
    found = {name: [] for name in MANAGED}
    for line in content.splitlines():
        fields = line.partition("#")[0].split()
        if len(fields) < 2:
            continue
        try:
            address = ipaddress.IPv4Address(fields[0])
        except ValueError:
            continue
        if not address.is_global or address.is_multicast:
            continue
        for name in fields[1:]:
            ips = found.get(name.lower().rstrip("."))
            if ips is not None and str(address) not in ips:
                ips.append(str(address))
    return found


def probe(pair):
    name, address = pair
    client = http.client.HTTPSConnection(name, context=TLS, timeout=4)
    client._create_connection = lambda *_args, **_kwargs: socket.create_connection((address, 443), 4)
    try:
        client.request("GET", MANAGED[name], headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
        status = client.getresponse().status
        if 200 <= status < 400 or status == 401:
            return 2
        # Cloud providers can return an edge challenge to an unauthenticated probe.
        if status in (403, 405, 429):
            return 1
    except (OSError, http.client.HTTPException):
        pass
    finally:
        client.close()
    return 0


def choose(previous, candidates, preferred):
    jobs = [(name, ip) for name, ips in candidates.items() for ip in ips[:8]]
    with ThreadPoolExecutor(max_workers=12) as pool:
        scores = dict(zip(jobs, pool.map(probe, jobs)))
    chosen = {}
    limited = []
    unreachable = []
    for name, ips in candidates.items():
        if not ips:
            unreachable.append(name)
            continue
        previous_ip = previous.get(name)
        ordered = list(dict.fromkeys([previous_ip, *preferred[name], *ips]))
        ranked = [ip for ip in ordered if scores.get((name, ip), 0) == 2]
        if not ranked:
            ranked = [ip for ip in ordered if scores.get((name, ip), 0) == 1]
            if ranked:
                limited.append(name)
        if not ranked:
            unreachable.append(name)
            continue
        chosen[name] = ranked[0]
    return chosen, limited, unreachable


def content_map(rows):
    return {name: row["content"] for name, row in rows.items()}


def make_plan(before, chosen, allow_retire):
    target = before | chosen
    candidates = [name for name in APPROVED_DISCORD if before.get(name) == LEGACY_DISCORD_IP]
    slots = max(0, len(target) - TARGET)
    retired = candidates[-slots:] if slots and allow_retire else []
    for name in retired:
        del target[name]
    return target, retired, len(target) <= TARGET


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def reconcile(api, current, target):
    existing = content_map(current)
    for name in sorted(existing.keys() - target.keys()):
        api.delete(current[name])
    for name, ip in sorted(target.items()):
        if name in existing and existing[name] != ip:
            api.delete(current[name])
            api.add(name, ip)
        elif name not in existing:
            api.add(name, ip)


def resolved(profile, name):
    query_id = os.urandom(2)
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    query = query_id + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0) + labels + b"\0\0\x01\0\x01"
    encoded = base64.urlsafe_b64encode(query).decode().rstrip("=")
    request = Request(f"https://dns.nextdns.io/{profile}?dns={encoded}", headers={
        "Accept": "application/dns-message",
    })
    data = read(request, maximum=65535)
    if len(data) < 12 or data[:2] != query_id:
        raise RuntimeError("Malformed DoH answer")
    flags, questions, answers = struct.unpack_from("!HHH", data, 2)
    if flags & 0x000F or not flags & 0x8000:
        raise RuntimeError("NextDNS did not resolve the verification query")

    def skip_name(offset):
        while data[offset] != 0:
            length = data[offset]
            if length & 0xC0 == 0xC0:
                return offset + 2
            if length > 63:
                raise RuntimeError("Invalid DNS label")
            offset += length + 1
        return offset + 1

    offset = 12
    for _ in range(questions):
        offset = skip_name(offset) + 4
    addresses = set()
    for _ in range(answers):
        offset = skip_name(offset)
        typ, cls, _, size = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if typ == 1 and cls == 1 and size == 4:
            addresses.add(str(ipaddress.IPv4Address(data[offset:offset + size])))
        offset += size
    return addresses


def check(api, target, chosen):
    for attempt in range(4):
        try:
            if content_map(api.entries()) != target:
                raise RuntimeError("NextDNS rewrite list differs from the applied plan")
            for name in VERIFY:
                if chosen[name] not in resolved(api.profile, name):
                    raise RuntimeError(f"NextDNS did not return the planned address for {name}")
            return
        except RuntimeError:
            if attempt == 3:
                raise
            time.sleep(4)


def cleanup_target(before):
    conflicts = [name for name in APPROVED_DISCORD
                 if name in before and before[name] != LEGACY_DISCORD_IP]
    if conflicts:
        raise RuntimeError("At least one approved Discord entry changed IP; inspect before removal")
    return {name: ip for name, ip in before.items() if name not in APPROVED_DISCORD}


def apply(api, plan):
    cleanup = plan.get("cleanup_discord_only", False)
    before, target = plan["before"], plan["target"]
    if cleanup and target != cleanup_target(before):
        raise RuntimeError("Discord cleanup is outside the fixed scope")
    if not cleanup and set(plan["chosen"]) != MANAGED.keys():
        raise RuntimeError("Some managed domains have no verified candidate; profile was left intact")
    if not plan["fits"]:
        raise RuntimeError(f'Plan has {len(plan["target"])} rules; maximum with reserve is {TARGET}')
    current = api.entries()
    if content_map(current) != before:
        raise RuntimeError("Profile changed since planning; regenerate the plan")
    try:
        reconcile(api, current, target)
        if cleanup:
            if content_map(api.entries()) != target:
                raise RuntimeError("NextDNS rewrite list differs from the cleanup plan")
        else:
            check(api, target, plan["chosen"])
    except Exception:
        # Restore only the affected names, keeping unrelated concurrent changes.
        affected = {name for name in before.keys() | target.keys() if before.get(name) != target.get(name)}
        actual = api.entries()
        rollback = {name: ip for name, ip in content_map(actual).items() if name not in affected}
        rollback.update({name: ip for name, ip in before.items() if name in affected})
        reconcile(api, actual, rollback)
        if content_map(api.entries()) != rollback:
            raise RuntimeError("Rollback could not be verified; encrypted backup is available") from None
        print("Restored the previous rewrite values after a failed application", flush=True)
        raise
    if cleanup:
        print(f"Verified {len(before) - len(target)} Discord removals; {len(target)}/{LIMIT} rules remain", flush=True)
    else:
        print(f"Verified {len(target)} NextDNS rewrites and four live DNS answers", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("plan", "apply"))
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--retire-legacy-discord", action="store_true")
    parser.add_argument("--cleanup-discord-only", action="store_true")
    args = parser.parse_args()
    api = NextDNS()
    if args.mode == "apply":
        apply(api, json.loads(args.file.read_text()))
        return
    before = content_map(api.entries())
    if args.cleanup_discord_only:
        target = cleanup_target(before)
        removed = sorted(before.keys() - target.keys())
        save_json(args.file, {"before": before, "target": target, "chosen": {}, "retired": removed,
                              "fits": len(target) <= LIMIT, "cleanup_discord_only": True})
        print(f"Discord cleanup plan: {len(removed)} named legacy rules; {len(target)}/{LIMIT} rules after cleanup")
        return
    source = read(Request(SOURCE)).decode()
    candidates = hosts(source)
    preferred = hosts((ROOT / "hosts/openai-preferred.hosts").read_text())
    chosen, limited, unreachable = choose(before, candidates, preferred)
    # Estimate capacity for every intended name, even when its candidate could not be verified.
    pending = {name: before.get(name, "candidate pending") for name in unreachable}
    target, retired, fits = make_plan(before, pending | chosen, args.retire_legacy_discord)
    save_json(args.file, {"before": before, "target": target, "chosen": chosen, "retired": retired, "fits": fits})
    print(f"NextDNS before: {len(before)}/{LIMIT}. Planned: {len(target)}/{LIMIT}. Reserve target: {LIMIT - TARGET}.")
    print(f"Managed: {len(MANAGED)}. New: {len(MANAGED.keys() - before.keys())}. Legacy Discord to retire: {len(retired)}.")
    if unreachable:
        print("No verified HTTPS candidate for: " + ", ".join(unreachable))
    if limited:
        print("TLS reachable, but HTTPS application access inconclusive: " + ", ".join(limited))
    if not fits:
        print("The plan needs more capacity before an apply run is possible.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, ValueError, KeyError, OSError) as error:
        raise SystemExit(str(error)) from None
