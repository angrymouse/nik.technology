"""Redact Telegram identities from the static public research artifacts."""

import csv
import gzip
import io
import json
import re
from pathlib import Path


GROUP_ID = "2282015815"
HANDLE = re.compile(r"(?<![A-Za-z0-9_])@[A-Za-z][A-Za-z0-9_]{2,}")
ACCOUNT_KEY = re.compile(r"(?<![A-Za-z0-9_])(?:user|bot|channel):\d+\b")
HOME_PATH = "/home/nik/entryliquidity/analysis/ayugram-token-strategy"
TEXT_SUFFIXES = {".html", ".json", ".csv", ".md", ".py", ".svg"}


class PublicationPrivacy:
    def __init__(self, source: Path, files: set[Path]):
        self.aliases = {}
        self.next_number = 1
        snapshots = sorted(path for path in files if path.name == "caller_snapshot.csv")
        for path in snapshots:
            with path.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            ranked = [row for row in rows if row["identity"] == "requester"
                      and float(row["count"]) >= 10
                      and "(bot)" not in row["callerLabel"].lower()]
            ranked.sort(key=lambda row: float(row["excess"]), reverse=True)
            for row in ranked:
                self._pair(row["callerKey"], row["callerLabel"])
            for row in rows:
                self._pair(row["callerKey"], row["callerLabel"])
        for path in sorted(files):
            if path.name == "attribution.json":
                data = json.loads(path.read_text())
                for key, label in sorted(data.get("labels", {}).items()):
                    self._pair(key, label)
            elif path.name == "versions.json" and "live_message_captures" in path.parts:
                data = json.loads(path.read_text())
                for version in data.get("versions", []):
                    author = version.get("author") or {}
                    self._pair(author.get("key"), author.get("label"))

    @staticmethod
    def _key(value):
        return value.lower() if value.startswith("@") else value

    def _alias(self, value):
        key = self._key(value)
        if key not in self.aliases:
            self.aliases[key] = f"Caller {self.next_number:02d}"
            self.next_number += 1
        return self.aliases[key]

    def _pair(self, key, label):
        if not key or not label:
            return
        handle = HANDLE.search(label)
        label_key = self._key(handle.group() if handle else label)
        key_key = self._key(key)
        alias = self.aliases.get(key_key) or self.aliases.get(label_key)
        if alias is None:
            alias = self._alias(key)
        self.aliases[key_key] = alias
        self.aliases[label_key] = alias

    def _sanitize_text(self, text):
        text = text.replace(HOME_PATH, "research")
        text = text.replace("-100" + GROUP_ID, "0")
        text = text.replace("−100" + GROUP_ID, "the source group")
        text = text.replace(GROUP_ID, "0")
        text = ACCOUNT_KEY.sub(lambda match: self._alias(match.group()), text)
        text = HANDLE.sub(lambda match: self._alias(match.group()), text)
        if (GROUP_ID in text or "/home/nik/" in text or "entryliquidity" in text.lower()
                or ACCOUNT_KEY.search(text) or HANDLE.search(text)):
            raise ValueError("Direct Telegram or local identity remained in public artifact")
        return text.replace("\r\n", "\n")

    @staticmethod
    def _redact_message_versions(content):
        data = json.loads(content)
        for version in data.get("versions", []):
            version["text"] = "[message text redacted for publication]"
            version["entities"] = []
        data["publicationRedaction"] = "Message text and entities removed; source hashes refer to private originals."
        return json.dumps(data, ensure_ascii=False, indent=2) + "\n"

    @staticmethod
    def _omit_automated_rankings(content):
        reader = csv.DictReader(io.StringIO(content))
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=reader.fieldnames, lineterminator="\n")
        writer.writeheader()
        for row in reader:
            if "(bot)" not in " ".join(row.values()).lower():
                writer.writerow(row)
        return output.getvalue()

    def transform(self, path: Path, content: bytes):
        if path.suffix == ".gz":
            with gzip.GzipFile(fileobj=io.BytesIO(content)) as stream:
                for line in stream:
                    if any(needle in line for needle in (GROUP_ID.encode(), b"/home/nik/", b"user:", b"bot:", b"channel:", b"@")):
                        decoded = line.decode("utf-8")
                        if (GROUP_ID in decoded or "/home/nik/" in decoded or
                                ACCOUNT_KEY.search(decoded) or HANDLE.search(decoded)):
                            raise ValueError(f"Identifier in compressed public artifact: {path}")
            return content
        if path.suffix not in TEXT_SUFFIXES:
            return content
        text = content.decode("utf-8")
        if path.name == "versions.json" and "live_message_captures" in path.parts:
            text = self._redact_message_versions(text)
        if path.name in {"caller_snapshot.csv", "caller_ranking.csv"}:
            text = self._omit_automated_rankings(text)
        return self._sanitize_text(text).encode("utf-8")
