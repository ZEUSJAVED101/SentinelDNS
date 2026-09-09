"""
SentinelDNS Filter Manager

Built-in filters remain code-defined. Custom filters are data-only
rules backed by managed blocklist files; no user-supplied Python,
expressions, templates, or executable content is loaded.
"""
from __future__ import annotations
import json
import os
import re
import tempfile
from pathlib import Path
from threading import RLock

from dns_engine.filters.adblock import AdBlockFilter
from dns_engine.filters.adult import AdultFilter
from dns_engine.filters.blacklist import BlacklistFilter
from dns_engine.filters.custom import CustomBlocklistFilter
from dns_engine.filters.malware import MalwareFilter
from dns_engine.filters.schedule import ScheduleFilter
from dns_engine.filters.whitelist import WhitelistFilter
from dns_engine.models import DNSQuery, FilterDecision


class FilterManager:
    DEFAULT_STATES = {
        "Whitelist": True,
        "Blacklist": True,
        "AdBlock": True,
        "Malware": True,
        "Adult": True,
        "Schedule": True,
    }
    BUILTIN_NAMES = frozenset(DEFAULT_STATES)
    NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,47}$")
    FILE_RE = re.compile(r"^custom_[a-z0-9][a-z0-9_-]{0,47}\.txt$")
    PROJECT_ROOT = Path(__file__).resolve().parents[2]
    STORE_PATH = PROJECT_ROOT / "data" / "custom_filters.json"
    _store_lock = RLock()

    def __init__(self) -> None:
        self.filters = [
            WhitelistFilter(), BlacklistFilter(), AdBlockFilter(),
            MalwareFilter(), AdultFilter(), ScheduleFilter(),
        ]
        self.enabled = dict(self.DEFAULT_STATES)
        self.custom_definitions: dict[str, dict[str, object]] = {}
        self._load_custom_filters()

    @staticmethod
    def _filter_name(dns_filter) -> str:
        if isinstance(dns_filter, CustomBlocklistFilter):
            return dns_filter.name
        name = dns_filter.__class__.__name__
        return name[:-6] if name.endswith("Filter") else name

    @classmethod
    def _validate_name(cls, name: str) -> str:
        if not isinstance(name, str):
            raise ValueError("Filter name must be text.")
        name = name.strip()
        if not cls.NAME_RE.fullmatch(name):
            raise ValueError("Filter name must be 1-48 characters and contain only letters, numbers, spaces, '_' or '-'.")
        if name in cls.BUILTIN_NAMES:
            raise ValueError("That name is reserved for a built-in filter.")
        return name

    @classmethod
    def _validate_filename(cls, filename: str) -> str:
        if not isinstance(filename, str) or not cls.FILE_RE.fullmatch(filename):
            raise ValueError("Invalid custom blocklist filename.")
        return filename

    @classmethod
    def _load_store(cls) -> list[dict[str, object]]:
        path = cls.STORE_PATH
        if not path.is_file():
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return []
        if not isinstance(raw, list):
            return []
        result = []
        for item in raw[:100]:
            if not isinstance(item, dict):
                continue
            try:
                name = cls._validate_name(item.get("name", ""))
                filename = cls._validate_filename(item.get("filename", ""))
                enabled = bool(item.get("enabled", True))
            except ValueError:
                continue
            result.append({"name": name, "filename": filename, "enabled": enabled})
        return result

    @classmethod
    def _save_store(cls, definitions: list[dict[str, object]]) -> None:
        cls.STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(definitions, ensure_ascii=True, indent=2) + "\n"
        with cls._store_lock:
            fd, temp_name = tempfile.mkstemp(prefix="custom_filters_", suffix=".tmp", dir=cls.STORE_PATH.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp_name, cls.STORE_PATH)
            finally:
                try:
                    os.unlink(temp_name)
                except FileNotFoundError:
                    pass

    def _load_custom_filters(self) -> None:
        self.custom_definitions = {}
        for item in self._load_store():
            name = str(item["name"])
            filename = str(item["filename"])
            self.custom_definitions[name] = dict(item)
            self.filters.append(CustomBlocklistFilter(name, filename))
            self.enabled[name] = bool(item["enabled"])

    def _persist(self) -> None:
        self._save_store(list(self.custom_definitions.values()))

    def _valid_names(self) -> set[str]:
        return {self._filter_name(dns_filter) for dns_filter in self.filters}

    def evaluate(self, query: DNSQuery) -> FilterDecision:
        for dns_filter in self.filters:
            name = self._filter_name(dns_filter)
            if not self.enabled.get(name, False):
                continue
            decision = dns_filter.evaluate(query)
            if not decision.allowed:
                return decision
        return FilterDecision(allowed=True)

    def set_enabled(self, name: str, enabled: bool) -> None:
        if name not in self._valid_names():
            raise ValueError(f"Unknown DNS filter: {name}")
        self.enabled[name] = bool(enabled)
        if name in self.custom_definitions:
            self.custom_definitions[name]["enabled"] = bool(enabled)
            self._persist()

    def is_enabled(self, name: str) -> bool:
        if name not in self._valid_names():
            raise ValueError(f"Unknown DNS filter: {name}")
        return bool(self.enabled.get(name, False))

    def status(self) -> list[dict[str, object]]:
        result = []
        for dns_filter in self.filters:
            name = self._filter_name(dns_filter)
            item = {"name": name, "enabled": self.is_enabled(name), "available": True}
            if isinstance(dns_filter, CustomBlocklistFilter):
                item["custom"] = True
                item["blocklist_filename"] = dns_filter.filename
                item["blocklist_size"] = dns_filter.blocklist.size
            else:
                item["custom"] = False
            result.append(item)
        return result

    def add_custom_filter(self, name: str, filename: str, enabled: bool = True) -> None:
        name = self._validate_name(name)
        filename = self._validate_filename(filename)
        if name in self._valid_names():
            raise ValueError("A filter with that name already exists.")
        if not (self.PROJECT_ROOT / "data" / "blocklists" / filename).is_file():
            raise ValueError("Custom blocklist does not exist.")
        definition = {"name": name, "filename": filename, "enabled": bool(enabled)}
        self.custom_definitions[name] = definition
        self.filters.append(CustomBlocklistFilter(name, filename))
        self.enabled[name] = bool(enabled)
        try:
            self._persist()
        except Exception:
            self.filters.pop()
            self.custom_definitions.pop(name, None)
            self.enabled.pop(name, None)
            raise

    def update_custom_filter(self, name: str, new_name: str | None = None, filename: str | None = None, enabled: bool | None = None) -> str:
        if name not in self.custom_definitions:
            raise ValueError("Custom filter not found.")
        target_name = self._validate_name(new_name) if new_name is not None else name
        target_filename = self._validate_filename(filename) if filename is not None else str(self.custom_definitions[name]["filename"])
        if not (self.PROJECT_ROOT / "data" / "blocklists" / target_filename).is_file():
            raise ValueError("Custom blocklist does not exist.")
        if target_name != name and target_name in self._valid_names():
            raise ValueError("A filter with that name already exists.")
        old_enabled = bool(self.enabled.get(name, False))
        target_enabled = old_enabled if enabled is None else bool(enabled)
        idx = next(i for i, f in enumerate(self.filters) if self._filter_name(f) == name)
        self.filters[idx] = CustomBlocklistFilter(target_name, target_filename)
        self.filters[idx].blocklist.reload()
        self.enabled.pop(name, None)
        self.enabled[target_name] = target_enabled
        definition = {"name": target_name, "filename": target_filename, "enabled": target_enabled}
        self.custom_definitions.pop(name, None)
        self.custom_definitions[target_name] = definition
        try:
            self._persist()
        except Exception:
            raise
        return target_name

    def remove_custom_filter(self, name: str) -> None:
        if name not in self.custom_definitions:
            raise ValueError("Custom filter not found.")
        self.filters = [f for f in self.filters if self._filter_name(f) != name]
        self.enabled.pop(name, None)
        self.custom_definitions.pop(name, None)
        self._persist()
