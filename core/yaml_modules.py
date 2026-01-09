"""
YAML Module System - Parse and execute YAML-based security modules.
Inspired by Nuclei templates and sif's YAML module system.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .module import Finding, ModuleInfo, ModuleResult, ModuleType, Severity


@dataclass
class Matcher:
    """Defines matching logic for module responses"""
    type: str  # status, word, regex
    part: str = "body"  # body, header, all
    status: list[int] = field(default_factory=list)
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    condition: str = "and"  # and, or
    negative: bool = False


@dataclass
class Extractor:
    """Defines data extraction from responses"""
    type: str  # regex, json, kval
    name: str
    part: str = "body"
    regex: list[str] = field(default_factory=list)
    group: int = 0


@dataclass
class HTTPConfig:
    """HTTP module configuration"""
    method: str = "GET"
    paths: list[str] = field(default_factory=list)
    payloads: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    threads: int = 10
    matchers: list[Matcher] = field(default_factory=list)
    extractors: list[Extractor] = field(default_factory=list)


@dataclass
class YAMLModule:
    """Parsed YAML module definition"""
    id: str
    name: str
    author: str = "webcross"
    severity: Severity = Severity.INFO
    description: str = ""
    tags: list[str] = field(default_factory=list)
    module_type: ModuleType = ModuleType.HTTP
    http: HTTPConfig | None = None

    def info(self) -> ModuleInfo:
        return ModuleInfo(
            id=self.id,
            name=self.name,
            author=self.author,
            severity=self.severity,
            description=self.description,
            tags=self.tags,
        )


def load_yaml_module(path: str | Path) -> YAMLModule:
    """
    Parse a YAML file into a module definition.
    
    Args:
        path: Path to YAML module file
        
    Returns:
        Parsed YAMLModule
        
    Raises:
        ValueError: If required fields are missing
    """
    path = Path(path)
    with open(path) as f:
        data = yaml.safe_load(f)

    # Validate required fields
    if not data.get("id"):
        raise ValueError(f"Module missing required field: id ({path})")

    # Parse info section
    info = data.get("info", {})
    severity_str = info.get("severity", "info").lower()
    try:
        severity = Severity(severity_str)
    except ValueError:
        severity = Severity.INFO

    # Parse module type
    type_str = data.get("type", "http").lower()
    try:
        module_type = ModuleType(type_str)
    except ValueError:
        module_type = ModuleType.HTTP

    # Parse HTTP config if present
    http_config = None
    if data.get("http"):
        http_data = data["http"]
        matchers = []
        for m in http_data.get("matchers", []):
            matchers.append(Matcher(
                type=m.get("type", "word"),
                part=m.get("part", "body"),
                status=m.get("status", []),
                words=m.get("words", []),
                regex=m.get("regex", []),
                condition=m.get("condition", "and"),
                negative=m.get("negative", False),
            ))

        extractors = []
        for e in http_data.get("extractors", []):
            extractors.append(Extractor(
                type=e.get("type", "regex"),
                name=e.get("name", ""),
                part=e.get("part", "body"),
                regex=e.get("regex", []),
                group=e.get("group", 0),
            ))

        http_config = HTTPConfig(
            method=http_data.get("method", "GET"),
            paths=http_data.get("paths", []),
            payloads=http_data.get("payloads", []),
            headers=http_data.get("headers", {}),
            body=http_data.get("body", ""),
            threads=http_data.get("threads", 10),
            matchers=matchers,
            extractors=extractors,
        )

    return YAMLModule(
        id=data["id"],
        name=info.get("name", data["id"]),
        author=info.get("author", "webcross"),
        severity=severity,
        description=info.get("description", ""),
        tags=info.get("tags", []),
        module_type=module_type,
        http=http_config,
    )


def substitute_variables(template: str, base_url: str, payload: str = "") -> str:
    """
    Replace template variables in a string.
    
    Supported variables:
    - {{BaseURL}} / {{baseurl}} - Target base URL
    - {{Payload}} / {{payload}} - Current payload
    """
    result = template
    result = result.replace("{{BaseURL}}", base_url)
    result = result.replace("{{baseurl}}", base_url)
    result = result.replace("{{Payload}}", payload)
    result = result.replace("{{payload}}", payload)
    return result


def get_response_part(part: str, headers: dict[str, str], body: str) -> str:
    """Extract the relevant part of a response for matching"""
    if part in ("header", "headers"):
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    elif part == "body":
        return body
    else:  # "all" or default
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        return f"{header_str}\n\n{body}"


def check_matcher(
    matcher: Matcher,
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> bool:
    """Evaluate a single matcher against response data"""
    if matcher.type == "status":
        result = status_code in matcher.status
    elif matcher.type == "word":
        content = get_response_part(matcher.part, headers, body)
        if matcher.condition == "or":
            result = any(word in content for word in matcher.words)
        else:  # and
            result = all(word in content for word in matcher.words)
    elif matcher.type == "regex":
        content = get_response_part(matcher.part, headers, body)
        if matcher.condition == "or":
            result = any(
                re.search(pattern, content) is not None
                for pattern in matcher.regex
            )
        else:  # and
            result = all(
                re.search(pattern, content) is not None
                for pattern in matcher.regex
            )
    else:
        result = False

    return not result if matcher.negative else result


def check_matchers(
    matchers: list[Matcher],
    status_code: int,
    headers: dict[str, str],
    body: str,
) -> bool:
    """Evaluate all matchers (AND logic across matchers)"""
    if not matchers:
        return False

    for matcher in matchers:
        if not check_matcher(matcher, status_code, headers, body):
            return False
    return True


def run_extractors(
    extractors: list[Extractor],
    headers: dict[str, str],
    body: str,
) -> dict[str, str]:
    """Extract data from response using extractors"""
    if not extractors:
        return {}

    result: dict[str, str] = {}
    for extractor in extractors:
        content = get_response_part(extractor.part, headers, body)

        if extractor.type == "regex":
            for pattern in extractor.regex:
                match = re.search(pattern, content)
                if match:
                    if extractor.group <= len(match.groups()):
                        result[extractor.name] = match.group(extractor.group)
                    else:
                        result[extractor.name] = match.group(0)
                    break

    return result


def truncate_evidence(text: str, max_len: int = 500) -> str:
    """Truncate evidence text for storage"""
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def load_yaml_modules_from_dir(directory: str | Path) -> list[YAMLModule]:
    """Load all YAML modules from a directory"""
    directory = Path(directory)
    modules = []

    if not directory.exists():
        return modules

    for path in directory.glob("*.yaml"):
        try:
            module = load_yaml_module(path)
            modules.append(module)
        except Exception:
            # Skip invalid modules
            continue

    for path in directory.glob("*.yml"):
        try:
            module = load_yaml_module(path)
            modules.append(module)
        except Exception:
            continue

    return modules
