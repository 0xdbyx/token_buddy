#!/usr/bin/env python3
"""Token Buddy.

Reversibly tokenises sensitive values in UTF-8 CSV files while keeping the
local token map separate from the sanitised output.

Custom terms are literal, case-insensitive substring matches. This is
intentional: a term such as ``example`` is redacted in ``un_example_001``,
``-example``, and ``examplewifi``.

The script performs no network activity and uses only the Python standard
library.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Match, Optional, Pattern, Tuple

# Recognises placeholders created by this script, for example <<IP_0001>>.
TOKEN_RE = re.compile(r"<<([A-Z0-9_]+)_([0-9]{4,})>>")

BANNER = r"""
 _____ ___  _  _______ _   _   ____  _   _ ____  ______ __
|_   _/ _ \| |/ / ____| \ | | | __ )| | | |  _ \|  _ \ \ / /
  | || | | | ' /|  _| |  \| | |  _ \| | | | | | | | | \ V /
  | || |_| | . \| |___| |\  | | |_) | |_| | |_| | |_| || |
  |_| \___/|_|\_\_____|_| \_| |____/ \___/|____/|____/ |_|
"""

TOKEN_TYPES = ("IP", "IPV6", "CIDR", "FQDN", "KEYWORD")
TOKEN_TYPE_SET = frozenset(TOKEN_TYPES)

# Tenable reference/advisory URLs remain exactly as exported.
SEE_ALSO_COLUMN = "see also"

# Inline matching is deliberately limited to high-confidence contexts. The
# script does not run a broad FQDN/IPv6 search over arbitrary prose because
# filenames and programming syntax can look identical to those identifiers.
FQDN_CANDIDATE = (
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)

INLINE_IPV4_CIDR_RE = re.compile(
    r"(?<![\w.])(?P<value>(?:\d{1,3}\.){3}\d{1,3}/\d{1,2})(?![\w/.])"
)
INLINE_IPV4_RE = re.compile(
    r"(?<![\w.])(?P<value>(?:\d{1,3}\.){3}\d{1,3})(?![\w./])"
)
URL_HOST_RE = re.compile(
    rf"(?i)(?P<prefix>\b(?:https?|ftp)://)"
    rf"(?P<host>\[(?:[A-Fa-f0-9:.]+)\]|(?:\d{{1,3}}\.){{3}}\d{{1,3}}|{FQDN_CANDIDATE})"
    r"(?=[:/?#\s,;\"'<>)]|$)"
)
RESOLVES_FQDN_RE = re.compile(
    rf"(?i)(?P<prefix>\b(?:resolves\s+(?:as|to)\s+))"
    rf"(?P<host>{FQDN_CANDIDATE})(?![\w-]|\.(?=[A-Za-z0-9-]))"
)
LABELLED_IDENTIFIER_RE = re.compile(
    r"(?im)(?P<prefix>^\s*(?:ipv6\s+address|ipv4\s+address|ip\s+address|"
    r"fqdn|dns\s+name|hostname)\s*[:=]\s*)(?P<value>[^\s,;]+)"
)


def fail(message: str, code: int = 1) -> None:
    """Exit without printing source CSV content."""
    print(f"Error: {message}", file=sys.stderr)
    raise SystemExit(code)


@dataclass
class TokenMap:
    """Local reversible mapping between original values and placeholders."""

    by_type: Dict[str, Dict[str, str]] = field(
        default_factory=lambda: {token_type: {} for token_type in TOKEN_TYPES}
    )
    by_token: Dict[str, str] = field(default_factory=dict)
    counters: Dict[str, int] = field(
        default_factory=lambda: {token_type: 0 for token_type in TOKEN_TYPES}
    )

    @classmethod
    def new(cls) -> "TokenMap":
        return cls()

    @classmethod
    def load(cls, path: Path) -> "TokenMap":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            fail("token map must be UTF-8 JSON")
        except json.JSONDecodeError:
            fail("token map is not valid JSON")
        except OSError:
            fail("unable to read token map")

        if not isinstance(data, dict):
            fail("token map has invalid structure")

        mappings = data.get("mappings")
        counters = data.get("counters")
        if not isinstance(mappings, dict) or not isinstance(counters, dict):
            fail("token map has invalid structure")

        legacy_types = {"IP", "IPV6", "CIDR", "FQDN", "ORG"}
        if set(mappings) == legacy_types and set(counters) == legacy_types:
            fail(
                "token map uses legacy ORG placeholders. "
                "Use the earlier ORG script to detokenize it, "
                "or create a new map with this KEYWORD version"
            )

        if set(mappings) != TOKEN_TYPE_SET or set(counters) != TOKEN_TYPE_SET:
            fail("token map has unsupported token namespaces")

        token_map = cls.new()
        for token_type in TOKEN_TYPES:
            entries = mappings[token_type]
            counter = counters[token_type]
            if (
                not isinstance(entries, dict)
                or not isinstance(counter, int)
                or isinstance(counter, bool)
                or counter < 0
            ):
                fail("token map has invalid mapping entries")

            highest_number = 0
            for original, token in entries.items():
                if not isinstance(original, str) or not isinstance(token, str):
                    fail("token map has non-text mapping entries")

                match = TOKEN_RE.fullmatch(token)
                if match is None or match.group(1) != token_type:
                    fail("token map has invalid placeholder format")

                number = int(match.group(2))
                if number == 0:
                    fail("token map has invalid placeholder numbering")
                highest_number = max(highest_number, number)

                previous = token_map.by_token.get(token)
                if previous is not None and previous != original:
                    fail("token map has duplicate placeholder conflict")
                token_map.by_token[token] = original

            if counter < highest_number:
                fail("token map counter is lower than an existing placeholder")

            token_map.by_type[token_type] = dict(entries)
            token_map.counters[token_type] = counter

        ok, reason = token_map.validate()
        if not ok:
            fail(f"token map validation failed: {reason}")
        return token_map

    def save(self, path: Path) -> None:
        data = {"mappings": self.by_type, "counters": self.counters}
        atomic_write_text(
            path,
            json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def count(self) -> int:
        return sum(len(entries) for entries in self.by_type.values())

    def get_token(self, token_type: str, original: str) -> str:
        if token_type not in TOKEN_TYPE_SET:
            raise ValueError("unsupported token type")

        existing = self.by_type[token_type].get(original)
        if existing is not None:
            return existing

        self.counters[token_type] += 1
        token = f"<<{token_type}_{self.counters[token_type]:04d}>>"
        while token in self.by_token:
            self.counters[token_type] += 1
            token = f"<<{token_type}_{self.counters[token_type]:04d}>>"

        self.by_type[token_type][original] = token
        self.by_token[token] = original
        return token

    def validate(self) -> Tuple[bool, str]:
        seen: Dict[str, str] = {}

        if set(self.by_type) != TOKEN_TYPE_SET or set(self.counters) != TOKEN_TYPE_SET:
            return False, "unsupported token namespace found"

        for token_type in TOKEN_TYPES:
            entries = self.by_type[token_type]
            counter = self.counters[token_type]
            if (
                not isinstance(entries, dict)
                or not isinstance(counter, int)
                or isinstance(counter, bool)
            ):
                return False, "invalid token map namespace state found"
            if counter < 0:
                return False, "negative token counter found"

            highest_number = 0
            for original, token in entries.items():
                if not isinstance(original, str) or not isinstance(token, str):
                    return False, "non-text mapping entry found"

                match = TOKEN_RE.fullmatch(token)
                if match is None or match.group(1) != token_type:
                    return False, "invalid placeholder format found"

                number = int(match.group(2))
                if number == 0:
                    return False, "invalid placeholder numbering found"
                highest_number = max(highest_number, number)

                if token in seen and seen[token] != original:
                    return False, "duplicate placeholder conflict found"
                seen[token] = original

            if counter < highest_number:
                return False, "counter lower than existing placeholder found"

        if set(seen) != set(self.by_token):
            return False, "reverse mapping count mismatch found"
        for token, original in seen.items():
            if self.by_token.get(token) != original:
                return False, "reverse mapping mismatch found"

        return True, "ok"


@dataclass(frozen=True)
class CustomTerms:
    """Combined literal matcher for all configured custom terms."""

    pattern: Pattern[str]
    count: int


def atomic_write_text(path: Path, text: str, encoding: str) -> None:
    """Write to a temporary file, then replace the destination in one step."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name: Optional[str] = None

    try:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            encoding=encoding,
            newline="",
        ) as tmp:
            tmp.write(text)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_name = tmp.name

        os.replace(tmp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass


def detect_encoding(path: Path) -> Tuple[str, bool, str]:
    """Detect UTF-8/BOM and preserve the input CSV's line-ending style."""
    try:
        with path.open("rb") as handle:
            sample = handle.read(65536)
    except OSError:
        fail("unable to read input CSV")

    has_bom = sample.startswith(b"\xef\xbb\xbf")
    if b"\r\n" in sample:
        lineterminator = "\r\n"
    elif b"\n" in sample:
        lineterminator = "\n"
    elif b"\r" in sample:
        lineterminator = "\r"
    else:
        # A one-line CSV has no observable source line ending; use standard CSV output.
        lineterminator = "\r\n"

    return ("utf-8-sig" if has_bom else "utf-8"), has_bom, lineterminator


def normalise_col(name: Optional[str]) -> str:
    return (name or "").strip().casefold()


def is_valid_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def is_valid_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def is_valid_fqdn(value: str) -> bool:
    """Accept a conservative ASCII DNS name with at least one dot."""
    if (
        not value
        or len(value) > 253
        or value.endswith(".")
        or not value.isascii()
        or "." not in value
    ):
        return False

    labels = value.split(".")
    if len(labels) < 2 or not any(char.isalpha() for char in value):
        return False

    for label in labels:
        if not (1 <= len(label) <= 63):
            return False
        if not (label[0].isalnum() and label[-1].isalnum()):
            return False
        if not all(char.isalnum() or char == "-" for char in label):
            return False

    return True


def load_custom_terms(path_arg: Optional[str]) -> Optional[CustomTerms]:
    """Load literal case-insensitive substring terms, longest first.

    Terms are deliberately matched inside compound identifiers. For example,
    ``example`` matches ``un_example_001``, ``-example``, and ``examplewifi``.
    """
    path = Path(path_arg) if path_arg else Path.cwd() / "redact_terms.txt"
    if not path.exists():
        return None

    try:
        raw_terms = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeDecodeError):
        fail("unable to read terms file")

    seen: set[str] = set()
    terms: List[str] = []
    for term in sorted(raw_terms, key=len, reverse=True):
        key = term.casefold()
        if key not in seen:
            seen.add(key)
            terms.append(term)

    if not terms:
        return None

    # A single longest-first regex prevents a shorter configured term from
    # winning over a longer term at the same location. It also avoids scanning
    # placeholders created by an earlier per-term replacement pass.
    pattern = re.compile("|".join(re.escape(term) for term in terms), re.IGNORECASE)
    return CustomTerms(pattern=pattern, count=len(terms))


def tokenise_custom_terms(
    text: str,
    terms: Optional[CustomTerms],
    token_map: TokenMap,
) -> str:
    """Tokenise configured literal substrings while retaining exact restoration."""
    if terms is None:
        return text

    return terms.pattern.sub(
        lambda match: token_map.get_token("KEYWORD", match.group(0)),
        text,
    )


def replace_stripped_value(original: str, replacement: str) -> str:
    """Replace a whole trimmed cell while retaining leading/trailing whitespace."""
    start = len(original) - len(original.lstrip())
    end = len(original.rstrip())
    return original[:start] + replacement + original[end:]


def tokenise_whole_cell_identifier(text: str, token_map: TokenMap) -> str:
    """Tokenise a complete IP, IPv6, CIDR, or FQDN cell.

    This intentionally does not search for an arbitrary FQDN/IPv6 inside prose.
    """
    stripped = text.strip()
    if not stripped or TOKEN_RE.fullmatch(stripped):
        return text

    if is_valid_ipv4(stripped):
        replacement = token_map.get_token("IP", stripped)
    elif is_valid_ipv6(stripped):
        replacement = token_map.get_token("IPV6", stripped)
    elif is_valid_cidr(stripped):
        replacement = token_map.get_token("CIDR", stripped)
    elif is_valid_fqdn(stripped):
        replacement = token_map.get_token("FQDN", stripped)
    else:
        return text

    return replace_stripped_value(text, replacement)


def tokenise_inline_url_hosts(text: str, token_map: TokenMap) -> str:
    """Tokenise validated hostname/IP literals in standard HTTP(S)/FTP URLs only."""

    def repl(match: Match[str]) -> str:
        prefix = match.group("prefix")
        raw_host = match.group("host")

        if raw_host.startswith("[") and raw_host.endswith("]"):
            value = raw_host[1:-1]
            if is_valid_ipv6(value):
                return f"{prefix}[{token_map.get_token('IPV6', value)}]"
            return match.group(0)

        if is_valid_ipv4(raw_host):
            return f"{prefix}{token_map.get_token('IP', raw_host)}"
        if is_valid_fqdn(raw_host):
            return f"{prefix}{token_map.get_token('FQDN', raw_host)}"
        return match.group(0)

    return URL_HOST_RE.sub(repl, text)


def tokenise_labelled_identifiers(text: str, token_map: TokenMap) -> str:
    """Tokenise one value after a recognised host/address label at line start."""

    def repl(match: Match[str]) -> str:
        value = match.group("value")
        if is_valid_ipv4(value):
            token = token_map.get_token("IP", value)
        elif is_valid_ipv6(value):
            token = token_map.get_token("IPV6", value)
        elif is_valid_cidr(value):
            token = token_map.get_token("CIDR", value)
        elif is_valid_fqdn(value):
            token = token_map.get_token("FQDN", value)
        else:
            return match.group(0)
        return f"{match.group('prefix')}{token}"

    return LABELLED_IDENTIFIER_RE.sub(repl, text)


def tokenise_inline_ipv4_cidrs(text: str, token_map: TokenMap) -> str:
    """Tokenise validated IPv4 CIDRs embedded in text without partial matches."""

    def repl(match: Match[str]) -> str:
        value = match.group("value")
        return token_map.get_token("CIDR", value) if is_valid_cidr(value) else value

    return INLINE_IPV4_CIDR_RE.sub(repl, text)


def tokenise_inline_ipv4(text: str, token_map: TokenMap) -> str:
    """Tokenise validated IPv4 literals embedded in text without partial matches."""

    def repl(match: Match[str]) -> str:
        value = match.group("value")
        return token_map.get_token("IP", value) if is_valid_ipv4(value) else value

    return INLINE_IPV4_RE.sub(repl, text)


def tokenise_resolved_fqdns(text: str, token_map: TokenMap) -> str:
    """Tokenise a validated FQDN only in clear DNS-resolution phrasing."""

    def repl(match: Match[str]) -> str:
        host = match.group("host")
        if not is_valid_fqdn(host):
            return match.group(0)
        return f"{match.group('prefix')}{token_map.get_token('FQDN', host)}"

    return RESOLVES_FQDN_RE.sub(repl, text)


def transform_outside_existing_placeholders(
    text: str,
    transform: Callable[[str], str],
) -> str:
    """Apply a transform around, never inside, existing <<...>> placeholders."""
    pieces: List[str] = []
    previous_end = 0

    for match in TOKEN_RE.finditer(text):
        pieces.append(transform(text[previous_end:match.start()]))
        pieces.append(match.group(0))
        previous_end = match.end()

    pieces.append(transform(text[previous_end:]))
    return "".join(pieces)


def tokenise_cell(
    value: str,
    column_name: str,
    token_map: TokenMap,
    terms: Optional[CustomTerms],
) -> str:
    """Tokenise identifiers in one CSV cell while preserving See Also unchanged."""
    if value == "" or normalise_col(column_name) == SEE_ALSO_COLUMN:
        return value

    # Structured identifiers take precedence, so a complete FQDN or URL host
    # becomes one FQDN token rather than a partial custom-term replacement.
    text = tokenise_whole_cell_identifier(value, token_map)
    text = tokenise_inline_url_hosts(text, token_map)
    text = tokenise_labelled_identifiers(text, token_map)
    text = tokenise_inline_ipv4_cidrs(text, token_map)
    text = tokenise_inline_ipv4(text, token_map)
    text = tokenise_resolved_fqdns(text, token_map)

    # Existing and newly created placeholders must never be altered. Segmenting
    # is safer than temporary marker text because a user may configure any
    # literal term, including text that could occur in a marker.
    return transform_outside_existing_placeholders(
        text,
        lambda segment: tokenise_custom_terms(segment, terms, token_map),
    )


def find_placeholders(text: str) -> List[str]:
    return [match.group(0) for match in TOKEN_RE.finditer(text)]


def unknown_placeholders_in_rows(rows: List[Dict[str, str]], token_map: TokenMap) -> int:
    known = set(token_map.by_token)
    return sum(
        1
        for row in rows
        for value in row.values()
        for placeholder in find_placeholders(value)
        if placeholder not in known
    )


def read_csv_rows(path: Path) -> Tuple[List[Dict[str, str]], List[str], bool, str]:
    encoding, has_bom, lineterminator = detect_encoding(path)

    try:
        with path.open("r", encoding=encoding, newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                fail("input CSV has no header row")

            fieldnames = list(reader.fieldnames)
            if any(not isinstance(name, str) or not name.strip() for name in fieldnames):
                fail("input CSV contains an empty header name")
            if len(set(fieldnames)) != len(fieldnames):
                fail("input CSV contains duplicate header names")

            rows: List[Dict[str, str]] = []
            for row in reader:
                if None in row:
                    fail("input CSV has row(s) with more fields than the header")
                rows.append({field: (row.get(field) or "") for field in fieldnames})

            return rows, fieldnames, has_bom, lineterminator
    except UnicodeDecodeError:
        fail("input CSV must be UTF-8 or UTF-8 with BOM")
    except csv.Error:
        fail("unable to parse CSV safely")
    except OSError:
        fail("unable to read input CSV")


def write_csv_rows(
    path: Path,
    rows: List[Dict[str, str]],
    fieldnames: List[str],
    use_bom: bool,
    lineterminator: str,
) -> None:
    encoding = "utf-8-sig" if use_bom else "utf-8"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name: Optional[str] = None

    try:
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=str(path.parent),
            prefix=f".{path.name}.",
            encoding=encoding,
            newline="",
        ) as tmp:
            writer = csv.DictWriter(
                tmp,
                fieldnames=fieldnames,
                extrasaction="raise",
                lineterminator=lineterminator,
            )
            writer.writeheader()
            writer.writerows(rows)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_name = tmp.name

        os.replace(tmp_name, path)
    finally:
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass


def same_path(first: Path, second: Path) -> bool:
    try:
        return first.resolve() == second.resolve()
    except OSError:
        return first.absolute() == second.absolute()


def refuse_path_collisions(input_path: Path, output_path: Path, map_path: Path) -> None:
    if same_path(input_path, output_path):
        fail("output path must be different from input path")
    if same_path(input_path, map_path):
        fail("token map path must be different from input path")
    if same_path(output_path, map_path):
        fail("token map path must be different from output path")


def default_tokenize_output_path(input_path: Path) -> Path:
    """Return _sanitised.csv beside the input CSV."""
    return input_path.with_name(f"{input_path.stem}_sanitised.csv")


def default_token_map_path(input_path: Path) -> Path:
    """Return _token_map.json beside the input CSV."""
    return input_path.with_name(f"{input_path.stem}_token_map.json")


def default_detokenize_output_path(input_path: Path) -> Path:
    """Return _restored.csv beside the input CSV."""
    return input_path.with_name(f"{input_path.stem}_restored.csv")


def command_tokenize(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else default_tokenize_output_path(input_path)
    map_path = Path(args.map) if args.map else default_token_map_path(input_path)

    refuse_path_collisions(input_path, output_path, map_path)
    if not input_path.is_file():
        fail("input file does not exist")

    if map_path.exists():
        if not args.reuse_map:
            fail("token map already exists; use --reuse-map only for the same isolated batch")
        token_map = TokenMap.load(map_path)
        print(f"Using existing local token map; {token_map.count()} mappings loaded.")
    else:
        token_map = TokenMap.new()
        print("Creating a new local JSON token map for this isolated batch.")

    terms = load_custom_terms(args.terms_file)
    rows, fieldnames, has_bom, lineterminator = read_csv_rows(input_path)

    if unknown_placeholders_in_rows(rows, token_map):
        fail("input CSV contains placeholder(s) not present in the local token map")

    changed_cells = 0
    output_rows: List[Dict[str, str]] = []
    for row in rows:
        output_row: Dict[str, str] = {}
        for field in fieldnames:
            original = row[field]
            replacement = tokenise_cell(original, field, token_map, terms)
            if replacement != original:
                changed_cells += 1
            output_row[field] = replacement
        output_rows.append(output_row)

    if unknown_placeholders_in_rows(output_rows, token_map):
        fail("sanitised output contains placeholder(s) not present in the local token map")

    # Write the map first: a tokenised CSV without its map cannot be restored.
    token_map.save(map_path)
    write_csv_rows(output_path, output_rows, fieldnames, has_bom, lineterminator)

    print(f"Sanitised CSV written: {output_path}")
    print(f"Local token map written: {map_path} ({token_map.count()} mappings).")
    print("WARNING: The local token map contains original sensitive values. Do not upload or share it.")

    if args.verbose:
        print(
            f"Verbose: rows processed={len(rows)}, cells changed={changed_cells}, "
            f"custom terms loaded={terms.count if terms is not None else 0}"
        )


def command_detokenize(args: argparse.Namespace) -> None:
    input_path = Path(args.input)
    output_path = Path(args.output) if args.output else default_detokenize_output_path(input_path)
    map_path = Path(args.map)

    refuse_path_collisions(input_path, output_path, map_path)
    if not input_path.is_file():
        fail("input file does not exist")
    if not map_path.is_file():
        fail("token map does not exist")

    token_map = TokenMap.load(map_path)
    rows, fieldnames, has_bom, lineterminator = read_csv_rows(input_path)

    unknown: set[str] = set()

    def repl(match: Match[str]) -> str:
        placeholder = match.group(0)
        original = token_map.by_token.get(placeholder)
        if original is None:
            unknown.add(placeholder)
            return placeholder
        return original

    output_rows = [
        {field: TOKEN_RE.sub(repl, row[field]) for field in fieldnames}
        for row in rows
    ]
    write_csv_rows(output_path, output_rows, fieldnames, has_bom, lineterminator)

    print(f"Detokenised CSV written: {output_path}")
    print(f"Unknown placeholders left unchanged: {len(unknown)}.")
    if args.verbose:
        print(f"Verbose: rows processed={len(rows)}, mappings loaded={token_map.count()}")


def command_validate_map(args: argparse.Namespace) -> None:
    map_path = Path(args.map)
    if not map_path.is_file():
        fail("token map does not exist")

    token_map = TokenMap.load(map_path)
    ok, reason = token_map.validate()
    if not ok:
        fail(f"token map validation failed: {reason}")

    print(f"Token map validation ok. {token_map.count()} mappings present.")
    print("No sensitive values displayed.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"{BANNER}\n"
            "Token Buddy sanitises CSV files with reversible tokenisation.\n"
            "By default, tokenize needs only --input."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s tokenize --input test.csv\n"
            "  %(prog)s tokenize --input test.csv --terms-file redact_terms.txt --verbose\n"
            "  %(prog)s detokenize --input ai_output.csv --map test_token_map.json\n\n"
            "Tokenize defaults:\n"
            "  test.csv -> test_sanitised.csv and test_token_map.json\n\n"
            "Keep the JSON token map local. It contains the original values."
        ),
    )

    commands = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="{tokenize,detokenize,validate-map}",
    )

    tokenize = commands.add_parser(
        "tokenize",
        help="Sanitise a CSV; only --input is required",
        description=(
            f"{BANNER}\n"
            "Create a sanitised CSV and local token map.\n"
            "Default files are created beside the input CSV."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --input test.csv\n"
            "  %(prog)s --input test.csv --terms-file redact_terms.txt\n"
            "  %(prog)s --input test.csv --output clean.csv --map local_map.json\n\n"
            "Defaults for test.csv:\n"
            "  output: test_sanitised.csv\n"
            "  map:    test_token_map.json"
        ),
    )
    tokenize.add_argument(
        "--input",
        required=True,
        metavar="CSV",
        help="Source CSV file (UTF-8 or UTF-8 with BOM)",
    )
    tokenize.add_argument(
        "--output",
        metavar="CSV",
        help="Optional output CSV path (default: _sanitised.csv)",
    )
    tokenize.add_argument(
        "--map",
        metavar="JSON",
        help="Optional local map path (default: _token_map.json)",
    )
    tokenize.add_argument(
        "--reuse-map",
        action="store_true",
        help="Allow use of an existing map for the same isolated batch only",
    )
    tokenize.add_argument(
        "--terms-file",
        metavar="TXT",
        help=(
            "Optional literal-term file; one term per line, case-insensitive; "
            "values become <<KEYWORD_0001>> "
            "(default: ./redact_terms.txt if present)"
        ),
    )
    tokenize.add_argument(
        "--verbose",
        action="store_true",
        help="Show row/cell counts only; never print original values",
    )
    tokenize.set_defaults(func=command_tokenize)

    detokenize = commands.add_parser(
        "detokenize",
        help="Restore placeholders; --input and --map are required",
        description=(
            f"{BANNER}\n"
            "Restore placeholders using the matching local JSON map."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Example:\n"
            "  %(prog)s --input ai_output.csv --map test_token_map.json\n\n"
            "Default output: _restored.csv"
        ),
    )
    detokenize.add_argument(
        "--input",
        required=True,
        metavar="CSV",
        help="Tokenised or AI-processed CSV file",
    )
    detokenize.add_argument(
        "--map",
        required=True,
        metavar="JSON",
        help="Local JSON map created during tokenize",
    )
    detokenize.add_argument(
        "--output",
        metavar="CSV",
        help="Optional restored CSV path (default: _restored.csv)",
    )
    detokenize.add_argument(
        "--verbose",
        action="store_true",
        help="Show row and mapping counts only",
    )
    detokenize.set_defaults(func=command_detokenize)

    validate = commands.add_parser(
        "validate-map",
        help="Optional: check a local token map",
        description=(
            f"{BANNER}\n"
            "Check that a local token map is readable and internally consistent."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    validate.add_argument(
        "--map",
        required=True,
        metavar="JSON",
        help="Local JSON token map to check",
    )
    validate.set_defaults(func=command_validate_map)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        args.func(args)
        return 0
    except SystemExit:
        raise
    except Exception:
        # Do not print exception values: source paths or source data may be sensitive.
        print("Error: operation failed safely without displaying sensitive values", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
