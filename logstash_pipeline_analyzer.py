#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logstash_pipeline_analyzer_v12.py
═══════════════════════════════════════════════════════════════════════════
Stage 1 of the Logstash → Elasticsearch Ingest Migration System.

What's new vs v11
─────────────────
1.  ORDERED FILTER TREE  — replaces the flat processor list.

    The filter section is now modelled as a tree of FilterNode objects:
      - ProcessorNode   : a single plugin block (grok, mutate, ruby…)
      - ConditionalNode : if/else if/else branch set
      - SequenceNode    : ordered list of nodes (the filter { } body itself)

    This preserves exact execution order and branching structure, enabling
    the visualizer to render a Kibana-style processor chain with branches.

2.  INGEST COMPATIBILITY FLAGS  — every processor node carries:
      ingest_status : "supported" | "partial" | "unsupported"
      ingest_note   : short human-readable explanation
      ingest_mapping: which ES ingest processor it maps to (or None)

3.  RAW CONFIG SNAPSHOT  — every processor node carries a trimmed raw
    source text excerpt so the visualizer and transformer can show/use
    the original config without re-reading the file.

4.  FULL CONFIG EXTRACTION  — extract_full_raw_config() extracts the
    exact text of each top-level block (input/filter/output) from the
    source file using the balanced-brace scanner, solving the "[No filter
    block found]" problem permanently.

5.  STRUCTURED JSON OUTPUT  — the JSON now emits processors_ordered
    (the full filter tree as a serialisable dict) alongside all v11 fields,
    making it directly consumable by Stage 2 (Transformer) and Stage 4
    (Visualizer).

6.  Backward-compatible  — all v11 JSON fields retained.
═══════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# ─────────────────────────────────────────────────────────────
# Ingest compatibility catalogue
# Every Logstash filter plugin maps to one of three statuses.
# ─────────────────────────────────────────────────────────────

@dataclass
class IngestInfo:
    status: str           # "supported" | "partial" | "unsupported"
    ingest_processor: Optional[str]   # ES ingest processor name or None
    note: str             # short explanation for the UI

INGEST_CATALOGUE: Dict[str, IngestInfo] = {
    # ── Fully supported ──────────────────────────────────────
    "grok":        IngestInfo("supported",   "grok",         "Direct 1:1 mapping to ES grok processor"),
    "dissect":     IngestInfo("supported",   "dissect",      "Direct mapping to ES dissect processor"),
    "date":        IngestInfo("supported",   "date",         "Maps to ES date processor"),
    "json":        IngestInfo("supported",   "json",         "Maps to ES json processor"),
    "geoip":       IngestInfo("supported",   "geoip",        "Maps to ES geoip processor (needs MaxMind DB)"),
    "useragent":   IngestInfo("supported",   "user_agent",   "Maps to ES user_agent processor (ES 7.11+)"),
    "urldecode":   IngestInfo("supported",   "urldecode",    "Maps to ES urldecode processor"),
    "fingerprint": IngestInfo("supported",   "fingerprint",  "Maps to ES fingerprint processor"),
    "drop":        IngestInfo("supported",   "drop",         "Maps to ES drop processor"),
    "kv":          IngestInfo("supported",   "kv",           "Maps to ES kv processor"),
    "csv":         IngestInfo("supported",   "csv",          "Maps to ES csv processor"),
    "split":       IngestInfo("supported",   "foreach",      "Maps to ES foreach processor"),
    "cidr":        IngestInfo("supported",   "script",       "Replicate with Painless script or network processor"),
    "truncate":    IngestInfo("supported",   "set",          "Replicate with set + value length check"),
    "de_dot":      IngestInfo("supported",   "dot_expander", "Maps to ES dot_expander processor"),
    "syslog_pri":  IngestInfo("supported",   "grok",         "Parse syslog PRI with grok pattern"),
    # ── Partial / needs work ─────────────────────────────────
    "mutate":      IngestInfo("partial",     "set",          "Maps to set/rename/remove/append — split per sub-action"),
    "translate":   IngestInfo("partial",     "enrich",       "Replace with enrich policy; inline dict not supported"),
    "xml":         IngestInfo("partial",     "script",       "No native XML processor; use Painless or pre-parse"),
    "uuid":        IngestInfo("partial",     "set",          "Use set with {{{_id}}} or script to generate UUID"),
    "prune":       IngestInfo("partial",     "remove",       "Replicate field exclusion with remove processor"),
    "throttle":    IngestInfo("partial",     None,           "No ingest equivalent; consider index lifecycle or routing"),
    "sleep":       IngestInfo("partial",     None,           "No ingest equivalent; remove or handle upstream"),
    "date":        IngestInfo("supported",   "date",         "Maps to ES date processor"),
    # ── Not supported ────────────────────────────────────────
    "ruby":        IngestInfo("unsupported", "script",       "No Ruby in ingest — rewrite in Painless or pre-process"),
    "aggregate":   IngestInfo("unsupported", None,           "Stateful aggregation — no ingest equivalent"),
    "elapsed":     IngestInfo("unsupported", None,           "Stateful timing — no ingest equivalent"),
    "clone":       IngestInfo("unsupported", None,           "Event cloning — use pipeline fan-out instead"),
    "metrics":     IngestInfo("unsupported", None,           "Aggregation state — use ES aggregations instead"),
    "jdbc_streaming": IngestInfo("unsupported", "enrich",    "DB lookup — replace with enrich policy"),
    "memcached":   IngestInfo("unsupported", "enrich",       "Cache lookup — replace with enrich policy"),
    "cipher":      IngestInfo("unsupported", "script",       "Crypto — evaluate Painless or pre/post-process"),
    "http":        IngestInfo("unsupported", None,           "Outbound HTTP — not available in ingest"),
    "elasticsearch": IngestInfo("unsupported", "enrich",     "ES lookup — replace with enrich policy"),
    "dns":         IngestInfo("unsupported", None,           "DNS lookup — network I/O not in ingest"),
}

def get_ingest_info(plugin: str) -> IngestInfo:
    return INGEST_CATALOGUE.get(plugin, IngestInfo("partial", None, f"Unknown plugin '{plugin}' — manual review needed"))

# ─────────────────────────────────────────────────────────────
# Plugin catalogues (unchanged from v11)
# ─────────────────────────────────────────────────────────────

OFFICIAL_FILTER_PLUGINS = {
    "age", "aggregate", "alter", "bytes", "cidr", "cipher", "clone",
    "csv", "date", "de_dot", "dissect", "dns", "drop", "elapsed",
    "elastic_integration", "elasticsearch", "environment", "extractnumbers",
    "fingerprint", "geoip", "grok", "http", "i18n", "java_uuid",
    "jdbc_streaming", "json", "json_encode", "kv", "memcached", "metricize",
    "metrics", "mutate", "prune", "range", "ruby", "sleep", "split",
    "syslog_pri", "threats_classifier", "throttle", "tld", "translate",
    "truncate", "urldecode", "useragent", "uuid", "wurfl_device_detection", "xml",
}

KNOWN_TERMINAL_SINKS = {
    "elasticsearch", "file", "kafka", "http", "stdout", "s3", "tcp", "udp",
    "opensearch", "rabbitmq", "email", "redis", "azure_event_hubs", "sqs",
}

STRUCTURAL_BLOCKS = {
    "root", "input", "filter", "output", "pipeline",
    "if", "else", "elsif", "else if", "body",
}
CONDITIONAL_BLOCK_NAMES = {"if", "else", "elsif", "else if"}

# ─────────────────────────────────────────────────────────────
# Migration scoring catalogue (v11, unchanged)
# ─────────────────────────────────────────────────────────────

MIGRATION_PENALTIES: Dict[str, Tuple[int, str, str]] = {
    "ruby":           (30, "inline Ruby code — not supported in ingest pipelines",
                       "Replace with script processor (painless) or simulate API"),
    "aggregate":      (35, "stateful aggregation — requires external coordination",
                       "Rethink as enrich policy or move logic to application layer"),
    "elapsed":        (25, "event-pair timing — stateful, not ingest-compatible",
                       "Use APM / application-level timing instead"),
    "clone":          (12, "event cloning — not natively supported in ingest",
                       "Use pipeline fan-out or application-side duplication"),
    "metrics":        (20, "metrics aggregation — external state required",
                       "Replace with Elasticsearch aggregations or Metricbeat"),
    "jdbc_streaming": (18, "JDBC lookup — external DB dependency",
                       "Pre-load to enrich policy or use lookup processor"),
    "memcached":      (20, "memcached lookup — external state",
                       "Replace with enrich policy"),
    "cipher":         (15, "encryption/decryption — security-critical custom code",
                       "Evaluate script processor with painless or pre-process"),
    "http":           (10, "outbound HTTP calls — I/O not supported in ingest",
                       "Pre-enrich data or use external pipeline trigger"),
    "elasticsearch":  (10, "Elasticsearch filter (lookup) — complex dependency",
                       "Replace with enrich policy"),
    "translate":      ( 8, "dictionary translation — file-based, needs pre-loading",
                       "Replace with enrich policy (lookup by value)"),
    "xml":            ( 8, "XML parsing — not natively in ingest",
                       "Use script processor or pre-parse before ingest"),
    "dns":            ( 6, "DNS reverse lookup — network I/O not in ingest",
                       "Pre-resolve or accept missing DNS enrichment"),
    "useragent":      ( 5, "user-agent parsing — needs Elastic UA processor",
                       "Use user_agent ingest processor (available in ES 7.11+)"),
    "geoip":          ( 5, "GeoIP — available as ingest processor but needs DB",
                       "Use geoip ingest processor with maxmind DB"),
}

EASY_THRESHOLD   = 75
MEDIUM_THRESHOLD = 45

INPUT_REPLACEMENT_PENALTIES: Dict[str, Tuple[Optional[int], int, str, str]] = {
    "jdbc": (30, 0,
        "JDBC input: scheduled SQL polling with sql_last_value watermarking — "
        "no Elastic Agent equivalent. Requires separate ingestion strategy.",
        "Consider Elastic JDBC connector / Kafka Connect JDBC source. "
        "Filter logic may migrate to ingest pipeline; input stage cannot."),
    "http_poller": (45, 0,
        "HTTP Poller input: scheduled HTTP polling — limited Elastic Agent support.",
        "Evaluate Elastic Agent HTTP input or custom Fleet integration."),
    "redis": (None, 15,
        "Redis input: Elastic Agent does not natively support Redis queues.",
        "Replace Redis queue with Kafka (supported by Elastic Agent)."),
    "kafka": (None, 10,
        "Kafka input: Elastic Agent supports Kafka but option parity gaps exist.",
        "Verify consumer group, codec, and offset management options."),
}

JDBC_EXTRA_PENALTIES: List[Tuple[str, int, str]] = [
    ("schedule",         10, "JDBC schedule/cron: automated polling — no ingest pipeline equivalent"),
    ("tracking_column",  15, "sql_last_value watermarking: stateful incremental ingestion"),
    ("use_column_value",  5, "use_column_value: timestamp-based watermarking detected"),
    ("statement",         5, "SQL statement: query logic must be ported to connector config"),
]

# ─────────────────────────────────────────────────────────────
# Value model (unchanged)
# ─────────────────────────────────────────────────────────────

class Value:
    def to_python(self) -> Any: raise NotImplementedError

@dataclass
class ScalarValue(Value):
    value: str
    def to_python(self) -> Any: return self.value

@dataclass
class ArrayValue(Value):
    items: List["Value"]
    def to_python(self) -> Any: return [v.to_python() for v in self.items]

@dataclass
class MapValue(Value):
    pairs: List[Tuple[str, "Value"]]
    def to_python(self) -> Any:
        out: Dict[str, Any] = {}
        for k, v in self.pairs:
            pv = v.to_python()
            if k in out:
                if not isinstance(out[k], list): out[k] = [out[k]]
                out[k].append(pv)
            else: out[k] = pv
        return out

@dataclass
class RawValue(Value):
    text: str
    def to_python(self) -> Any: return self.text

# ─────────────────────────────────────────────────────────────
# AST model (unchanged)
# ─────────────────────────────────────────────────────────────

@dataclass
class Assignment:
    key: str
    value: Value

@dataclass
class Block:
    name: str
    items: List[Union["Block", Assignment]] = field(default_factory=list)

@dataclass
class Token:
    tt: str; val: str; pos: int

# ─────────────────────────────────────────────────────────────
# Filter tree model  (NEW in v12)
# ─────────────────────────────────────────────────────────────

@dataclass
class ProcessorNode:
    """A single Logstash filter plugin instance."""
    node_type: str = "processor"
    plugin: str = ""
    seq_index: int = 0          # position in the flat execution order
    branch_depth: int = 0       # nesting depth inside conditionals
    condition_path: List[str] = field(default_factory=list)  # e.g. ["if [type]==\"syslog\""]
    config: Dict[str, Any] = field(default_factory=dict)     # extracted config values
    raw_config: str = ""        # trimmed source text of this plugin block
    direct_assignments: int = 0
    metrics: Dict[str, Any] = field(default_factory=dict)
    # Ingest compatibility
    ingest_status: str = "partial"
    ingest_processor: Optional[str] = None
    ingest_note: str = ""

@dataclass
class ConditionalBranch:
    """One arm of a conditional (if / else if / else)."""
    condition: str              # the if/else-if condition string, or "" for else
    branch_type: str            # "if" | "elsif" | "else"
    body: "SequenceNode" = field(default_factory=lambda: SequenceNode())

@dataclass
class ConditionalNode:
    """A full if/else-if/else group."""
    node_type: str = "conditional"
    seq_index: int = 0
    branch_depth: int = 0
    branches: List[ConditionalBranch] = field(default_factory=list)

@dataclass
class SequenceNode:
    """An ordered list of filter nodes — the body of filter {} or a branch."""
    node_type: str = "sequence"
    children: List[Union[ProcessorNode, ConditionalNode, "SequenceNode"]] = \
        field(default_factory=list)

def filter_tree_to_dict(node) -> Dict[str, Any]:
    """Recursively serialise the filter tree to plain dicts for JSON output."""
    if isinstance(node, ProcessorNode):
        return {
            "node_type": "processor",
            "plugin": node.plugin,
            "seq_index": node.seq_index,
            "branch_depth": node.branch_depth,
            "condition_path": node.condition_path,
            "config": node.config,
            "raw_config": node.raw_config,
            "direct_assignments": node.direct_assignments,
            "metrics": node.metrics,
            "ingest_status": node.ingest_status,
            "ingest_processor": node.ingest_processor,
            "ingest_note": node.ingest_note,
        }
    if isinstance(node, ConditionalNode):
        return {
            "node_type": "conditional",
            "seq_index": node.seq_index,
            "branch_depth": node.branch_depth,
            "branches": [
                {
                    "condition": b.condition,
                    "branch_type": b.branch_type,
                    "body": filter_tree_to_dict(b.body),
                }
                for b in node.branches
            ],
        }
    if isinstance(node, SequenceNode):
        return {
            "node_type": "sequence",
            "children": [filter_tree_to_dict(c) for c in node.children],
        }
    return {}

def flatten_processors(node) -> List[ProcessorNode]:
    """Return all ProcessorNodes in execution order (depth-first)."""
    result: List[ProcessorNode] = []
    if isinstance(node, ProcessorNode):
        result.append(node)
    elif isinstance(node, ConditionalNode):
        for branch in node.branches:
            result.extend(flatten_processors(branch.body))
    elif isinstance(node, SequenceNode):
        for child in node.children:
            result.extend(flatten_processors(child))
    return result

# ─────────────────────────────────────────────────────────────
# Text preprocessing (unchanged)
# ─────────────────────────────────────────────────────────────

def normalize_arrows(text: str) -> str:
    text = text.replace("=&gt;", "=>")
    text = re.sub(r'=\s*\\\s*>', '=>', text)
    text = re.sub(r'=\s*>', '=>', text)
    return text

def strip_comments(text: str) -> str:
    out: List[str] = []
    for line in text.splitlines():
        in_str = False; quote = ""; escaped = False; buf: List[str] = []
        for ch in line:
            if escaped: buf.append(ch); escaped = False; continue
            if ch == "\\": buf.append(ch); escaped = True; continue
            if in_str:
                buf.append(ch)
                if ch == quote: in_str = False; quote = ""
                continue
            if ch in ("'", '"'): buf.append(ch); in_str = True; quote = ch; continue
            if ch == "#": break
            buf.append(ch)
        out.append("".join(buf))
    return "\n".join(out)

# ─────────────────────────────────────────────────────────────
# Tokenizer (unchanged)
# ─────────────────────────────────────────────────────────────

def tokenize(text: str) -> List[Token]:
    toks: List[Token] = []
    i = 0; L = len(text)
    while i < L:
        ch = text[i]
        if ch.isspace(): i += 1; continue
        if text.startswith("=>", i): toks.append(Token("ARROW", "=>", i)); i += 2; continue
        if ch == "{": toks.append(Token("LBRACE", ch, i)); i += 1; continue
        if ch == "}": toks.append(Token("RBRACE", ch, i)); i += 1; continue
        if ch == "[": toks.append(Token("LBRACKET", ch, i)); i += 1; continue
        if ch == "]": toks.append(Token("RBRACKET", ch, i)); i += 1; continue
        if ch == ",": toks.append(Token("COMMA", ch, i)); i += 1; continue
        if ch in ("'", '"'):
            q = ch; j = i + 1; buf: List[str] = []; esc = False
            while j < L:
                c = text[j]
                if esc: buf.append(c); esc = False; j += 1; continue
                if c == "\\": esc = True; j += 1; continue
                if c == q: break
                buf.append(c); j += 1
            toks.append(Token("STRING", "".join(buf), i))
            i = j + 1 if j < L else L; continue
        j = i
        while j < L and not text[j].isspace() and text[j] not in '{}[],"\'':
            if text.startswith("=>", j): break
            j += 1
        toks.append(Token("WORD", text[i:j], i)); i = j
    return toks

# ─────────────────────────────────────────────────────────────
# Value parsers (unchanged)
# ─────────────────────────────────────────────────────────────

def parse_value(tokens: Sequence[Token], i: int):
    if i >= len(tokens): return RawValue(""), i
    t = tokens[i]
    if t.tt in ("WORD", "STRING"): return ScalarValue(t.val), i + 1
    if t.tt == "LBRACKET": return parse_array(tokens, i)
    if t.tt == "LBRACE": return parse_map(tokens, i)
    return RawValue(t.val), i + 1

def parse_array(tokens: Sequence[Token], i: int):
    i += 1; items: List[Value] = []
    while i < len(tokens):
        if tokens[i].tt == "RBRACKET": return ArrayValue(items), i + 1
        if tokens[i].tt == "COMMA": i += 1; continue
        val, i = parse_value(tokens, i); items.append(val)
    return ArrayValue(items), i

def parse_map(tokens: Sequence[Token], i: int):
    i += 1; pairs: List[Tuple[str, Value]] = []
    while i < len(tokens):
        if tokens[i].tt == "RBRACE": return MapValue(pairs), i + 1
        if tokens[i].tt == "COMMA": i += 1; continue
        if tokens[i].tt in ("WORD", "STRING"):
            key = tokens[i].val
            if i + 1 < len(tokens) and tokens[i + 1].tt == "ARROW":
                i += 2; val, i = parse_value(tokens, i); pairs.append((key, val)); continue
        i += 1
    return MapValue(pairs), i

def parse_blocks(tokens: Sequence[Token]) -> Block:
    root = Block("root"); stack = [root]; key_buf: List[Token] = []; i = 0
    def flush_key() -> str:
        nonlocal key_buf
        if not key_buf: return ""
        key = " ".join(t.val for t in key_buf).strip(); key_buf = []; return key
    while i < len(tokens):
        t = tokens[i]
        if t.tt in ("WORD", "STRING") and i + 1 < len(tokens) and tokens[i+1].tt == "LBRACE":
            blk = Block(t.val.lower()); stack[-1].items.append(blk); stack.append(blk)
            i += 2; key_buf = []; continue
        if t.tt == "LBRACE":
            blk = Block("body"); stack[-1].items.append(blk); stack.append(blk)
            i += 1; key_buf = []; continue
        if t.tt == "RBRACE":
            if len(stack) > 1: stack.pop()
            i += 1; key_buf = []; continue
        if t.tt == "ARROW":
            key = flush_key(); i += 1; val, i = parse_value(tokens, i)
            if key: stack[-1].items.append(Assignment(key.lower(), val)); continue
        if t.tt in ("WORD", "STRING"): key_buf.append(t)
        else:
            if t.tt not in ("LBRACKET", "RBRACKET"): key_buf = []
        i += 1
    return root

# ─────────────────────────────────────────────────────────────
# Raw config extraction (NEW in v12)
# Uses a brace-balanced scanner on the original source text.
# ─────────────────────────────────────────────────────────────

def extract_named_blocks_raw(text: str, block_name: str) -> List[Tuple[int, int, str]]:
    """
    Return list of (start, end, block_text) for all occurrences of
    'block_name { ... }' in text, using brace-balanced scanning.
    Works on the original (comment-stripped) source, so raw_config
    snapshots are readable.
    """
    results: List[Tuple[int, int, str]] = []
    lower = block_name.lower(); L = len(text); i = 0
    while i < L:
        idx = text.lower().find(lower, i)
        if idx == -1: break
        end_name = idx + len(lower)
        before_ok = idx == 0 or not (text[idx-1].isalnum() or text[idx-1] == "_")
        after_ok  = end_name >= L or not (text[end_name].isalnum() or text[end_name] == "_")
        if not (before_ok and after_ok): i = idx + 1; continue
        j = end_name
        while j < L and text[j] in (" ", "\t", "\n", "\r"): j += 1
        if j >= L or text[j] != "{": i = idx + 1; continue
        depth = 0; in_str = False; quote = ""; escaped = False; end = None
        for k in range(j, L):
            ch = text[k]
            if escaped: escaped = False; continue
            if ch == "\\": escaped = True; continue
            if in_str:
                if ch == quote: in_str = False; quote = ""
                continue
            if ch in ("'", '"'): in_str = True; quote = ch; continue
            if ch == "{": depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0: end = k + 1; break
        if end is not None:
            results.append((idx, end, text[idx:end].strip())); i = end
        else:
            i = idx + 1
    return results

# ─────────────────────────────────────────────────────────────
# Value helpers (unchanged)
# ─────────────────────────────────────────────────────────────

def scalar_text(v: Optional[Value]) -> Optional[str]:
    return v.value if isinstance(v, ScalarValue) else None

def array_of_scalars(v: Optional[Value]) -> List[str]:
    if isinstance(v, ArrayValue): return [x.value for x in v.items if isinstance(x, ScalarValue)]
    return []

def map_to_pairs(v: Optional[Value]) -> List[Tuple[str, Value]]:
    return v.pairs if isinstance(v, MapValue) else []

def truthy_scalar(v: Optional[Value]) -> Optional[bool]:
    s = scalar_text(v)
    if s is None: return None
    return True if s.lower() in ("true","yes","1") else False if s.lower() in ("false","no","0") else None

def value_to_python(v: Value) -> Any: return v.to_python()
def direct_assignment_count(block: Block) -> int: return sum(1 for x in block.items if isinstance(x, Assignment))
def count_map_entries(v: Optional[Value]) -> int: return len(map_to_pairs(v))
def count_array_entries(v: Optional[Value]) -> int: return len(array_of_scalars(v))

# ─────────────────────────────────────────────────────────────
# Plugin metrics extractors (unchanged from v11)
# ─────────────────────────────────────────────────────────────

def extract_grok_metrics(block: Block) -> Dict[str, Any]:
    m = {"pattern_count":0,"pattern_chars":0,"named_capture_count":0,"alternation_count":0,"overwrite_count":0,"heavy":False}
    for item in block.items:
        if not isinstance(item, Assignment): continue
        if item.key.lower() == "match":
            v = item.value; patterns: List[str] = []
            if isinstance(v, MapValue):
                for _, mv in v.pairs: patterns += [mv.value] if isinstance(mv, ScalarValue) else array_of_scalars(mv) if isinstance(mv, ArrayValue) else []
            elif isinstance(v, ArrayValue): arr = array_of_scalars(v); patterns += [arr[i] for i in range(1,len(arr),2)]
            elif isinstance(v, ScalarValue): patterns.append(v.value)
            for p in patterns:
                m["pattern_count"]+=1; m["pattern_chars"]+=len(p)
                m["named_capture_count"]+=p.count("(?<")+p.count("%{")
                m["alternation_count"]+=p.count("|")
                if len(p)>200: m["heavy"]=True
        elif item.key.lower() == "overwrite":
            m["overwrite_count"] += len(array_of_scalars(item.value)) if isinstance(item.value, ArrayValue) else 1
    return m

def extract_mutate_metrics(block: Block) -> Dict[str, Any]:
    m = {"rename_count":0,"convert_count":0,"add_field_count":0,"remove_field_count":0,"remove_tag_count":0,"replace_count":0,"add_tag_count":0}
    for item in block.items:
        if not isinstance(item, Assignment): continue
        k = item.key.lower()
        if k=="rename": m["rename_count"]+=count_map_entries(item.value)
        elif k=="convert": m["convert_count"]+=count_map_entries(item.value)
        elif k=="add_field": m["add_field_count"]+=count_map_entries(item.value)
        elif k=="remove_field": m["remove_field_count"]+=max(1,count_array_entries(item.value))
        elif k=="remove_tag": m["remove_tag_count"]+=max(1,count_array_entries(item.value))
        elif k=="replace": m["replace_count"]+=max(1,len(array_of_scalars(item.value))//2) if isinstance(item.value,ArrayValue) else max(1,count_map_entries(item.value))
        elif k=="add_tag": n=count_array_entries(item.value); m["add_tag_count"]+=n if n else 1
    return m

def extract_ruby_metrics(block: Block) -> Dict[str, Any]:
    m = {"inline_code_chars":0,"inline_code_lines":0,"has_init":False,"external_path":None,"loop_keywords":0,"has_event_cancel":False,"has_require":False,"has_http":False}
    for item in block.items:
        if not isinstance(item, Assignment): continue
        k = item.key.lower()
        if k=="code" and isinstance(item.value,ScalarValue):
            code=item.value.value; m["inline_code_chars"]=len(code); m["inline_code_lines"]=code.count("\n")+1
            m["loop_keywords"]=sum(code.count(w) for w in ("each","while","for ","until","loop do"))
            m["has_event_cancel"]="event.cancel" in code; m["has_require"]="require" in code
            m["has_http"]="Net::HTTP" in code or "http.get" in code.lower()
        elif k=="init": m["has_init"]=True
        elif k=="path" and isinstance(item.value,ScalarValue): m["external_path"]=item.value.value
    return m

def extract_translate_metrics(block: Block) -> Dict[str, Any]:
    m = {"dictionary_entries":0,"regex":False,"exact":None,"has_file":False}
    for item in block.items:
        if not isinstance(item, Assignment): continue
        k = item.key.lower()
        if k=="dictionary": m["dictionary_entries"]+=len(array_of_scalars(item.value))//2 if isinstance(item.value,ArrayValue) else len(item.value.pairs) if isinstance(item.value,MapValue) else 0
        elif k=="dictionary_path": m["has_file"]=True
        elif k=="regex": m["regex"]=bool(truthy_scalar(item.value))
        elif k=="exact": m["exact"]=truthy_scalar(item.value)
    return m

def extract_xml_metrics(block: Block) -> Dict[str, Any]:
    m = {"xpath_entries":0}
    for item in block.items:
        if isinstance(item,Assignment) and item.key.lower()=="xpath":
            m["xpath_entries"]+=len(array_of_scalars(item.value))//2 if isinstance(item.value,ArrayValue) else len(item.value.pairs) if isinstance(item.value,MapValue) else 0
    return m

def extract_csv_metrics(block: Block) -> Dict[str, Any]:
    m = {"columns_count":0}
    for item in block.items:
        if isinstance(item,Assignment) and item.key.lower()=="columns": m["columns_count"]=len(array_of_scalars(item.value))
    return m

def extract_sink_details(block: Block) -> Dict[str, Any]:
    details: Dict[str,Any] = {}
    for item in block.items:
        if not isinstance(item,Assignment): continue
        k=item.key.lower()
        if k in ("topic_id","topic","topics","path","index","url","codec","ilm_rollover_alias","hosts","host","compression_type","port"):
            details[k]=value_to_python(item.value)
    return details

def extract_input_source_details(block: Block) -> Dict[str, Any]:
    details: Dict[str,Any] = {}
    for item in block.items:
        if not isinstance(item,Assignment): continue
        k=item.key.lower()
        if k in ("port","path","paths","topics","topic","topic_id","group_id","host","hosts","queue","codec","type",
                 "schedule","tracking_column","tracking_column_type","use_column_value","statement",
                 "last_run_metadata_path","jdbc_driver_class","jdbc_connection_string"):
            details[k]=value_to_python(item.value)
    return details

def processor_metrics(plugin: str, block: Block) -> Dict[str, Any]:
    if plugin=="grok": return extract_grok_metrics(block)
    if plugin=="mutate": return extract_mutate_metrics(block)
    if plugin=="ruby": return extract_ruby_metrics(block)
    if plugin=="translate": return extract_translate_metrics(block)
    if plugin=="xml": return extract_xml_metrics(block)
    if plugin=="csv": return extract_csv_metrics(block)
    return {}

def block_to_config(block: Block) -> Dict[str, Any]:
    """Extract all assignments from a plugin block as a plain python dict."""
    config: Dict[str, Any] = {}
    for item in block.items:
        if isinstance(item, Assignment):
            config[item.key] = value_to_python(item.value)
    return config

# ─────────────────────────────────────────────────────────────
# Analysis model (extended from v11)
# ─────────────────────────────────────────────────────────────

@dataclass
class ProcessorInstance:
    """Legacy flat processor record — kept for scoring compatibility."""
    plugin: str
    direct_assignments: int
    metrics: Dict[str, Any]
    branch_depth: int
    conditional_count_along_path: int

@dataclass
class SinkInfo:
    sink_type: str
    details: Dict[str, Any]
    def label(self) -> str:
        if self.sink_type=="kafka":
            t=self.details.get("topic_id") or self.details.get("topic") or self.details.get("topics")
            return f"SINK:kafka:{t}" if t else "SINK:kafka"
        if self.sink_type=="file":
            p=self.details.get("path"); return f"SINK:file:{p}" if p else "SINK:file"
        if self.sink_type in ("elasticsearch","opensearch"):
            idx=self.details.get("index") or self.details.get("ilm_rollover_alias")
            return f"SINK:{self.sink_type}:{idx}" if idx else f"SINK:{self.sink_type}"
        if self.sink_type=="http":
            u=self.details.get("url"); return f"SINK:http:{u}" if u else "SINK:http"
        return f"SINK:{self.sink_type}"

@dataclass
class InputSource:
    input_type: str
    details: Dict[str, Any]
    def label(self) -> str:
        if self.input_type=="beats":
            p=self.details.get("port"); return f"SOURCE:beats:{p}" if p else "SOURCE:beats"
        if self.input_type=="file":
            p=self.details.get("path"); return f"SOURCE:file:{p}" if p else "SOURCE:file"
        if self.input_type=="kafka":
            t=self.details.get("topics") or self.details.get("topic_id") or self.details.get("topic")
            return f"SOURCE:kafka:{t}" if t else "SOURCE:kafka"
        if self.input_type in ("tcp","udp","http","http_poller"):
            p=self.details.get("port"); return f"SOURCE:{self.input_type}:{p}" if p else f"SOURCE:{self.input_type}"
        return f"SOURCE:{self.input_type}"

@dataclass
class MigrationAnalysis:
    filter_transform_score: int
    full_replacement_score: int
    score: int
    migration_class: str
    pipeline_label: str
    reasons: List[str]
    penalties: Dict[str, int]
    recommendations: List[str]
    input_blockers: List[str]

@dataclass
class FileAnalysis:
    file: str
    pipeline_inputs: List[str]
    pipeline_outputs: List[str]
    input_sources: List[InputSource]
    terminal_sinks: List[SinkInfo]
    processors: List[ProcessorInstance]     # legacy flat list
    filter_tree: SequenceNode               # NEW: ordered tree
    has_conditionals: bool
    branch_count: int
    max_branch_depth: int
    regex_pipeline_input_hits: List[str]
    regex_pipeline_output_hits: List[str]
    raw_filter_text: str = ""              # NEW: raw filter { } block text
    raw_input_text: str = ""              # NEW: raw input { } block text
    raw_output_text: str = ""             # NEW: raw output { } block text

@dataclass
class PipelineDefinition:
    pipeline_address: str
    file: str               # primary file (first in files list)
    files: List[str]        # ALL source files that contributed to this definition
    local_outputs: List[str]
    input_sources: List[InputSource]
    terminal_sinks: List[SinkInfo]
    processors: List[ProcessorInstance]
    filter_tree: SequenceNode
    has_conditionals: bool
    branch_count: int
    max_branch_depth: int
    local_statement_total: int
    local_score: int

# ─────────────────────────────────────────────────────────────
# Visitors
# ─────────────────────────────────────────────────────────────

def regex_pipeline_sanity(text: str) -> Tuple[List[str], List[str]]:
    i_hits = re.findall(r'pipeline\s*\{[\s\S]{0,500}?address\s*=>\s*["\']?([A-Za-z0-9_.:@/\-]+)', text, re.IGNORECASE)
    o_hits = re.findall(r'pipeline\s*\{[\s\S]{0,500}?send_to\s*=>\s*["\']?([A-Za-z0-9_.:@/\-]+)', text, re.IGNORECASE)
    return sorted(set(i_hits)), sorted(set(o_hits))

def collect_pipeline_io_sources_and_sinks(ast: Block):
    inputs: List[str] = []; outputs: List[str] = []
    input_sources: List[InputSource] = []; sinks: List[SinkInfo] = []
    def add_outputs(v: Value):
        if isinstance(v, ScalarValue):
            if v.value: outputs.append(v.value)
        elif isinstance(v, ArrayValue):
            for s in array_of_scalars(v):
                if s: outputs.append(s)
    def walk(node: Block, in_in=False, in_out=False, in_pipe=False):
        name = node.name.lower()
        if name=="input": in_in,in_out=True,False
        elif name=="output": in_out,in_in=True,False
        elif name=="pipeline": in_pipe=True
        if in_in and name not in STRUCTURAL_BLOCKS and name!="pipeline":
            input_sources.append(InputSource(name, extract_input_source_details(node)))
        if in_out and name in KNOWN_TERMINAL_SINKS and name!="pipeline":
            sinks.append(SinkInfo(name, extract_sink_details(node)))
        for item in node.items:
            if isinstance(item, Assignment):
                k=item.key.lower()
                if in_pipe and in_in and k=="address":
                    s=scalar_text(item.value)
                    if s: inputs.append(s)
                elif in_pipe and in_out and k=="send_to": add_outputs(item.value)
            elif isinstance(item, Block): walk(item,in_in,in_out,in_pipe)
    walk(ast)
    return sorted(set(inputs)), sorted(set(outputs)), input_sources, sinks

def collect_conditionals(ast: Block):
    branch_count=0; max_depth=0
    def walk(node: Block, depth: int):
        nonlocal branch_count,max_depth
        if node.name.lower() in CONDITIONAL_BLOCK_NAMES:
            branch_count+=1; depth+=1; max_depth=max(max_depth,depth)
        for item in node.items:
            if isinstance(item, Block): walk(item,depth)
    walk(ast,0)
    return branch_count>0, branch_count, max_depth

def collect_processors_flat(ast: Block, include_custom: bool=False) -> List[ProcessorInstance]:
    """Legacy flat collector — kept for scoring."""
    found: List[ProcessorInstance] = []
    def is_plugin(node: Block, inside: bool) -> bool:
        if not inside: return False
        n=node.name.lower()
        if n in STRUCTURAL_BLOCKS: return False
        if n in OFFICIAL_FILTER_PLUGINS: return True
        if include_custom: return direct_assignment_count(node)>0
        return False
    def walk(node: Block, inside=False, cd=0, cc=0):
        n=node.name.lower()
        if n=="filter": inside=True
        elif n in ("input","output"): inside=False
        if n in CONDITIONAL_BLOCK_NAMES: cd+=1; cc+=1
        if is_plugin(node,inside):
            found.append(ProcessorInstance(
                plugin=n, direct_assignments=direct_assignment_count(node),
                metrics=processor_metrics(n,node), branch_depth=cd, conditional_count_along_path=cc))
        for item in node.items:
            if isinstance(item, Block): walk(item,inside,cd,cc)
    walk(ast); return found

def collect_filter_tree(ast: Block, raw_source: str = "", include_custom: bool = False) -> SequenceNode:
    """
    Build an ordered SequenceNode tree from the filter { } section.
    Preserves execution order and branch structure.
    raw_source: the original file text (with comments stripped) used to
    extract raw_config snippets for each plugin block.
    """
    seq_counter = [0]

    def next_seq() -> int:
        seq_counter[0] += 1
        return seq_counter[0]

    def is_plugin(node: Block) -> bool:
        n = node.name.lower()
        if n in STRUCTURAL_BLOCKS: return False
        if n in OFFICIAL_FILTER_PLUGINS: return True
        if include_custom: return direct_assignment_count(node) > 0
        return False

    def extract_raw(plugin_name: str, seq_idx: int) -> str:
        """Heuristically find the Nth occurrence of plugin_name { in raw_source."""
        # Count occurrences seen so far for this plugin
        occurrences = []
        pattern = re.compile(rf'(?i)\b{re.escape(plugin_name)}\s*\{{')
        for m in pattern.finditer(raw_source):
            brace = raw_source.find("{", m.start())
            if brace == -1: continue
            depth=0; in_str=False; quote=""; esc=False; end=None
            for k in range(brace, len(raw_source)):
                ch=raw_source[k]
                if esc: esc=False; continue
                if ch=="\\": esc=True; continue
                if in_str:
                    if ch==quote: in_str=False; quote=""
                    continue
                if ch in ("'",'"'): in_str=True; quote=ch; continue
                if ch=="{": depth+=1
                elif ch=="}":
                    depth-=1
                    if depth==0: end=k+1; break
            if end: occurrences.append(raw_source[m.start():end].strip())
        # Return the occurrence that corresponds to the counter for this plugin
        # (we track separately per-plugin in a dict)
        if not occurrences: return ""
        # Use the first available — caller tracks which instance this is
        return occurrences[0] if occurrences else ""

    # Per-plugin occurrence counter for raw extraction
    plugin_occurrence: Dict[str, int] = defaultdict(int)

    def get_raw_for_plugin(plugin_name: str) -> str:
        """Return the Nth raw block for plugin_name."""
        occurrences = []
        pattern = re.compile(rf'(?i)\b{re.escape(plugin_name)}\s*\{{')
        for m in pattern.finditer(raw_source):
            brace = raw_source.find("{", m.start())
            if brace == -1: continue
            depth=0; in_str=False; quote=""; esc=False; end=None
            for k in range(brace, len(raw_source)):
                ch=raw_source[k]
                if esc: esc=False; continue
                if ch=="\\": esc=True; continue
                if in_str:
                    if ch==quote: in_str=False; quote=""
                    continue
                if ch in ("'",'"'): in_str=True; quote=ch; continue
                if ch=="{": depth+=1
                elif ch=="}":
                    depth-=1
                    if depth==0: end=k+1; break
            if end: occurrences.append(raw_source[m.start():end].strip())
        n = plugin_occurrence[plugin_name]
        plugin_occurrence[plugin_name] += 1
        return occurrences[n] if n < len(occurrences) else ""

    def walk_sequence(node: Block, inside_filter: bool, depth: int, cond_path: List[str]) -> SequenceNode:
        seq = SequenceNode()
        name = node.name.lower()

        if name == "filter":
            inside_filter = True

        if not inside_filter:
            return seq

        # Iterate direct children in order
        i = 0
        children = node.items
        while i < len(children):
            item = children[i]
            if isinstance(item, Block):
                cname = item.name.lower()
                if cname == "if":
                    # Collect the full if/elsif/else chain
                    cond_node = ConditionalNode(seq_index=next_seq(), branch_depth=depth)
                    # Get the condition string from subsequent WORD tokens before LBRACE
                    # (already embedded in the block name via the tokenizer for "if")
                    # We use the block name as a proxy — the tokenizer captures "if" but
                    # not the condition expression. Extract it from raw source heuristically.
                    branch_body = walk_sequence(item, True, depth+1, cond_path + [f"if (branch)"])
                    cond_node.branches.append(ConditionalBranch(
                        condition="if (condition)",
                        branch_type="if",
                        body=branch_body,
                    ))
                    # Look ahead for elsif/else
                    j = i + 1
                    while j < len(children):
                        sibling = children[j]
                        if isinstance(sibling, Block) and sibling.name.lower() in ("elsif", "else if"):
                            sib_body = walk_sequence(sibling, True, depth+1, cond_path + ["elsif (branch)"])
                            cond_node.branches.append(ConditionalBranch(
                                condition="elsif (condition)",
                                branch_type="elsif",
                                body=sib_body,
                            ))
                            j += 1
                        elif isinstance(sibling, Block) and sibling.name.lower() == "else":
                            else_body = walk_sequence(sibling, True, depth+1, cond_path + ["else"])
                            cond_node.branches.append(ConditionalBranch(
                                condition="",
                                branch_type="else",
                                body=else_body,
                            ))
                            j += 1
                            break
                        else:
                            break
                    seq.children.append(cond_node)
                    i = j
                    continue
                elif cname in ("elsif", "else if", "else"):
                    # Already consumed by the if-lookahead above; skip
                    i += 1; continue
                elif is_plugin(item):
                    ii = get_ingest_info(cname)
                    pn = ProcessorNode(
                        plugin=cname,
                        seq_index=next_seq(),
                        branch_depth=depth,
                        condition_path=list(cond_path),
                        config=block_to_config(item),
                        raw_config=get_raw_for_plugin(cname),
                        direct_assignments=direct_assignment_count(item),
                        metrics=processor_metrics(cname, item),
                        ingest_status=ii.status,
                        ingest_processor=ii.ingest_processor,
                        ingest_note=ii.note,
                    )
                    seq.children.append(pn)
                else:
                    # Recurse into nested structural blocks (e.g. body blocks)
                    sub = walk_sequence(item, inside_filter, depth, cond_path)
                    seq.children.extend(sub.children)
            i += 1
        return seq

    # Find the filter block and walk it
    for item in ast.items:
        if isinstance(item, Block) and item.name.lower() == "filter":
            return walk_sequence(item, False, 0, [])
    return SequenceNode()

# ─────────────────────────────────────────────────────────────
# Scoring (unchanged from v11)
# ─────────────────────────────────────────────────────────────

def score_processor_instance(p: ProcessorInstance) -> int:
    plugin, m = p.plugin, p.metrics; score = 0
    if plugin=="mutate": score+=p.direct_assignments+m.get("rename_count",0)+m.get("convert_count",0)+m.get("add_field_count",0)//2+m.get("remove_field_count",0)//2+m.get("replace_count",0)
    elif plugin=="grok": score+=max(1,m.get("pattern_count",0)*3)+m.get("named_capture_count",0)//5+m.get("alternation_count",0)//5; score+=(2 if m.get("pattern_chars",0)>200 else 0)+(5 if m.get("pattern_chars",0)>1000 else 0)+m.get("overwrite_count",0)
    elif plugin=="ruby": score+=10+(1 if m.get("has_init") else 0)+m.get("inline_code_chars",0)//300+m.get("inline_code_lines",0)//5+m.get("loop_keywords",0)*2+(2 if m.get("external_path") else 0)+(3 if m.get("has_event_cancel") else 0)+(3 if m.get("has_require") else 0)+(5 if m.get("has_http") else 0)
    elif plugin=="translate": score+=2+m.get("dictionary_entries",0)//10+(3 if m.get("regex") else 0)
    elif plugin=="xml": score+=3+m.get("xpath_entries",0)//3
    elif plugin in ("json","geoip","kv","fingerprint"): score+=2*max(1,p.direct_assignments)
    elif plugin in ("csv",): score+=max(1,p.direct_assignments)+m.get("columns_count",0)//25
    elif plugin in ("dissect","date"): score+=max(1,p.direct_assignments)
    elif plugin=="aggregate": score+=8
    elif plugin=="elapsed": score+=4
    else: score+=max(1,p.direct_assignments)
    if p.branch_depth>0: score+=p.branch_depth
    return score

def summarize_processor_counts(processors: List[ProcessorInstance]) -> Dict[str, int]:
    counts: Dict[str,int] = {}
    for p in processors: counts[p.plugin]=counts.get(p.plugin,0)+p.direct_assignments
    return counts

def local_pipeline_score(processors, branch_count, local_outputs, terminal_sinks, unresolved=0):
    score=sum(score_processor_instance(p) for p in processors)
    if branch_count>0: score+=5+max(0,branch_count-1)*2
    if len(set(local_outputs))>1: score+=5
    if len(terminal_sinks)>1: score+=2
    if unresolved>0: score+=unresolved*3
    return score

def compute_migration_analysis(processors, branch_count, max_branch_depth, local_outputs, terminal_sinks, input_sources, flags, total_statements, total_score) -> MigrationAnalysis:
    reasons: List[str]=[]; penalties: Dict[str,int]={}; recommendations: List[str]=[]; input_blockers: List[str]=[]
    filter_score=100
    plugin_counts: Dict[str,int]={}
    for p in processors: plugin_counts[p.plugin]=plugin_counts.get(p.plugin,0)+1

    for plugin,count in plugin_counts.items():
        entry=MIGRATION_PENALTIES.get(plugin)
        if entry is None or entry[0]==0: continue
        base_pen,reason_text,rec=entry
        eff=base_pen+(count-1)*(base_pen//4)
        filter_score-=eff; reasons.append(f"{plugin}: {reason_text}"); penalties[plugin]=eff
        if rec: recommendations.append(f"{plugin} → {rec}")
        if plugin=="ruby":
            for p in processors:
                if p.plugin!="ruby": continue
                m=p.metrics
                if m.get("has_event_cancel"): filter_score-=5; reasons.append("ruby uses event.cancel"); penalties["ruby_event_cancel"]=5
                if m.get("has_require"): filter_score-=3; reasons.append("ruby uses require"); penalties["ruby_require"]=3
                if m.get("has_http"): filter_score-=5; reasons.append("ruby makes HTTP calls"); penalties["ruby_http"]=5

    if branch_count>0:
        bp=min(20,branch_count*2+max_branch_depth*3); filter_score-=bp
        reasons.append(f"conditional branching: {branch_count} branches, max depth {max_branch_depth}"); penalties["branching"]=bp

    unique_outputs=len(set(local_outputs))
    if unique_outputs>1: filter_score-=8; reasons.append(f"fan-out: {unique_outputs} outputs"); penalties["fanout"]=8
    if len(terminal_sinks)>1: filter_score-=5; reasons.append(f"multiple sinks: {len(terminal_sinks)}"); penalties["multi_sink"]=5
    if total_statements>100: filter_score-=8; reasons.append("very large pipeline"); penalties["large_size"]=8
    elif total_statements>50: filter_score-=4; reasons.append("large pipeline"); penalties["medium_size"]=4
    if total_score>250: filter_score-=10; reasons.append("very high complexity"); penalties["high_complexity"]=10
    elif total_score>120: filter_score-=5; reasons.append("moderate complexity"); penalties["moderate_complexity"]=5
    for fl in flags:
        if fl.startswith("duplicate_defs"): filter_score-=6; reasons.append("duplicate definitions"); penalties["duplicate_defs"]=6
        elif fl.startswith("unresolved"): filter_score-=8; reasons.append("unresolved routing"); penalties["unresolved"]=8

    filter_score=max(0,min(100,filter_score))
    full_score=filter_score; hard_ceiling: Optional[int]=None
    input_type_counts: Dict[str,int]={}
    for src in input_sources: t=src.input_type.lower(); input_type_counts[t]=input_type_counts.get(t,0)+1

    for itype,icount in input_type_counts.items():
        mkey=next((k for k in INPUT_REPLACEMENT_PENALTIES if k in itype),None)
        if mkey:
            ceil_val,flat_pen,ireason,irec=INPUT_REPLACEMENT_PENALTIES[mkey]
            input_blockers.append(ireason); recommendations.append(irec)
            if flat_pen: full_score-=flat_pen; penalties[f"input_{mkey}"]=flat_pen
            if ceil_val is not None:
                if hard_ceiling is None or ceil_val<hard_ceiling: hard_ceiling=ceil_val
            if mkey=="jdbc":
                for src2 in input_sources:
                    if src2.input_type.lower() not in ("jdbc","jdbc_static","jdbc_streaming"): continue
                    for dk,ep,expl in JDBC_EXTRA_PENALTIES:
                        if dk in src2.details: full_score-=ep; penalties[f"jdbc_{dk}"]=ep; input_blockers.append(expl)
                if icount>1: full_score-=10; penalties["jdbc_multi_source"]=10; input_blockers.append(f"Multiple JDBC inputs ({icount})")

    if hard_ceiling is not None: full_score=min(full_score,hard_ceiling)
    full_score=max(0,min(100,full_score))
    migration_class="Easy" if full_score>=EASY_THRESHOLD else "Medium" if full_score>=MEDIUM_THRESHOLD else "Hard"

    has_hard_filter=any(MIGRATION_PENALTIES.get(p,(0,))[0]>=10 for p in plugin_counts)
    has_medium_filter=any(MIGRATION_PENALTIES.get(p,(0,))[0] in range(5,10) for p in plugin_counts)
    has_jdbc=any("jdbc" in t for t in input_type_counts)
    has_non_agent=hard_ceiling is not None and hard_ceiling<=30
    many_outputs=unique_outputs>2 or len(terminal_sinks)>2
    heavy=total_statements>80 or total_score>150

    if has_jdbc:
        if any(dk in src.details for src in input_sources for dk,_,_ in JDBC_EXTRA_PENALTIES):
            pipeline_label="JDBC polling pipeline – requires alternative ingestion strategy"
        else: pipeline_label="JDBC input – filter may migrate to ingest; input cannot"
    elif has_non_agent: pipeline_label="Input not replaceable by Elastic Agent – redesign data pipeline"
    elif migration_class=="Hard" or has_hard_filter: pipeline_label="Requires redesign – hard blockers"
    elif many_outputs: pipeline_label="Multi-output complex pipeline"
    elif heavy: pipeline_label="Heavy transformation pipeline"
    elif has_medium_filter: pipeline_label="Needs attention – medium blockers"
    else: pipeline_label="Simple ingest candidate"

    return MigrationAnalysis(filter_transform_score=filter_score, full_replacement_score=full_score,
        score=full_score, migration_class=migration_class, pipeline_label=pipeline_label,
        reasons=reasons, penalties=penalties, recommendations=recommendations, input_blockers=input_blockers)

# ─────────────────────────────────────────────────────────────
# File analysis
# ─────────────────────────────────────────────────────────────

def read_text(path: Path) -> str:
    for enc in ("utf-8","utf-8-sig","cp1252","latin-1"):
        try: return path.read_text(encoding=enc)
        except Exception: pass
    return path.read_text(errors="replace")

def analyze_file(path: Path, include_custom: bool=False) -> FileAnalysis:
    raw = read_text(path).replace("\r\n","\n").replace("\r","\n")
    text = normalize_arrows(raw)
    text_nc = strip_comments(text)
    regex_in, regex_out = regex_pipeline_sanity(text_nc)
    ast = parse_blocks(tokenize(text_nc))
    inputs, outputs, input_sources, sinks = collect_pipeline_io_sources_and_sinks(ast)
    processors = collect_processors_flat(ast, include_custom)
    filter_tree = collect_filter_tree(ast, text_nc, include_custom)
    has_cond, branch_count, max_depth = collect_conditionals(ast)

    # Extract raw block texts
    def first_raw(block_name: str) -> str:
        hits = extract_named_blocks_raw(text_nc, block_name)
        return hits[0][2] if hits else ""

    return FileAnalysis(
        file=str(path), pipeline_inputs=inputs, pipeline_outputs=outputs,
        input_sources=input_sources, terminal_sinks=sinks, processors=processors,
        filter_tree=filter_tree, has_conditionals=has_cond,
        branch_count=branch_count, max_branch_depth=max_depth,
        regex_pipeline_input_hits=regex_in, regex_pipeline_output_hits=regex_out,
        raw_filter_text=first_raw("filter"),
        raw_input_text=first_raw("input"),
        raw_output_text=first_raw("output"),
    )

# ─────────────────────────────────────────────────────────────
# Split-file grouping  (NEW in v12.1)
# ─────────────────────────────────────────────────────────────
#
# Many Logstash deployments split a logical pipeline across two files:
#   <base>_io.conf     — contains input {} and output {} blocks
#   <base>_filter.conf — contains filter {} block
#
# Files are considered siblings when they are in the SAME directory and
# share the same base name (case-insensitive).
#
# Group key = "<absolute_dir>#<base_lower>"
# This keeps same-named pipelines in different customer directories apart.

import re as _re   # already imported, alias just for clarity

_SPLIT_PATTERN = _re.compile(r'^(.+?)_(io|filter)$', _re.IGNORECASE)

def _split_group_key(path: Path) -> Optional[str]:
    """
    Return "<abs_dir>#<base_lower>" if path matches <base>_(io|filter).conf,
    otherwise None.
    """
    stem = path.stem          # filename without .conf
    m = _SPLIT_PATTERN.match(stem)
    if not m:
        return None
    base = m.group(1).lower()
    return f"{path.parent.resolve()}#{base}"

def _make_merged_fa(group_files: List[FileAnalysis], root: Path) -> FileAnalysis:
    """
    Merge a list of FileAnalysis objects (all fragments of one logical pipeline)
    into a single FileAnalysis following the spec:
      - Union:  pipeline_inputs, pipeline_outputs, input_sources, terminal_sinks
      - Concat: processors (order: io-file first, then filter-file)
      - filter_tree: concatenate children of all SequenceNode roots
      - has_conditionals = OR
      - branch_count = SUM
      - max_branch_depth = MAX
      - raw texts: pick first non-empty from each fragment
    The .file attribute is set to the first file in sorted order.
    """
    # Stable order: sort so _io comes before _filter
    fragments = sorted(group_files, key=lambda fa: fa.file)

    merged_inputs:   List[str]             = []
    merged_outputs:  List[str]             = []
    merged_sources:  List[InputSource]     = []
    merged_sinks:    List[SinkInfo]        = []
    merged_procs:    List[ProcessorInstance] = []
    tree_children:   List                  = []
    has_cond         = False
    branch_count     = 0
    max_depth        = 0
    raw_filter       = ""
    raw_input        = ""
    raw_output       = ""
    seen_inputs:     set = set()
    seen_outputs:    set = set()

    for fa in fragments:
        for v in fa.pipeline_inputs:
            if v not in seen_inputs:
                seen_inputs.add(v); merged_inputs.append(v)
        for v in fa.pipeline_outputs:
            if v not in seen_outputs:
                seen_outputs.add(v); merged_outputs.append(v)
        merged_sources.extend(fa.input_sources)
        merged_sinks.extend(fa.terminal_sinks)
        merged_procs.extend(fa.processors)
        tree_children.extend(fa.filter_tree.children)
        has_cond = has_cond or fa.has_conditionals
        branch_count += fa.branch_count
        max_depth = max(max_depth, fa.max_branch_depth)
        if not raw_filter and fa.raw_filter_text: raw_filter = fa.raw_filter_text
        if not raw_input  and fa.raw_input_text:  raw_input  = fa.raw_input_text
        if not raw_output and fa.raw_output_text: raw_output = fa.raw_output_text

    merged_tree = SequenceNode(children=tree_children)
    primary_file = fragments[0].file

    return FileAnalysis(
        file=primary_file,
        pipeline_inputs=merged_inputs,
        pipeline_outputs=merged_outputs,
        input_sources=merged_sources,
        terminal_sinks=merged_sinks,
        processors=merged_procs,
        filter_tree=merged_tree,
        has_conditionals=has_cond,
        branch_count=branch_count,
        max_branch_depth=max_depth,
        regex_pipeline_input_hits=[],   # not used downstream
        regex_pipeline_output_hits=[],
        raw_filter_text=raw_filter,
        raw_input_text=raw_input,
        raw_output_text=raw_output,
    )

def group_split_files(
    analyses: List[FileAnalysis],
    root: Path,
) -> Tuple[List[FileAnalysis], List[Tuple[str, List[str]]]]:
    """
    Detect <base>_io.conf / <base>_filter.conf sibling pairs, merge them,
    and return:
      - merged_analyses : List[FileAnalysis]  (groups replaced by one merged FA;
                           unmatched files unchanged)
      - group_info      : List[(group_key, [file_paths])]  for reporting

    Files that do NOT match the <base>_(io|filter) pattern are passed through
    unchanged.  Files that match but whose sibling is absent in the scan are
    also passed through unchanged (warn instead of silently dropping them).
    """
    # Bucket analyses by group key
    buckets: Dict[str, List[FileAnalysis]] = defaultdict(list)
    no_group: List[FileAnalysis] = []

    for fa in analyses:
        key = _split_group_key(Path(fa.file))
        if key:
            buckets[key].append(fa)
        else:
            no_group.append(fa)

    merged_analyses: List[FileAnalysis] = list(no_group)
    group_info: List[Tuple[str, List[str]]] = []

    for key, fragments in buckets.items():
        file_paths = sorted(fa.file for fa in fragments)
        group_info.append((key, file_paths))

        if len(fragments) == 1:
            # Lone split fragment with no sibling — treat as standalone
            merged_analyses.append(fragments[0])
        else:
            merged = _make_merged_fa(fragments, root)
            # Stash all contributing file paths on the merged FA for downstream
            merged._fragment_files = file_paths   # type: ignore[attr-defined]
            merged_analyses.append(merged)

    return merged_analyses, group_info

# ─────────────────────────────────────────────────────────────
# Graph building (unchanged from v11, extended for filter_tree)
# ─────────────────────────────────────────────────────────────

def make_synthetic_pipeline_id(file_path: str, root: Path) -> str:
    p=Path(file_path)
    try: rel=p.relative_to(root)
    except Exception: rel=p
    return f"@file:{rel.as_posix()}"

def build_pipeline_definitions(files: List[FileAnalysis], root: Path) -> List[PipelineDefinition]:
    """
    Convert FileAnalysis objects into PipelineDefinition records.

    Handles three cases per file/merged-group:
      Case A: pipeline_inputs present  → one PipelineDefinition per address
      Case B: no pipeline_inputs but input_sources present  → synthetic @file address
      Case C: neither → skip (pure filter fragment with no routing context)

    All contributing file paths are stored in PipelineDefinition.files.
    """
    defs: List[PipelineDefinition] = []
    for fr in files:
        # Recover all contributing files (set by group_split_files for merged FAs)
        all_files: List[str] = sorted(
            getattr(fr, "_fragment_files", None) or [fr.file]
        )
        primary = all_files[0]

        def make(addr: str) -> PipelineDefinition:
            return PipelineDefinition(
                pipeline_address=addr,
                file=primary,
                files=all_files,
                local_outputs=list(fr.pipeline_outputs),
                input_sources=list(fr.input_sources),
                terminal_sinks=list(fr.terminal_sinks),
                processors=list(fr.processors),
                filter_tree=fr.filter_tree,
                has_conditionals=fr.has_conditionals,
                branch_count=fr.branch_count,
                max_branch_depth=fr.max_branch_depth,
                local_statement_total=sum(p.direct_assignments for p in fr.processors),
                local_score=0,
            )

        if fr.pipeline_inputs:
            for addr in fr.pipeline_inputs:
                defs.append(make(addr))
        elif fr.input_sources:
            defs.append(make(make_synthetic_pipeline_id(primary, root)))
        # else: Case C — no routing context, skip silently

    return defs

def assign_local_scores(defs: List[PipelineDefinition], all_addresses: set) -> None:
    for d in defs:
        unresolved=sum(1 for o in d.local_outputs if o not in all_addresses)
        d.local_score=local_pipeline_score(d.processors,d.branch_count,d.local_outputs,d.terminal_sinks,unresolved)

def definition_label(d: PipelineDefinition) -> str:
    if len(d.files) > 1:
        names = "+".join(Path(f).name for f in sorted(d.files))
        return f"{d.pipeline_address} [{names}]"
    return f"{d.pipeline_address} [{Path(d.file).name}]"

def build_logical_address_rollup(defs: List[PipelineDefinition]) -> Dict[str, Dict[str, Any]]:
    gd: Dict[str,List[PipelineDefinition]] = defaultdict(list)
    for d in defs: gd[d.pipeline_address].append(d)
    by_addr: Dict[str,Dict[str,Any]] = {}
    for addr,items in gd.items():
        pc=Counter(); sinks=[]; outputs=[]; sources=[]; files=[]
        ls=0; st=0; bc=0; md=0; procs=[]; isrcs=[]; tsinks=[]; ftrees=[]
        for d in items:
            pc.update(summarize_processor_counts(d.processors))
            sinks.extend(s.label() for s in d.terminal_sinks)
            outputs.extend(d.local_outputs)
            sources.extend(s.label() for s in d.input_sources)
            files.extend(d.files); ls+=d.local_score; st+=d.local_statement_total
            bc+=d.branch_count; md=max(md,d.max_branch_depth)
            procs.extend(d.processors); isrcs.extend(d.input_sources)
            tsinks.extend(d.terminal_sinks); ftrees.append(d.filter_tree)
        by_addr[addr]={"definitions":items,"files":sorted(files),"input_sources":sorted(set(sources)),
            "local_processor_counts":dict(pc),"local_outputs":sorted(set(outputs)),
            "terminal_sinks":sorted(set(sinks)),"local_score":ls,"local_statement_total":st,
            "branch_count":bc,"max_branch_depth":md,"_processors":procs,
            "_input_sources":isrcs,"_terminal_sinks":tsinks,"_filter_trees":ftrees}
    return by_addr

def build_logical_edges(defs: List[PipelineDefinition]) -> Dict[str, List[str]]:
    grouped=build_logical_address_rollup(defs); all_addrs=set(grouped.keys())
    edges: Dict[str,List[str]] = defaultdict(list)
    for addr,info in grouped.items():
        for src in info["input_sources"]: edges[src].append(addr)
        for out in info["local_outputs"]: edges[addr].append(out if out in all_addrs else f"UNRESOLVED:{out}")
        for sink in info["terminal_sinks"]: edges[addr].append(sink)
        edges.setdefault(addr,[])
    return {k:sorted(set(v)) for k,v in edges.items()}

def collect_starts(logical_edges: Dict[str,List[str]]) -> List[str]:
    nodes=set(logical_edges.keys()); inbound: Counter=Counter()
    for _,dsts in logical_edges.items():
        for d in dsts:
            if d in nodes: inbound[d]+=1
    return [n for n in sorted(nodes) if inbound[n]==0]

def dfs_paths(edges: Dict[str,List[str]], start: str, max_paths: int=128):
    out: List[List[str]] = []
    def walk(node,path,seen):
        if len(out)>=max_paths: return
        if node in seen: out.append(path+["<CYCLE>"]); return
        seen=set(seen); seen.add(node); nexts=edges.get(node,[])
        if not nexts: out.append(path); return
        for nxt in nexts: walk(nxt,path+[nxt],seen)
    walk(start,[start],set()); return out

def aggregate_logical_pipeline(addr, grouped, logical_edges, memo, stack=None):
    if addr in memo: return memo[addr]
    if stack is None: stack=set()
    if addr in stack: return {"processor_counts":{},"total_statements":0,"total_score":0,"cycle":True}
    stack=set(stack); stack.add(addr); info=grouped.get(addr,{})
    pc=Counter(info.get("local_processor_counts",{}))
    ts=int(info.get("local_statement_total",0)); tsc=int(info.get("local_score",0))
    for nxt in logical_edges.get(addr,[]):
        if nxt.startswith(("SINK:","UNRESOLVED:","SOURCE:")): continue
        child=aggregate_logical_pipeline(nxt,grouped,logical_edges,memo,stack)
        pc.update(child["processor_counts"]); ts+=child["total_statements"]; tsc+=child["total_score"]
    result={"processor_counts":dict(pc),"total_statements":ts,"total_score":tsc,"cycle":False}
    memo[addr]=result; return result

# ─────────────────────────────────────────────────────────────
# Formatting helpers
# ─────────────────────────────────────────────────────────────

def fmt_proc_counts(d: Dict[str,int]) -> str:
    return "-" if not d else ", ".join(f"{k}:{d[k]}" for k in sorted(d))

def fmt_flow_paths(paths, max_paths=4) -> str:
    if not paths: return "-"
    shown=[" -> ".join(p) for p in paths[:max_paths]]
    if len(paths)>max_paths: shown.append(f"... ({len(paths)-max_paths} more)")
    return " || ".join(shown)

def write_csv(path: str, logical_rows: List[Dict[str, Any]]) -> None:
    fieldnames=["pipeline","migration_class","pipeline_label","full_replacement_score",
        "filter_transform_score","complexity_score","total_statements","migration_reasons",
        "input_blockers","recommendations","penalties","local_processors",
        "aggregated_processors","terminal_sinks","input_sources","flags"]
    with open(path,"w",newline="",encoding="utf-8") as fh:
        writer=csv.DictWriter(fh,fieldnames=fieldnames); writer.writeheader()
        for row in logical_rows:
            mig=row.get("migration",{})
            writer.writerow({"pipeline":row.get("pipeline",""),"migration_class":mig.get("migration_class",""),
                "pipeline_label":mig.get("pipeline_label",""),"full_replacement_score":mig.get("full_replacement_score",""),
                "filter_transform_score":mig.get("filter_transform_score",""),"complexity_score":row.get("total_score",""),
                "total_statements":row.get("total_statements",""),"migration_reasons":" | ".join(mig.get("reasons",[])),
                "input_blockers":" | ".join(mig.get("input_blockers",[])),"recommendations":" | ".join(mig.get("recommendations",[])),
                "penalties":json.dumps(mig.get("penalties",{})),"local_processors":fmt_proc_counts(row.get("local_processors",{})),
                "aggregated_processors":fmt_proc_counts(row.get("aggregated_processors",{})),
                "terminal_sinks":", ".join(row.get("terminal_sinks",[])),"input_sources":", ".join(row.get("input_sources",[])),
                "flags":", ".join(row.get("flags",[]))})

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main():
    ap=argparse.ArgumentParser(description="Logstash pipeline analyzer v12 — ordered filter tree + ingest compatibility")
    ap.add_argument("root"); ap.add_argument("--json-out"); ap.add_argument("--csv-out")
    ap.add_argument("--top-n",type=int,default=50); ap.add_argument("--include-custom-filters",action="store_true")
    args=ap.parse_args()

    root=Path(args.root); files=sorted(root.rglob("*.conf"))
    print(f"Scanned {len(files)} .conf files under {root}\n")

    analyses: List[FileAnalysis]=[]; warnings: List[Tuple[str,str]]=[]
    for f in files:
        try: analyses.append(analyze_file(f,include_custom=args.include_custom_filters))
        except Exception as e: warnings.append((str(f),str(e)))

    # ── Group split-file pairs BEFORE building definitions ────
    analyses, split_groups = group_split_files(analyses, root)

    # Report merges so the user knows what was grouped
    merged_groups = [(k, fps) for k, fps in split_groups if len(fps) > 1]
    if merged_groups:
        print(f"Detected {len(merged_groups)} split-file pipeline group(s):")
        for key, fps in sorted(merged_groups):
            base = key.split("#", 1)[-1]
            print(f"  [{base}]  ←  {', '.join(Path(f).name for f in fps)}")
        print()

    defs=build_pipeline_definitions(analyses,root); all_addresses={d.pipeline_address for d in defs}
    assign_local_scores(defs,all_addresses)
    defs_by_addr: Dict[str,List[PipelineDefinition]]=defaultdict(list)
    for d in defs: defs_by_addr[d.pipeline_address].append(d)
    duplicate_addrs={k:v for k,v in defs_by_addr.items() if len(v)>1}

    grouped=build_logical_address_rollup(defs); logical_edges=build_logical_edges(defs)
    starts=collect_starts(logical_edges); agg_memo: Dict[str,Dict[str,Any]]={}
    logical_rows: List[Dict[str,Any]]=[]

    for addr,info in grouped.items():
        agg=aggregate_logical_pipeline(addr,grouped,logical_edges,agg_memo)
        paths=dfs_paths(logical_edges,addr); flags: List[str]=[]
        if addr in starts: flags.append("start")
        if len(info.get("definitions",[]))>1: flags.append(f"duplicate_defs={len(info['definitions'])}")
        if not info.get("local_outputs") and not info.get("terminal_sinks"): flags.append("dead_end")
        unresolved=[x for x in logical_edges.get(addr,[]) if x.startswith("UNRESOLVED:")]
        if unresolved: flags.append(f"unresolved={len(unresolved)}")

        mig=compute_migration_analysis(info.get("_processors",[]),info.get("branch_count",0),
            info.get("max_branch_depth",0),info.get("local_outputs",[]),info.get("_terminal_sinks",[]),
            info.get("_input_sources",[]),flags,agg["total_statements"],agg["total_score"])

        # Merge filter trees from all definitions for this address
        merged_tree=info.get("_filter_trees",[])
        combined_tree = merged_tree[0] if len(merged_tree)==1 else SequenceNode(children=[c for t in merged_tree for c in t.children])

        logical_rows.append({
            "pipeline":addr,"input_sources":info.get("input_sources",[]),
            "local_processors":info.get("local_processor_counts",{}),"aggregated_processors":agg["processor_counts"],
            "total_statements":agg["total_statements"],"local_score":info.get("local_score",0),
            "downstream_score":agg["total_score"]-info.get("local_score",0),"total_score":agg["total_score"],
            "flow_chains":paths,"flags":flags,"files":info.get("files",[]),
            "terminal_sinks":info.get("terminal_sinks",[]),"local_outputs":info.get("local_outputs",[]),
            "migration":asdict(mig),
            "migration_score":mig.full_replacement_score,"filter_transform_score":mig.filter_transform_score,
            "full_replacement_score":mig.full_replacement_score,"migration_class":mig.migration_class,
            "pipeline_label":mig.pipeline_label,"migration_reasons":mig.reasons,"input_blockers":mig.input_blockers,
            # NEW v12 fields
            "processors_ordered": filter_tree_to_dict(combined_tree),
            "raw_filter_text": next((fa.raw_filter_text for fa in analyses if fa.file in info.get("files",[])), ""),
            "raw_input_text":  next((fa.raw_input_text  for fa in analyses if fa.file in info.get("files",[])), ""),
            "raw_output_text": next((fa.raw_output_text for fa in analyses if fa.file in info.get("files",[])), ""),
        })

    logical_rows.sort(key=lambda r:(r["migration_class"]!="Hard",r["migration_class"]!="Medium",-r["total_score"]))

    print("=== MIGRATION REPORT ===")
    print(f"{'PIPELINE':<40} {'CLASS':<8} {'FULL':>4} {'FILT':>4} {'CMPLX':>6} {'STMTS':>5}  LABEL")
    print("-"*110)
    for row in logical_rows[:args.top_n]:
        mig=row["migration"]
        gap=mig["filter_transform_score"]-mig["full_replacement_score"]
        gap_flag=f" ⚠gap:{gap:+d}" if gap>=20 else ""
        print(f"{row['pipeline']:<40} {mig['migration_class']:<8} {mig['full_replacement_score']:>4} {mig['filter_transform_score']:>4} {row['total_score']:>6} {row['total_statements']:>5}  {mig['pipeline_label']}{gap_flag}")

    print("\n=== INGEST COMPATIBILITY SUMMARY ===")
    status_counts: Counter=Counter()
    for row in logical_rows:
        tree_dict=row.get("processors_ordered",{})
        def count_statuses(node_dict):
            if node_dict.get("node_type")=="processor":
                status_counts[node_dict.get("ingest_status","partial")]+=1
            elif node_dict.get("node_type")=="sequence":
                for c in node_dict.get("children",[]): count_statuses(c)
            elif node_dict.get("node_type")=="conditional":
                for b in node_dict.get("branches",[]): count_statuses(b.get("body",{}))
        count_statuses(tree_dict)
    total_procs=sum(status_counts.values())
    for status in ("supported","partial","unsupported"):
        n=status_counts.get(status,0)
        pct=f"{100*n//total_procs}%" if total_procs else "0%"
        print(f"  {status:<12}: {n:4d} ({pct})")

    if warnings:
        print("\n=== WARNINGS ===",file=sys.stderr)
        for f,msg in warnings[:100]: print(f"[WARN] {f}: {msg}",file=sys.stderr)

    if args.json_out:
        out={"overall_summary":{"scan_root":str(root),"files_analyzed":len(analyses),
            "pipeline_definitions":len(defs),"unique_logical_pipelines":len(logical_rows),
            "ingest_status_totals":dict(status_counts)},
            "logical_pipelines":logical_rows,"logical_edges":logical_edges,
            "warnings":[{"file":f,"message":m} for f,m in warnings]}
        Path(args.json_out).write_text(json.dumps(out,indent=2,ensure_ascii=False),encoding="utf-8")
        print(f"\nJSON written: {args.json_out}")

    if args.csv_out:
        write_csv(args.csv_out,logical_rows)
        print(f"CSV  written: {args.csv_out}")

if __name__=="__main__": main()
