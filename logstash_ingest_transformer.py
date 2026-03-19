#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logstash_ingest_transformer.py
═══════════════════════════════════════════════════════════════════════════
Stage 2 of the Logstash → Elasticsearch Ingest Migration System.

Takes the v12 analyzer JSON output and generates:
  1. Elasticsearch ingest pipeline JSON  (per pipeline)
  2. Migration plan text report          (per pipeline)
  3. Coverage score                      (0.0–1.0)

Usage:
  python logstash_ingest_transformer.py analysis.json --out-dir ./output/
  python logstash_ingest_transformer.py analysis.json --pipeline myapp --stdout

Output per pipeline (in --out-dir):
  <pipeline_id>.ingest.json   — ready to PUT to /_ingest/pipeline/<id>
  <pipeline_id>.plan.md       — migration plan in Markdown
  migration_summary.json      — aggregate report across all pipelines

Architecture
────────────
The transformer walks the processors_ordered tree from the analyzer JSON.
For each ProcessorNode it calls a plugin-specific translator function that
returns either:
  - one or more ES ingest processor dicts  (supported/partial)
  - a stub with on_failure handler         (unsupported — runtime skip)
  - a comment-stub                         (completely unsupported)

Mutate is split into its sub-actions in execution order:
  rename, convert, add_field, remove_field, add_tag → remove_field,
  gsub → gsub (not native; falls back to script), uppercase/lowercase,
  strip, replace → script.

Conditional branches become if-condition guards on each processor group
(ES ingest pipelines support 'if' on every processor via Painless).

Coverage = supported_processors / total_processors
═══════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────
# Logstash field reference → ES field reference conversion
# ─────────────────────────────────────────────────────────────

def ls_field_to_es(field: str) -> str:
    """
    Convert a Logstash field reference to an ES ingest pipeline field path.
    [a][b][c] → a.b.c
    [field]   → field
    field     → field
    """
    if not field: return field
    # Strip outer braces if it's a full reference like [a][b]
    parts = re.findall(r'\[([^\]]+)\]', field)
    if parts: return ".".join(parts)
    return field.strip()

def ls_field_to_painless(field: str) -> str:
    """Convert a Logstash field ref to Painless ctx access: [a][b] → ctx['a']['b']"""
    parts = re.findall(r'\[([^\]]+)\]', field)
    if not parts:
        return f"ctx['{field.strip()}']"
    return "".join(f"['{p}']" for p in ["ctx"] + parts).replace("]['","[\"").replace("']","\"']")

def _ctx(field: str) -> str:
    """Return ctx.field for simple fields, ctx['field'] for dotted."""
    f = ls_field_to_es(field)
    if "." in f:
        return "ctx['" + f.replace(".", "']['") + "']"
    return f"ctx.{f}"

# ─────────────────────────────────────────────────────────────
# Translation result
# ─────────────────────────────────────────────────────────────

class TranslationResult:
    def __init__(self):
        self.processors: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.coverage_supported: int = 0    # count of fully supported sub-actions
        self.coverage_total: int = 0        # count of all sub-actions attempted

    def add_processor(self, proc: Dict[str, Any], supported: bool = True):
        self.processors.append(proc)
        self.coverage_total += 1
        if supported: self.coverage_supported += 1

    def add_warning(self, msg: str):
        self.warnings.append(msg)

# ─────────────────────────────────────────────────────────────
# Per-plugin translators
# ─────────────────────────────────────────────────────────────

def translate_grok(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    match = config.get("match", {})
    if isinstance(match, dict):
        for source_field, patterns in match.items():
            if isinstance(patterns, str): patterns = [patterns]
            for pattern in patterns:
                proc: Dict[str, Any] = {
                    "grok": {
                        "field": ls_field_to_es(source_field),
                        "patterns": [pattern],
                    }
                }
                if config.get("tag_on_failure"):
                    proc["grok"]["tag_on_failure"] = config["tag_on_failure"] if isinstance(config["tag_on_failure"], list) else [config["tag_on_failure"]]
                if config.get("overwrite"): proc["grok"]["trace_match"] = True
                if condition: proc["grok"]["if"] = condition
                r.add_processor(proc, supported=True)
    elif isinstance(match, list) and len(match) >= 2:
        # Array form: [field, pattern, field, pattern, ...]
        for i in range(0, len(match) - 1, 2):
            proc = {"grok": {"field": ls_field_to_es(match[i]), "patterns": [match[i+1]]}}
            if condition: proc["grok"]["if"] = condition
            r.add_processor(proc, supported=True)
    if not r.processors:
        r.add_warning("grok: could not parse match configuration")
        r.add_processor({"grok": {"field": "message", "patterns": ["%{GREEDYDATA}"], "_comment": "REVIEW: original match not parsed"}}, supported=False)
    return r

def translate_date(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    match = config.get("match", [])
    if isinstance(match, list) and len(match) >= 2:
        source = ls_field_to_es(match[0])
        formats = match[1:]
        proc: Dict[str, Any] = {
            "date": {
                "field": source,
                "formats": formats,
                "target_field": ls_field_to_es(config.get("target", "@timestamp")),
            }
        }
        if config.get("timezone"): proc["date"]["timezone"] = config["timezone"]
        if condition: proc["date"]["if"] = condition
        r.add_processor(proc, supported=True)
    else:
        r.add_warning("date: could not parse match configuration")
        r.add_processor({"date": {"field": "timestamp", "formats": ["ISO8601"], "_comment": "REVIEW: original match not parsed"}}, supported=False)
    return r

def translate_mutate(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    """
    Split mutate into individual ES ingest processors in Logstash execution order.
    Logstash mutate order: coerce, rename, update, replace, convert, gsub,
    merge, copy, split, join, strip, remove, lowercase, uppercase, capitalize,
    add_field, add_tag, remove_field, remove_tag.
    """
    r = TranslationResult()

    def cond_wrap(inner: Dict[str, Any]) -> Dict[str, Any]:
        if condition:
            # inject if into the innermost processor
            proc_type = list(inner.keys())[0]
            inner[proc_type]["if"] = condition
        return inner

    # rename → rename processor
    rename = config.get("rename", {})
    if isinstance(rename, dict):
        for src, dst in rename.items():
            r.add_processor(cond_wrap({"rename": {"field": ls_field_to_es(src), "target_field": ls_field_to_es(dst), "ignore_missing": True}}), supported=True)

    # convert → convert processor
    convert = config.get("convert", {})
    TYPE_MAP = {"integer": "long", "float": "double", "string": "string", "boolean": "boolean", "long": "long", "double": "double"}
    if isinstance(convert, dict):
        for fld, typ in convert.items():
            es_type = TYPE_MAP.get(str(typ).lower(), "string")
            r.add_processor(cond_wrap({"convert": {"field": ls_field_to_es(fld), "type": es_type, "ignore_missing": True}}), supported=True)

    # add_field → set processor
    add_field = config.get("add_field", {})
    if isinstance(add_field, dict):
        for fld, val in add_field.items():
            r.add_processor(cond_wrap({"set": {"field": ls_field_to_es(fld), "value": val}}), supported=True)

    # replace → set (overwrite)
    replace = config.get("replace", {})
    if isinstance(replace, dict):
        for fld, val in replace.items():
            r.add_processor(cond_wrap({"set": {"field": ls_field_to_es(fld), "value": val, "override": True}}), supported=True)
    elif isinstance(replace, list):
        for i in range(0, len(replace)-1, 2):
            r.add_processor(cond_wrap({"set": {"field": ls_field_to_es(replace[i]), "value": replace[i+1], "override": True}}), supported=True)

    # remove_field → remove processor
    remove_field = config.get("remove_field", [])
    if isinstance(remove_field, list) and remove_field:
        for fld in remove_field:
            r.add_processor(cond_wrap({"remove": {"field": ls_field_to_es(fld), "ignore_missing": True}}), supported=True)
    elif isinstance(remove_field, str) and remove_field:
        r.add_processor(cond_wrap({"remove": {"field": ls_field_to_es(remove_field), "ignore_missing": True}}), supported=True)

    # add_tag → set (append to tags array)
    add_tag = config.get("add_tag", [])
    if isinstance(add_tag, list) and add_tag:
        for tag in add_tag:
            r.add_processor(cond_wrap({"append": {"field": "tags", "value": tag, "allow_duplicates": False}}), supported=True)
    elif isinstance(add_tag, str) and add_tag:
        r.add_processor(cond_wrap({"append": {"field": "tags", "value": add_tag, "allow_duplicates": False}}), supported=True)

    # remove_tag → script (no native remove_tag)
    remove_tag = config.get("remove_tag", [])
    if isinstance(remove_tag, (list, str)) and remove_tag:
        tags = [remove_tag] if isinstance(remove_tag, str) else remove_tag
        for tag in tags:
            script = f"if (ctx.tags != null) {{ ctx.tags.removeIf(t -> t == '{tag}'); }}"
            proc = {"script": {"lang": "painless", "source": script, "_comment": f"remove_tag: {tag}"}}
            if condition: proc["script"]["if"] = condition
            r.add_processor(proc, supported=True)

    # uppercase / lowercase → uppercase/lowercase processors
    for action in ("uppercase", "lowercase"):
        fields = config.get(action, [])
        if isinstance(fields, str): fields = [fields]
        for fld in fields:
            r.add_processor(cond_wrap({action: {"field": ls_field_to_es(fld), "ignore_missing": True}}), supported=True)

    # strip → trim processor
    strip_fields = config.get("strip", [])
    if isinstance(strip_fields, str): strip_fields = [strip_fields]
    for fld in strip_fields:
        r.add_processor(cond_wrap({"trim": {"field": ls_field_to_es(fld), "ignore_missing": True}}), supported=True)

    # gsub → gsub processor
    gsub = config.get("gsub", [])
    if isinstance(gsub, list) and len(gsub) >= 3:
        for i in range(0, len(gsub)-2, 3):
            proc = {"gsub": {"field": ls_field_to_es(gsub[i]), "pattern": gsub[i+1], "replacement": gsub[i+2], "ignore_missing": True}}
            if condition: proc["gsub"]["if"] = condition
            r.add_processor(proc, supported=True)

    # copy → set with copy_from
    copy = config.get("copy", {})
    if isinstance(copy, dict):
        for src, dst in copy.items():
            r.add_processor(cond_wrap({"set": {"field": ls_field_to_es(dst), "copy_from": ls_field_to_es(src), "ignore_empty_value": True}}), supported=True)

    # split → split processor
    split = config.get("split", {})
    if isinstance(split, dict):
        for fld, sep in split.items():
            r.add_processor(cond_wrap({"split": {"field": ls_field_to_es(fld), "separator": re.escape(sep), "ignore_missing": True}}), supported=True)

    if not r.processors:
        r.add_warning("mutate: no translatable sub-actions found in config")

    return r

def translate_geoip(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    source = ls_field_to_es(config.get("source", "ip"))
    proc: Dict[str, Any] = {
        "geoip": {
            "field": source,
            "target_field": ls_field_to_es(config.get("target", "geoip")),
            "ignore_missing": True,
        }
    }
    if config.get("fields"):
        # Map Logstash field names to ES property names
        field_map = {"city_name": "city_name", "country_name": "country_name", "latitude": "location",
                     "longitude": "location", "ip": "ip", "timezone": "timezone", "region_name": "region_name"}
        props = list({field_map.get(f, f) for f in config["fields"]})
        proc["geoip"]["properties"] = props
    if condition: proc["geoip"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_useragent(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    proc: Dict[str, Any] = {
        "user_agent": {
            "field": ls_field_to_es(config.get("source", "agent")),
            "target_field": ls_field_to_es(config.get("target", "user_agent")),
            "ignore_missing": True,
        }
    }
    if condition: proc["user_agent"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_json(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    proc: Dict[str, Any] = {
        "json": {
            "field": ls_field_to_es(config.get("source", "message")),
            "add_to_root": not bool(config.get("target")),
        }
    }
    if config.get("target"):
        proc["json"]["target_field"] = ls_field_to_es(config["target"])
    if condition: proc["json"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_kv(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    proc: Dict[str, Any] = {
        "kv": {
            "field": ls_field_to_es(config.get("source", "message")),
            "field_split": config.get("field_split", " "),
            "value_split": config.get("value_split", "="),
            "ignore_missing": True,
        }
    }
    if config.get("target"): proc["kv"]["target_field"] = ls_field_to_es(config["target"])
    if config.get("prefix"): proc["kv"]["prefix"] = config["prefix"]
    if condition: proc["kv"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_dissect(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    mapping = config.get("mapping", {})
    if isinstance(mapping, dict):
        for source_field, pattern in mapping.items():
            proc: Dict[str, Any] = {
                "dissect": {
                    "field": ls_field_to_es(source_field),
                    "pattern": pattern,
                    "ignore_missing": True,
                    "ignore_failure": True,
                }
            }
            if condition: proc["dissect"]["if"] = condition
            r.add_processor(proc, supported=True)
    return r

def translate_fingerprint(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    sources = config.get("source", ["message"])
    if isinstance(sources, str): sources = [sources]
    method_map = {"SHA1": "SHA-1", "SHA256": "SHA-256", "MD5": "MD5", "MURMUR3": "MurmurHash3"}
    proc: Dict[str, Any] = {
        "fingerprint": {
            "fields": [ls_field_to_es(f) for f in sources],
            "target_field": ls_field_to_es(config.get("target", "fingerprint")),
            "method": method_map.get(config.get("method", "SHA256").upper(), "SHA-256"),
            "ignore_missing": True,
        }
    }
    if condition: proc["fingerprint"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_urldecode(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    fld = ls_field_to_es(config.get("field", "message"))
    proc: Dict[str, Any] = {"urldecode": {"field": fld, "ignore_missing": True}}
    if config.get("charset"): proc["urldecode"]["charset"] = config["charset"]
    if condition: proc["urldecode"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_drop(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    proc: Dict[str, Any] = {"drop": {}}
    if condition: proc["drop"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_csv(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    proc: Dict[str, Any] = {
        "csv": {
            "field": ls_field_to_es(config.get("source", "message")),
            "target_fields": config.get("columns", []),
            "separator": config.get("separator", ","),
            "ignore_missing": True,
        }
    }
    if condition: proc["csv"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_de_dot(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    r = TranslationResult()
    proc: Dict[str, Any] = {"dot_expander": {"field": "*", "override": True}}
    if condition: proc["dot_expander"]["if"] = condition
    r.add_processor(proc, supported=True)
    return r

def translate_ruby(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    """Ruby cannot be auto-translated. Emit a stub script with the original code as a comment."""
    r = TranslationResult()
    code = config.get("code", "")
    ext  = config.get("path", "")
    r.add_warning(
        f"ruby filter: CANNOT be auto-translated. "
        f"{'Inline code (' + str(len(code)) + ' chars)' if code else ''}"
        f"{'External file: ' + ext if ext else ''}. "
        "Rewrite in Painless or handle upstream."
    )
    stub: Dict[str, Any] = {
        "script": {
            "lang": "painless",
            "source": "// TODO: rewrite the following Ruby logic in Painless\n// " + code[:200].replace("\n", "\n// "),
            "_original_ruby": code[:500] if code else f"(external: {ext})",
            "ignore_failure": True,
        }
    }
    if condition: stub["script"]["if"] = condition
    r.add_processor(stub, supported=False)
    return r

def translate_translate(config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    """Translate filter → enrich policy stub (cannot auto-create the policy)."""
    r = TranslationResult()
    r.add_warning(
        f"translate filter on field '{config.get('field', '?')}': "
        "Cannot auto-translate — requires an Elasticsearch enrich policy. "
        "Create an enrich policy with the dictionary data, then use the enrich processor."
    )
    proc: Dict[str, Any] = {
        "enrich": {
            "policy_name": "TODO_enrich_policy_name",
            "field": ls_field_to_es(config.get("field", "UNKNOWN")),
            "target_field": ls_field_to_es(config.get("destination", "translation")),
            "_comment": "MANUAL: create enrich policy from dictionary_path or inline dictionary",
            "ignore_missing": True,
        }
    }
    if condition: proc["enrich"]["if"] = condition
    r.add_processor(proc, supported=False)
    return r

def translate_unsupported(plugin: str, config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    """Generic stub for unsupported plugins."""
    r = TranslationResult()
    r.add_warning(f"{plugin}: not supported in Elasticsearch ingest pipelines — manual redesign required")
    stub: Dict[str, Any] = {
        "script": {
            "lang": "painless",
            "source": f"// TODO: '{plugin}' has no ingest equivalent. Manual redesign required.",
            "ignore_failure": True,
            "_original_plugin": plugin,
        }
    }
    if condition: stub["script"]["if"] = condition
    r.add_processor(stub, supported=False)
    return r

def translate_partial_stub(plugin: str, config: Dict[str, Any], condition: Optional[str] = None) -> TranslationResult:
    """Stub for partial plugins that need manual review."""
    r = TranslationResult()
    r.add_warning(f"{plugin}: partially supported — manual review required")
    stub: Dict[str, Any] = {
        "script": {
            "lang": "painless",
            "source": f"// TODO: reimplement '{plugin}' logic",
            "ignore_failure": True,
            "_original_plugin": plugin,
            "_config_summary": {k: str(v)[:80] for k, v in list(config.items())[:5]},
        }
    }
    if condition: stub["script"]["if"] = condition
    r.add_processor(stub, supported=False)
    return r

# ─────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────

TRANSLATORS = {
    "grok":        translate_grok,
    "date":        translate_date,
    "mutate":      translate_mutate,
    "geoip":       translate_geoip,
    "useragent":   translate_useragent,
    "json":        translate_json,
    "kv":          translate_kv,
    "dissect":     translate_dissect,
    "fingerprint": translate_fingerprint,
    "urldecode":   translate_urldecode,
    "drop":        translate_drop,
    "csv":         translate_csv,
    "de_dot":      translate_de_dot,
    "ruby":        translate_ruby,
    "translate":   translate_translate,
}

UNSUPPORTED_PLUGINS = {"aggregate", "elapsed", "clone", "metrics", "jdbc_streaming",
                        "memcached", "cipher", "http", "elasticsearch", "dns"}

def dispatch_processor(node_dict: Dict[str, Any], parent_condition: Optional[str] = None) -> TranslationResult:
    """Translate a single ProcessorNode dict to ES ingest processors."""
    plugin = node_dict.get("plugin", "")
    config = node_dict.get("config", {})
    if isinstance(plugin, str): plugin = plugin.lower()

    if plugin in UNSUPPORTED_PLUGINS:
        return translate_unsupported(plugin, config, parent_condition)
    if plugin in TRANSLATORS:
        return TRANSLATORS[plugin](config, parent_condition)
    # Unknown — partial stub
    return translate_partial_stub(plugin, config, parent_condition)

# ─────────────────────────────────────────────────────────────
# Tree walker — converts the ordered filter tree to ingest JSON
# ─────────────────────────────────────────────────────────────

def walk_filter_tree(node_dict: Dict[str, Any], parent_condition: Optional[str] = None) -> TranslationResult:
    """Recursively walk the processors_ordered tree and build the translation."""
    combined = TranslationResult()

    node_type = node_dict.get("node_type", "")

    if node_type == "processor":
        r = dispatch_processor(node_dict, parent_condition)
        combined.processors.extend(r.processors)
        combined.warnings.extend(r.warnings)
        combined.coverage_supported += r.coverage_supported
        combined.coverage_total += r.coverage_total

    elif node_type == "sequence":
        for child in node_dict.get("children", []):
            r = walk_filter_tree(child, parent_condition)
            combined.processors.extend(r.processors)
            combined.warnings.extend(r.warnings)
            combined.coverage_supported += r.coverage_supported
            combined.coverage_total += r.coverage_total

    elif node_type == "conditional":
        # Each branch gets its processors annotated with a Painless if condition
        # We use a placeholder since we don't have the actual Logstash condition expression.
        for i, branch in enumerate(node_dict.get("branches", [])):
            btype = branch.get("branch_type", "if")
            cond_expr = branch.get("condition", "")
            # For now, annotate with a TODO placeholder in the generated JSON
            es_condition = None
            if btype != "else":
                es_condition = f"/* TODO: translate Logstash condition: {cond_expr or 'if (branch ' + str(i) + ')'} */"
            r = walk_filter_tree(branch.get("body", {}), es_condition)
            combined.processors.extend(r.processors)
            combined.warnings.extend(r.warnings)
            combined.coverage_supported += r.coverage_supported
            combined.coverage_total += r.coverage_total
        combined.warnings.append(
            f"Conditional block with {len(node_dict.get('branches', []))} branches: "
            "Logstash condition expressions must be manually translated to Painless 'if' clauses."
        )

    return combined

# ─────────────────────────────────────────────────────────────
# Ingest pipeline builder
# ─────────────────────────────────────────────────────────────

def build_ingest_pipeline(pipeline_row: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str], float]:
    """
    Build the ES ingest pipeline JSON for one logical pipeline.
    Returns (pipeline_json, warnings, coverage_score).
    """
    processors_ordered = pipeline_row.get("processors_ordered", {})
    pipeline_id = pipeline_row.get("pipeline", "unknown")

    result = walk_filter_tree(processors_ordered)

    coverage = (result.coverage_supported / result.coverage_total
                if result.coverage_total > 0 else 1.0)

    # Build the final ES pipeline structure
    pipeline_json = {
        "description": f"Migrated from Logstash pipeline: {pipeline_id}",
        "_meta": {
            "source": "logstash_ingest_transformer",
            "original_pipeline": pipeline_id,
            "filter_transform_score": pipeline_row.get("filter_transform_score", 0),
            "full_replacement_score": pipeline_row.get("full_replacement_score", 0),
            "migration_class": pipeline_row.get("migration_class", ""),
            "coverage": round(coverage, 3),
        },
        "processors": result.processors,
        "on_failure": [
            {
                "set": {
                    "field": "error.message",
                    "value": "{{ _ingest.on_failure_message }}",
                }
            }
        ],
    }

    return pipeline_json, result.warnings, coverage

# ─────────────────────────────────────────────────────────────
# Migration plan generator (Stage 3)
# ─────────────────────────────────────────────────────────────

def build_migration_plan(pipeline_row: Dict[str, Any], warnings: List[str], coverage: float) -> str:
    """Generate a Markdown migration plan for one pipeline."""
    pid = pipeline_row.get("pipeline", "unknown")
    mig = pipeline_row.get("migration", {})
    filt_score = mig.get("filter_transform_score", pipeline_row.get("filter_transform_score", 0))
    full_score  = mig.get("full_replacement_score", pipeline_row.get("full_replacement_score", 0))
    mig_class   = mig.get("migration_class", pipeline_row.get("migration_class", ""))
    label       = mig.get("pipeline_label", pipeline_row.get("pipeline_label", ""))
    reasons     = mig.get("reasons", pipeline_row.get("migration_reasons", []))
    recs        = mig.get("recommendations", [])
    input_blks  = mig.get("input_blockers", pipeline_row.get("input_blockers", []))
    input_srcs  = pipeline_row.get("input_sources", [])
    sinks       = pipeline_row.get("terminal_sinks", [])
    files       = pipeline_row.get("files", [])
    local_procs = pipeline_row.get("local_processors", {})
    total_stmts = pipeline_row.get("total_statements", 0)
    total_score = pipeline_row.get("total_score", 0)

    lines = [
        f"# Migration Plan: {pid}",
        "",
        "## Summary",
        "",
        f"| Attribute | Value |",
        f"|---|---|",
        f"| Source file(s) | {', '.join(files) or '—'} |",
        f"| Migration class | **{mig_class}** |",
        f"| Pipeline label | {label} |",
        f"| Filter transform ease | {filt_score}/100 |",
        f"| Full replacement ease | {full_score}/100 |",
        f"| Ingest coverage | {coverage*100:.0f}% of processors auto-translated |",
        f"| Complexity score | {total_score} |",
        f"| Total statements | {total_stmts} |",
        "",
        "## Input Sources",
        "",
    ]

    if input_srcs:
        for src in input_srcs:
            lines.append(f"- `{src}`")
    else:
        lines.append("- *(pipeline input — no external source)*")

    if input_blks:
        lines += [
            "",
            "### ⛔ Input Blockers (Full Replacement)",
            "",
            "> These constraints mean the **input stage cannot be replaced by an Elasticsearch ingest pipeline**.",
            "> The filter logic may still be migrated; the input requires a separate strategy.",
            "",
        ]
        for b in input_blks:
            lines.append(f"- {b}")

    lines += [
        "",
        "## Processors",
        "",
        f"| Plugin | Count | Ingest Support |",
        f"|---|---|---|",
    ]
    for plugin, count in sorted(local_procs.items()):
        from logstash_ingest_transformer import UNSUPPORTED_PLUGINS
        if plugin in UNSUPPORTED_PLUGINS:
            support = "❌ Not supported"
        elif plugin in TRANSLATORS:
            support = "✅ Supported" if plugin not in ("ruby", "translate") else "⚠️ Partial"
        else:
            support = "⚠️ Review needed"
        lines.append(f"| `{plugin}` | {count} | {support} |")

    lines += ["", "## Filter Migration Notes", ""]
    if reasons:
        for r in reasons:
            lines.append(f"- {r}")
    else:
        lines.append("- No filter migration concerns detected.")

    if warnings:
        lines += ["", "## Translation Warnings", ""]
        seen = set()
        for w in warnings:
            if w not in seen:
                lines.append(f"- ⚠️  {w}")
                seen.add(w)

    if recs:
        lines += ["", "## Recommendations", ""]
        for r in recs:
            lines.append(f"- {r}")

    lines += [
        "",
        "## Recommended Architecture",
        "",
    ]

    has_jdbc = any("jdbc" in s.lower() for s in input_srcs)
    has_beats = any("beats" in s.lower() for s in input_srcs)
    has_kafka = any("kafka" in s.lower() for s in input_srcs)
    es_sinks  = [s for s in sinks if "elasticsearch" in s.lower() or "opensearch" in s.lower()]

    if has_jdbc:
        lines += [
            "```",
            "Database → [Elastic JDBC Connector / Kafka Connect JDBC]",
            "        → Elasticsearch (with ingest pipeline for filter logic)",
            "```",
            "",
            "> The filter logic below can be applied as an ingest pipeline.",
            "> The JDBC input must be replaced with a dedicated connector.",
        ]
    elif has_beats:
        lines += [
            "```",
            "Data Source → Elastic Agent (Fleet)",
            "           → Elasticsearch ingest pipeline (replaces filter {})",
            "           → Elasticsearch index",
            "```",
        ]
    elif has_kafka:
        lines += [
            "```",
            "Kafka topic → Elastic Agent (Kafka input)",
            "           → Elasticsearch ingest pipeline (replaces filter {})",
            "           → Elasticsearch index",
            "```",
        ]
    else:
        lines += [
            "```",
            "Source → Elastic Agent or Beats",
            "      → Elasticsearch ingest pipeline (replaces filter {})",
            "      → Elasticsearch index",
            "```",
        ]

    lines += ["", "## Generated Ingest Pipeline", ""]
    lines.append("See the accompanying `.ingest.json` file for the generated pipeline.")
    lines.append("")
    lines.append("To deploy:")
    lines.append("```bash")
    safe_pid = re.sub(r'[^a-z0-9_\-]', '_', pid.lower())
    lines.append(f"curl -X PUT 'http://localhost:9200/_ingest/pipeline/{safe_pid}' \\")
    lines.append(f"     -H 'Content-Type: application/json' \\")
    lines.append(f"     -d @{safe_pid}.ingest.json")
    lines.append("```")
    lines.append("")

    return "\n".join(lines)

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def safe_filename(pipeline_id: str) -> str:
    return re.sub(r'[^a-z0-9_\-]', '_', pipeline_id.lower()).strip("_")

def main():
    ap = argparse.ArgumentParser(description="Logstash → ES Ingest Pipeline Transformer (Stage 2+3)")
    ap.add_argument("analysis_json", help="JSON output from logstash_pipeline_analyzer_v12.py")
    ap.add_argument("--out-dir", default="./ingest_output", help="Output directory")
    ap.add_argument("--pipeline", help="Only process this pipeline ID (substring match)")
    ap.add_argument("--stdout", action="store_true", help="Print first result to stdout instead of files")
    ap.add_argument("--min-coverage", type=float, default=0.0, help="Only output pipelines with coverage >= this")
    args = ap.parse_args()

    data = json.loads(Path(args.analysis_json).read_text(encoding="utf-8"))
    pipelines = data.get("logical_pipelines", [])

    if args.pipeline:
        pipelines = [p for p in pipelines if args.pipeline.lower() in p.get("pipeline","").lower()]
        if not pipelines:
            print(f"No pipeline matching '{args.pipeline}' found.", file=sys.stderr)
            sys.exit(1)

    out_dir = Path(args.out_dir)
    if not args.stdout:
        out_dir.mkdir(parents=True, exist_ok=True)

    summary_rows = []

    for row in pipelines:
        pid = row.get("pipeline", "unknown")
        pipeline_json, warnings, coverage = build_ingest_pipeline(row)
        plan_md = build_migration_plan(row, warnings, coverage)

        if coverage < args.min_coverage:
            continue

        summary_rows.append({
            "pipeline": pid,
            "migration_class": row.get("migration_class", ""),
            "filter_transform_score": row.get("filter_transform_score", 0),
            "full_replacement_score": row.get("full_replacement_score", 0),
            "coverage": round(coverage, 3),
            "warning_count": len(warnings),
            "processor_count": len(pipeline_json["processors"]),
        })

        if args.stdout:
            print(f"\n{'='*60}")
            print(f"Pipeline: {pid}")
            print(f"Coverage: {coverage*100:.0f}%  |  Warnings: {len(warnings)}")
            print(f"{'='*60}")
            print("\n--- INGEST PIPELINE JSON ---")
            print(json.dumps(pipeline_json, indent=2))
            print("\n--- MIGRATION PLAN ---")
            print(plan_md)
            if warnings:
                print("\n--- WARNINGS ---")
                for w in warnings: print(f"  ⚠  {w}")
            break  # stdout mode shows first match only

        fname = safe_filename(pid)
        (out_dir / f"{fname}.ingest.json").write_text(
            json.dumps(pipeline_json, indent=2, ensure_ascii=False), encoding="utf-8")
        (out_dir / f"{fname}.plan.md").write_text(plan_md, encoding="utf-8")

    if not args.stdout:
        summary = {
            "total_pipelines": len(summary_rows),
            "by_class": {},
            "pipelines": sorted(summary_rows, key=lambda r: r["coverage"]),
        }
        for row in summary_rows:
            mc = row["migration_class"]
            summary["by_class"].setdefault(mc, 0)
            summary["by_class"][mc] += 1

        (out_dir / "migration_summary.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"\nTransformed {len(summary_rows)} pipelines → {out_dir}/")
        print(f"\nClass distribution: {summary['by_class']}")
        print(f"\nTop pipelines by coverage:")
        for r in sorted(summary_rows, key=lambda x: -x["coverage"])[:10]:
            print(f"  {r['coverage']*100:3.0f}%  {r['migration_class']:<6}  {r['pipeline']}")

if __name__ == "__main__":
    main()
