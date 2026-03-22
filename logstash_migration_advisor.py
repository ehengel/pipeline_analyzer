#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logstash_migration_advisor.py
═══════════════════════════════════════════════════════════════════════════
Migration decision-support advisor for Logstash → Elasticsearch ingest.

Consumes the JSON produced by logstash_pipeline_analyzer_v12.py and adds
four layers of analysis that turn raw scores into an actionable plan:

  1. OPERATIONAL BENEFIT SCORE
     How much value do we get by migrating this pipeline?
     Combines: ingest filter feasibility + how much Logstash complexity
     is removed + output simplicity + pipeline centrality in the flow graph.

  2. MIGRATION WAVE ASSIGNMENT
     Groups every pipeline into one of three waves:
       Wave 1 – Quick wins   : easy transform, simple arch, high benefit
       Wave 2 – Medium effort: partial blockers, some redesign needed
       Wave 3 – Redesign/keep: JDBC / ruby / aggregate / orchestration-heavy

  3. PATTERN CLUSTERING
     Identifies families of pipelines that share the same processor
     fingerprint (same plugin set in the same topology), so a migration
     template solved once can be reused across the whole family.

  4. FIELD INVENTORY
     Extracts what fields each pipeline creates, renames, removes and
     enriches — directly from mutate/grok/date/kv/geoip/useragent configs.
     Makes it easy to verify the ingest pipeline produces the same schema.

Usage:
  python logstash_migration_advisor.py analysis.json
  python logstash_migration_advisor.py analysis.json --json-out plan.json
  python logstash_migration_advisor.py analysis.json --csv-out plan.csv
  python logstash_migration_advisor.py analysis.json --wave 1
  python logstash_migration_advisor.py analysis.json --top-n 20

Output (stdout):
  Migration wave summary table
  Pattern cluster groups
  Per-wave pipeline details with benefit + effort scores
  Field inventory per pipeline
  Suggested migration order within each wave
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
from typing import Any, Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────
# Constants & catalogues
# ─────────────────────────────────────────────────────────────

# Plugins that are cleanly supported in ES ingest — no manual work
INGEST_NATIVE = {
    "grok", "dissect", "date", "json", "kv", "mutate",
    "geoip", "useragent", "fingerprint", "urldecode", "drop",
    "csv", "de_dot", "cidr", "split",
}

# Plugins that need some care but have a path forward
INGEST_PARTIAL = {"translate", "xml", "dns", "uuid", "prune", "throttle"}

# Plugins that are hard/impossible in ingest
INGEST_BLOCKERS = {
    "ruby", "aggregate", "elapsed", "clone", "metrics",
    "jdbc_streaming", "memcached", "cipher", "http", "elasticsearch",
}

# Input types that make full replacement impossible without redesign
HARD_INPUT_BLOCKERS = {"jdbc", "http_poller"}
SOFT_INPUT_BLOCKERS = {"redis", "kafka"}  # possible but needs verification

# Wave thresholds
WAVE1_FTS_MIN   = 75   # filter_transform_score must be >= this
WAVE1_FRS_MIN   = 70   # full_replacement_score must be >= this
WAVE2_FTS_MIN   = 45   # minimum to be Wave 2
WAVE3_THRESHOLD = 45   # below this full_replacement_score → Wave 3

# Operational benefit weights (all 0–1 scale, combined into 0–100 score)
OB_WEIGHT_FILTER_EASE   = 0.30  # how easily filters migrate
OB_WEIGHT_COMPLEXITY    = 0.25  # how much Logstash complexity is removed
OB_WEIGHT_OUTPUT_SIMPLE = 0.20  # ES-only output = highest value
OB_WEIGHT_CENTRALITY    = 0.15  # how many other pipelines depend on this
OB_WEIGHT_PROC_COUNT    = 0.10  # more statements = more value in ingest

# ─────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────

@dataclass
class FieldInventory:
    """Fields created, renamed, removed, enriched by a pipeline."""
    created:   List[str] = field(default_factory=list)
    renamed:   List[Tuple[str, str]] = field(default_factory=list)
    removed:   List[str] = field(default_factory=list)
    enriched:  List[str] = field(default_factory=list)
    timestamp_source: Optional[str] = None
    timestamp_target: str = "@timestamp"
    grok_targets: List[str] = field(default_factory=list)
    kv_target:    Optional[str] = None


@dataclass
class ExternalDependency:
    """A file, service, or resource the pipeline depends on outside of ES/Logstash."""
    dep_type:    str
    path:        str
    plugin:      str
    note:        str


@dataclass
class PipelineMetadata:
    """Optional business/operational context supplied via metadata.yml sidecar."""
    owner:       str = ""
    team:        str = ""
    customer:    str = ""
    environment: str = ""
    criticality: str = ""
    volume:      str = ""
    notes:       str = ""


@dataclass
class Blocker:
    name: str
    severity: str      # "hard" | "workaround" | "decision"
    description: str
    recommendation: str


@dataclass
class PipelinePattern:
    """
    Workshop-oriented pipeline classification.

    primary    : one canonical label (e.g. "jdbc_polling", "heavy_grok")
    tags       : all additional traits — any number, not mutually exclusive
    portability: 0–100 (higher = easier to migrate / replace Logstash)
    coupling   : 0–100 (higher = more external dependencies)
    complexity : "Low" | "Medium" | "High"
    """
    primary:     str
    tags:        List[str]
    portability: int
    coupling:    int
    complexity:  str


@dataclass
class AntiPatternFlag:
    """A detected anti-pattern on a specific pipeline."""
    anti_pattern_id:   str   # machine-readable key
    name:              str   # short display name
    severity:          str   # "high" | "medium" | "low" | "info"
    description:       str   # what was found
    recommendation:    str   # what to do about it


@dataclass
class PipelineAdvice:
    pipeline_id:        str
    wave:               int
    wave_reason:        str
    operational_benefit: int
    benefit_breakdown:  Dict[str, float]
    migration_effort:   str
    effort_score:       int
    decision:           str
    blockers:           List[Blocker]
    field_inventory:    FieldInventory
    external_deps:      List[ExternalDependency]
    metadata:           PipelineMetadata
    architecture:       Dict[str, Any]
    cluster_id:         Optional[str]
    cluster_template:   bool
    processor_fingerprint: str
    is_pure_transformer: bool
    is_orchestrator:     bool
    pattern:            Optional[PipelinePattern] = None   # NEW
    anti_patterns:      List[AntiPatternFlag] = field(default_factory=list)  # NEW


@dataclass
class PatternCluster:
    cluster_id:     str
    fingerprint:    str
    pipeline_ids:   List[str]
    representative: str
    size:           int
    avg_benefit:    float
    avg_fts:        float
    description:    str


@dataclass
class MigrationPlan:
    generated_at:       str
    scan_root:          str
    total_pipelines:    int
    wave_counts:        Dict[int, int]
    clusters:           List[PatternCluster]
    pipelines:          List[PipelineAdvice]
    summary_text:       str
    all_inputs:         List[Dict[str, Any]] = field(default_factory=list)
    all_outputs:        List[Dict[str, Any]] = field(default_factory=list)
    all_fields:         Dict[str, Any] = field(default_factory=dict)
    pattern_summary:    List[Dict[str, Any]] = field(default_factory=list)  # NEW
    anti_pattern_summary: List[Dict[str, Any]] = field(default_factory=list)  # NEW

# ─────────────────────────────────────────────────────────────
# Helper: flatten the processor tree
# ─────────────────────────────────────────────────────────────

def flatten_processors(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return all ProcessorNode dicts in execution order."""
    result: List[Dict[str, Any]] = []
    nt = node.get("node_type", "")
    if nt == "processor":
        result.append(node)
    elif nt == "sequence":
        for c in node.get("children", []): result.extend(flatten_processors(c))
    elif nt == "conditional":
        for b in node.get("branches", []): result.extend(flatten_processors(b.get("body", {})))
    return result

# ─────────────────────────────────────────────────────────────
# 1. Field inventory extraction
# ─────────────────────────────────────────────────────────────

def _ls_field(f: str) -> str:
    """Strip Logstash [bracket][notation] to dot.notation."""
    parts = re.findall(r'\[([^\]]+)\]', f)
    return ".".join(parts) if parts else f.strip()

def _extract_grok_captures(pattern: str) -> List[str]:
    """Pull named capture names from a grok pattern string."""
    captures = []
    captures += re.findall(r'%\{[^:}]+:([^}]+)\}', pattern)
    captures += re.findall(r'\(\?<([^>]+)>', pattern)
    return captures

def build_field_inventory(tree: Dict[str, Any]) -> FieldInventory:
    """Walk the processor tree and extract field-level operations."""
    inv = FieldInventory()
    procs = flatten_processors(tree)

    for p in procs:
        plugin = p.get("plugin", "")
        config = p.get("config", {})

        if plugin == "mutate":
            # add_field / set → created fields
            af = config.get("add_field", {})
            if isinstance(af, dict):
                for k in af: inv.created.append(_ls_field(k))

            # rename → (src, dst) pairs
            rn = config.get("rename", {})
            if isinstance(rn, dict):
                for src, dst in rn.items():
                    inv.renamed.append((_ls_field(src), _ls_field(str(dst))))

            # remove_field
            rf = config.get("remove_field", [])
            if isinstance(rf, list):
                for f in rf: inv.removed.append(_ls_field(f))
            elif isinstance(rf, str):
                inv.removed.append(_ls_field(rf))

            # replace / copy → created
            for key in ("replace", "copy"):
                val = config.get(key, {})
                if isinstance(val, dict):
                    for k in val: inv.created.append(_ls_field(k))

        elif plugin == "grok":
            match = config.get("match", {})
            patterns: List[str] = []
            if isinstance(match, dict):
                for v in match.values():
                    if isinstance(v, str): patterns.append(v)
                    elif isinstance(v, list): patterns.extend(v)
            elif isinstance(match, list):
                # alternating [field, pattern, field, pattern]
                for i in range(1, len(match), 2):
                    patterns.append(match[i])
            for pat in patterns:
                inv.grok_targets.extend(_extract_grok_captures(pat))

        elif plugin == "date":
            src = config.get("match", [])
            if isinstance(src, list) and src:
                inv.timestamp_source = _ls_field(src[0])
            tgt = config.get("target", "@timestamp")
            inv.timestamp_target = _ls_field(tgt)

        elif plugin == "kv":
            tgt = config.get("target", None)
            if tgt: inv.kv_target = _ls_field(str(tgt))

        elif plugin == "geoip":
            tgt = config.get("target", "geoip")
            inv.enriched.append(_ls_field(str(tgt)) + " (geoip)")

        elif plugin == "useragent":
            tgt = config.get("target", "user_agent")
            inv.enriched.append(_ls_field(str(tgt)) + " (user_agent)")

        elif plugin == "fingerprint":
            tgt = config.get("target", "fingerprint")
            inv.created.append(_ls_field(str(tgt)) + " (fingerprint)")

    # Deduplicate
    inv.created     = sorted(set(inv.created))
    inv.removed     = sorted(set(inv.removed))
    inv.grok_targets = sorted(set(inv.grok_targets))
    inv.enriched    = sorted(set(inv.enriched))

    return inv

# ─────────────────────────────────────────────────────────────
# 2. Operational benefit score
# ─────────────────────────────────────────────────────────────

def compute_operational_benefit(
    row: Dict[str, Any],
    all_pipeline_ids: Set[str],
    logical_edges: Dict[str, List[str]],
) -> Tuple[int, Dict[str, float]]:
    """
    Compute a 0-100 operational benefit score.

    Components:
      filter_ease   : how cleanly the filter logic migrates (from fts)
      complexity    : how much Logstash burden is removed (from total_score)
      output_simple : ES-only single-output = highest value
      centrality    : how many pipelines depend on/flow through this one
      proc_count    : more statements = more work offloaded to ingest

    Returns (score_0_to_100, breakdown_dict).
    """
    fts     = int(row.get("filter_transform_score", 0) or 0)
    cmplx   = int(row.get("total_score", 0) or 0)
    stmts   = int(row.get("total_statements", 0) or 0)
    sinks   = row.get("terminal_sinks", []) or []
    sources = row.get("input_sources", []) or []
    pid     = row.get("pipeline", "")

    # Filter ease: 0-100 directly from fts
    filter_ease = fts / 100.0

    # Complexity removed: sigmoid-ish over 0-200 range
    complexity = min(1.0, cmplx / 150.0)

    # Output simplicity: 1.0 = single ES output; lower for multi-output, kafka, file
    es_sinks = [s for s in sinks if "elasticsearch" in s.lower() or "opensearch" in s.lower()]
    kafka_sinks = [s for s in sinks if "kafka" in s.lower()]
    file_sinks  = [s for s in sinks if "file:" in s.lower()]
    if len(sinks) == 0:
        # Pipeline input only — no final sink yet (part of a chain)
        output_simple = 0.6
    elif len(es_sinks) == len(sinks):
        # All outputs are ES — perfect candidate
        output_simple = 1.0 if len(es_sinks) == 1 else 0.80
    elif kafka_sinks or file_sinks:
        output_simple = 0.30
    else:
        output_simple = 0.50

    # Centrality: how many OTHER pipelines send to or receive from this one
    inbound  = sum(1 for _, dsts in logical_edges.items()
                   if pid in dsts and not any(x in pid for x in ("SINK:", "SOURCE:")))
    outbound = len([d for d in logical_edges.get(pid, [])
                    if d in all_pipeline_ids])
    centrality = min(1.0, (inbound + outbound) / 6.0)

    # Statement count as proxy for "how much work moves to ingest"
    proc_count = min(1.0, stmts / 60.0)

    breakdown = {
        "filter_ease":   round(filter_ease   * OB_WEIGHT_FILTER_EASE   * 100, 1),
        "complexity":    round(complexity    * OB_WEIGHT_COMPLEXITY    * 100, 1),
        "output_simple": round(output_simple * OB_WEIGHT_OUTPUT_SIMPLE * 100, 1),
        "centrality":    round(centrality    * OB_WEIGHT_CENTRALITY    * 100, 1),
        "proc_count":    round(proc_count    * OB_WEIGHT_PROC_COUNT    * 100, 1),
    }

    total = (
        filter_ease   * OB_WEIGHT_FILTER_EASE   +
        complexity    * OB_WEIGHT_COMPLEXITY    +
        output_simple * OB_WEIGHT_OUTPUT_SIMPLE +
        centrality    * OB_WEIGHT_CENTRALITY    +
        proc_count    * OB_WEIGHT_PROC_COUNT
    )

    return round(total * 100), breakdown

# ─────────────────────────────────────────────────────────────
# 3. Blocker analysis
# ─────────────────────────────────────────────────────────────

def extract_blockers(row: Dict[str, Any]) -> List[Blocker]:
    """Build a structured blocker list from a pipeline row."""
    blockers: List[Blocker] = []
    procs  = set((row.get("local_processors", {}) or {}).keys())
    sinks  = row.get("terminal_sinks", []) or []
    sources = row.get("input_sources", []) or []
    flags  = row.get("flags", []) or []
    mig    = row.get("migration", {}) or {}
    input_blk = mig.get("input_blockers", []) or []

    # ── Input blockers ─────────────────────────────────────
    for src in sources:
        sl = src.lower()
        if "jdbc" in sl:
            blockers.append(Blocker(
                name="JDBC input",
                severity="hard",
                description="JDBC input polls a database on a schedule using sql_last_value "
                            "watermarking. No Elastic Agent equivalent exists.",
                recommendation="Replace with Elastic JDBC connector, Kafka Connect JDBC source, "
                               "or custom Beats. Filter logic can still move to ingest pipeline.",
            ))
        elif "http_poller" in sl:
            blockers.append(Blocker(
                name="HTTP Poller input",
                severity="workaround",
                description="Scheduled HTTP polling. Elastic Agent HTTP input has limited parity.",
                recommendation="Evaluate Elastic Agent HTTP endpoint input or a custom Fleet "
                               "integration. Test feature parity before committing.",
            ))
        elif "redis" in sl:
            blockers.append(Blocker(
                name="Redis input",
                severity="workaround",
                description="Elastic Agent does not natively support Redis as an input.",
                recommendation="Replace Redis queue with Kafka (supported by Elastic Agent) "
                               "or route data directly to the ES ingest endpoint.",
            ))
        elif "kafka" in sl:
            blockers.append(Blocker(
                name="Kafka input",
                severity="decision",
                description="Elastic Agent supports Kafka input but full consumer group / codec "
                            "option parity is not guaranteed.",
                recommendation="Verify Elastic Agent Kafka input covers the consumer group, "
                               "offset management and codec options used here.",
            ))

    # ── Filter blockers ────────────────────────────────────
    if "ruby" in procs:
        blockers.append(Blocker(
            name="ruby filter",
            severity="hard",
            description="Ruby code is not supported in ES ingest pipelines.",
            recommendation="Rewrite in Painless (script processor) or pre-process upstream. "
                           "Review ruby { code => ... } for complexity before estimating effort.",
        ))
    if "aggregate" in procs:
        blockers.append(Blocker(
            name="aggregate filter",
            severity="hard",
            description="Stateful event aggregation has no ingest equivalent.",
            recommendation="Redesign using an enrich policy, external aggregation service, "
                           "or move logic to the application layer.",
        ))
    if "elapsed" in procs:
        blockers.append(Blocker(
            name="elapsed filter",
            severity="hard",
            description="Event-pair timing is stateful — not ingest-compatible.",
            recommendation="Use APM transaction timing or application-level instrumentation.",
        ))
    if "clone" in procs:
        blockers.append(Blocker(
            name="clone filter",
            severity="workaround",
            description="Event cloning is not natively supported in ingest.",
            recommendation="Use pipeline fan-out at the data layer or duplicate upstream.",
        ))
    if "translate" in procs:
        blockers.append(Blocker(
            name="translate filter",
            severity="workaround",
            description="File-based dictionary lookup. Enrich processor is the ES equivalent "
                        "but requires an enrich policy to be created first.",
            recommendation="Pre-load dictionary into an ES index, create an enrich policy, "
                           "then use the enrich ingest processor.",
        ))
    if "xml" in procs:
        blockers.append(Blocker(
            name="xml filter",
            severity="workaround",
            description="No native XML ingest processor.",
            recommendation="Parse XML upstream or use a Painless script processor.",
        ))
    if "jdbc_streaming" in procs:
        blockers.append(Blocker(
            name="jdbc_streaming filter",
            severity="hard",
            description="JDBC lookup filter makes live DB calls — not supported in ingest.",
            recommendation="Pre-load lookup data into an ES enrich index and use enrich processor.",
        ))
    if "elasticsearch" in procs:
        blockers.append(Blocker(
            name="elasticsearch filter (lookup)",
            severity="hard",
            description="ES lookup filter is not supported in ingest.",
            recommendation="Replace with an enrich policy populated from the lookup index.",
        ))

    # ── Output blockers ────────────────────────────────────
    kafka_sinks = [s for s in sinks if "kafka" in s.lower()]
    file_sinks  = [s for s in sinks if "file:" in s.lower()]
    http_sinks  = [s for s in sinks if "http:" in s.lower()]
    multi_es    = [s for s in sinks if ("elasticsearch" in s.lower()
                                        or "opensearch" in s.lower())]

    if len(sinks) > 1:
        blockers.append(Blocker(
            name=f"multiple outputs ({len(sinks)})",
            severity="decision",
            description=f"Pipeline fans out to {len(sinks)} outputs. "
                        "Ingest pipelines write to one index; fan-out needs rethinking.",
            recommendation="Route to multiple indices via index naming patterns, or use "
                           "a processor pipeline per sink with conditional routing.",
        ))
    if kafka_sinks:
        blockers.append(Blocker(
            name="Kafka output",
            severity="hard",
            description="Ingest pipelines cannot write to Kafka.",
            recommendation="Keep Kafka output in Logstash or a separate connector. "
                           "Ingest pipeline can handle the ES write path only.",
        ))
    if file_sinks:
        blockers.append(Blocker(
            name="file output",
            severity="hard",
            description="Ingest pipelines cannot write to files.",
            recommendation="Keep file output in Logstash or route via Filebeat after indexing.",
        ))

    # ── Routing / architecture blockers ───────────────────
    if any(f.startswith("unresolved") for f in flags):
        blockers.append(Blocker(
            name="unresolved send_to targets",
            severity="decision",
            description="This pipeline routes to a send_to address that has no matching "
                        "input definition in the scanned files.",
            recommendation="Locate the missing pipeline definition or confirm it is "
                           "intentionally external before migrating.",
        ))

    return blockers

# ─────────────────────────────────────────────────────────────
# 4. Pipeline character flags
# ─────────────────────────────────────────────────────────────

def classify_character(row: Dict[str, Any]) -> Tuple[bool, bool]:
    """
    Return (is_pure_transformer, is_orchestrator).

    Pure transformer:
      - Input is beats/syslog/http/pipeline (simple push)
      - Filter is mostly grok/date/mutate/json/kv/dissect
      - Single ES output
      - No ruby/aggregate/clone/jdbc

    Orchestrator:
      - JDBC polling input OR
      - Multiple outputs OR
      - Kafka/file outputs OR
      - ruby/aggregate/clone/elapsed present OR
      - Stateful behaviour detected
    """
    procs   = set((row.get("local_processors", {}) or {}).keys())
    sinks   = row.get("terminal_sinks", []) or []
    sources = row.get("input_sources",  []) or []

    hard_blocker_procs = procs & INGEST_BLOCKERS
    has_jdbc   = any("jdbc" in s.lower() for s in sources)
    has_multi  = len(sinks) > 1
    has_kafka  = any("kafka" in s.lower() for s in sinks)
    has_file   = any("file:" in s.lower() for s in sinks)
    has_es     = any("elasticsearch" in s.lower() or "opensearch" in s.lower() for s in sinks)

    is_orchestrator = bool(
        has_jdbc or has_multi or has_kafka or has_file or hard_blocker_procs
    )

    is_pure_transformer = bool(
        not is_orchestrator
        and (not sinks or (len(sinks) == 1 and has_es))
        and not (procs - INGEST_NATIVE - INGEST_PARTIAL)
    )

    return is_pure_transformer, is_orchestrator

# ─────────────────────────────────────────────────────────────
# 5. Effort scoring
# ─────────────────────────────────────────────────────────────

def compute_effort(row: Dict[str, Any], blockers: List[Blocker]) -> Tuple[str, int]:
    """
    Return (effort_band, effort_score_0_to_100).
    Higher score = more engineering work.
    """
    score = 0

    # Hard blockers are expensive
    hard   = sum(1 for b in blockers if b.severity == "hard")
    work   = sum(1 for b in blockers if b.severity == "workaround")
    dec    = sum(1 for b in blockers if b.severity == "decision")
    score += hard * 20 + work * 8 + dec * 4

    # Statement count proxy
    stmts = int(row.get("total_statements", 0) or 0)
    score += min(20, stmts // 5)

    # Branch complexity
    bc = int((row.get("migration", {}) or {}).get("penalties", {}).get("branching", 0))
    score += min(15, bc)

    # Ruby metrics add extra if code is large
    tree = row.get("processors_ordered", {})
    for p in flatten_processors(tree):
        if p.get("plugin") == "ruby":
            m = p.get("metrics", {})
            lines = int(m.get("inline_code_lines", 0) or 0)
            score += min(15, lines // 5)
            if m.get("has_http"):     score += 8
            if m.get("has_require"):  score += 5
            if m.get("has_event_cancel"): score += 3

    score = min(100, score)
    band = "Low" if score <= 20 else "Medium" if score <= 50 else "High"
    return band, score

# ─────────────────────────────────────────────────────────────
# 6. Wave assignment
# ─────────────────────────────────────────────────────────────

def assign_wave(
    row: Dict[str, Any],
    benefit: int,
    effort_score: int,
    blockers: List[Blocker],
    is_pure: bool,
    is_orch: bool,
) -> Tuple[int, str]:
    """
    Assign a migration wave and return (wave, reason_string).

    Wave 1 — Quick wins:
      • fts ≥ 75 AND frs ≥ 70
      • No hard blockers
      • At most 2 workaround blockers
      • effort_score ≤ 30

    Wave 2 — Medium effort:
      • fts ≥ 45 OR benefit ≥ 50
      • Hard blockers ≤ 1 OR all hard blockers are filter-only (not input)
      • Partial/redesign possible

    Wave 3 — Redesign or keep on Logstash:
      • frs < 45 (full replacement very hard)
      • OR multiple hard blockers
      • OR is a true orchestrator (JDBC/stateful/multi-output)
    """
    fts = int(row.get("filter_transform_score", 0) or 0)
    frs = int(row.get("full_replacement_score", 0) or 0)
    hard_count = sum(1 for b in blockers if b.severity == "hard")
    work_count = sum(1 for b in blockers if b.severity == "workaround")
    input_hard = sum(1 for b in blockers if b.severity == "hard"
                     and "input" in b.name.lower())

    reasons: List[str] = []

    # ── Wave 1 ───────────────────────────────────────────
    if (fts >= WAVE1_FTS_MIN
            and frs >= WAVE1_FRS_MIN
            and hard_count == 0
            and work_count <= 2
            and effort_score <= 35):
        if is_pure:
            reasons.append("pure transformer — beats/push input, ES-only output, ingest-native filters")
        elif fts >= 85:
            reasons.append("very high filter compatibility")
        reasons.append(f"filter ease {fts}/100, full replacement {frs}/100, low effort")
        return 1, "; ".join(reasons)

    # ── Wave 3 (check before Wave 2) ─────────────────────
    # Strong Wave-3 signals override medium scores
    if is_orch and (hard_count >= 2 or frs < 40):
        reasons.append("orchestration-heavy pipeline (JDBC/stateful/multi-output)")
        reasons.append(f"full replacement score {frs}/100 — significant redesign needed")
        return 3, "; ".join(reasons)

    if hard_count >= 3:
        reasons.append(f"{hard_count} hard blockers — major rewrite required")
        return 3, "; ".join(reasons)

    if frs < WAVE3_THRESHOLD and input_hard >= 1:
        reasons.append(f"input cannot be replaced by Elastic Agent (frs={frs}/100)")
        reasons.append("filter logic may migrate but requires separate ingestion strategy")
        return 3, "; ".join(reasons)

    # ── Wave 2 ───────────────────────────────────────────
    reasons_2: List[str] = []
    if fts >= WAVE2_FTS_MIN:
        reasons_2.append(f"filter ease {fts}/100 — mostly migratable with some manual work")
    if hard_count == 1:
        reasons_2.append(f"one hard blocker ({next(b.name for b in blockers if b.severity=='hard')})")
    if work_count > 0:
        reasons_2.append(f"{work_count} partial blocker(s) need workarounds (translate/xml/dns)")
    if not reasons_2:
        reasons_2.append(f"moderate filter ease ({fts}/100) — partial migration feasible")

    return 2, "; ".join(reasons_2)

# ─────────────────────────────────────────────────────────────
# 7. Pattern fingerprint & clustering
# ─────────────────────────────────────────────────────────────

def build_fingerprint(row: Dict[str, Any]) -> str:
    """
    Create a canonical string describing the pipeline's processor pattern,
    source type, and sink type.  Two pipelines with the same fingerprint
    are structurally identical and can share a migration template.

    Format:
      procs:{sorted_plugin_set}|src:{source_categories}|sink:{sink_categories}
    """
    procs   = sorted(set((row.get("local_processors", {}) or {}).keys()))
    sources = row.get("input_sources", []) or []
    sinks   = row.get("terminal_sinks",  []) or []

    # Normalise source type to category
    def src_cat(s: str) -> str:
        sl = s.lower()
        if "beats" in sl: return "beats"
        if "kafka" in sl: return "kafka"
        if "jdbc"  in sl: return "jdbc"
        if "file"  in sl: return "file"
        if "http"  in sl: return "http"
        if "syslog" in sl: return "syslog"
        if "pipeline" in sl or not s: return "pipeline"
        return "other"

    def sink_cat(s: str) -> str:
        sl = s.lower()
        if "elasticsearch" in sl or "opensearch" in sl: return "elasticsearch"
        if "kafka" in sl: return "kafka"
        if "file"  in sl: return "file"
        if "http"  in sl: return "http"
        if "stdout" in sl: return "stdout"
        if "pipeline" in sl or not s: return "pipeline"
        return "other"

    src_cats  = sorted(set(src_cat(s) for s in sources)) or ["(none)"]
    sink_cats = sorted(set(sink_cat(s) for s in sinks))  or ["(none)"]

    proc_str = "+".join(procs)   if procs   else "(none)"
    src_str  = "+".join(src_cats)
    sink_str = "+".join(sink_cats)

    return f"procs:{proc_str}|src:{src_str}|sink:{sink_str}"


def _fingerprint_description(fp: str) -> str:
    """Human-readable description of a fingerprint."""
    parts = dict(p.split(":", 1) for p in fp.split("|") if ":" in p)
    procs   = parts.get("procs", "(none)")
    src     = parts.get("src",   "(none)")
    sink    = parts.get("sink",  "(none)")
    return (f"Processors: [{procs}]  •  Source: {src}  •  Sink: {sink}")


def cluster_pipelines(
    advices: List[PipelineAdvice],
) -> List[PatternCluster]:
    """
    Group PipelineAdvice objects by fingerprint.
    Returns sorted list of PatternCluster objects (largest clusters first).
    """
    buckets: Dict[str, List[PipelineAdvice]] = defaultdict(list)
    for a in advices:
        buckets[a.processor_fingerprint].append(a)

    clusters: List[PatternCluster] = []
    for fp, members in buckets.items():
        # Pick the representative: highest benefit score among Wave 1/2 members
        sorted_members = sorted(
            members,
            key=lambda a: (a.wave, -a.operational_benefit)
        )
        rep = sorted_members[0]
        rep.cluster_template = True

        avg_benefit = sum(a.operational_benefit for a in members) / len(members)
        avg_fts     = sum(int((a.pipeline_id and 0) or 0) for a in members)  # placeholder

        cid = f"C{len(clusters)+1:03d}"
        for m in members:
            m.cluster_id = cid

        clusters.append(PatternCluster(
            cluster_id=cid,
            fingerprint=fp,
            pipeline_ids=[a.pipeline_id for a in members],
            representative=rep.pipeline_id,
            size=len(members),
            avg_benefit=round(avg_benefit, 1),
            avg_fts=0.0,  # populated below
            description=_fingerprint_description(fp),
        ))

    # Sort: multi-pipeline clusters first (template reuse value), then by size
    clusters.sort(key=lambda c: -c.size)
    return clusters

# ─────────────────────────────────────────────────────────────
# 8. Decision label
# ─────────────────────────────────────────────────────────────

def make_decision(
    wave: int, is_pure: bool, is_orch: bool, fts: int, frs: int
) -> str:
    if wave == 1:
        if is_pure: return "Migrate now — pure transformer, minimal risk"
        return "Migrate now"
    if wave == 2:
        if fts >= 70 and frs < 50:
            return "Partially migrate — move filters to ingest, keep input/output in Logstash"
        return "Migrate with redesign — resolve blockers then migrate"
    # Wave 3
    if is_orch:
        return "Keep on Logstash — orchestration-heavy, architectural redesign required"
    return "Redesign first — resolve hard blockers before migration"

# ─────────────────────────────────────────────────────────────
# 9a. Cross-pipeline aggregate inventories  (new)
# ─────────────────────────────────────────────────────────────

def _clean_source_label(s: str) -> str:
    """Strip SOURCE: prefix and shorten long labels."""
    return s[len("SOURCE:"):] if s.startswith("SOURCE:") else s

def _clean_sink_label(s: str) -> str:
    """Strip SINK: prefix and shorten long labels."""
    return s[len("SINK:"):] if s.startswith("SINK:") else s

def _source_type(label: str) -> str:
    """Normalise a source label to a short type name."""
    ll = label.lower()
    for kw in ("beats","kafka","jdbc","file","http_poller","http","syslog",
               "tcp","udp","redis","pipeline","stdin"):
        if kw in ll: return kw
    return "other"

def _sink_type(label: str) -> str:
    """Normalise a sink label to a short type name."""
    ll = label.lower()
    if "elasticsearch" in ll or "opensearch" in ll: return "elasticsearch"
    for kw in ("kafka","file","http","stdout","redis","rabbitmq","s3","tcp","udp","pipeline"):
        if kw in ll: return kw
    return "other"


def build_input_inventory(
    rows: List[Dict[str, Any]],
    advices: List[PipelineAdvice],
) -> List[Dict[str, Any]]:
    """
    Aggregate all input sources across all pipelines.

    Returns a list sorted by pipeline count descending:
      [{type, label, pipeline_count, pipelines: [pid, ...], wave_counts: {1:N, 2:N, 3:N}}]
    """
    # label → {pipelines, wave}
    advice_wave = {a.pipeline_id: a.wave for a in advices}
    buckets: Dict[str, Dict[str, Any]] = {}

    for row in rows:
        pid = row.get("pipeline", "")
        sources = row.get("input_sources", []) or []
        wave = advice_wave.get(pid, 0)

        if not sources:
            # pipeline-to-pipeline input (no external source)
            label = "(pipeline input)"
            key = label
            if key not in buckets:
                buckets[key] = {"type": "pipeline", "label": label,
                                "pipelines": [], "wave_counts": {1:0,2:0,3:0}}
            buckets[key]["pipelines"].append(pid)
            if wave in (1,2,3): buckets[key]["wave_counts"][wave] += 1
        else:
            for src in sources:
                label = _clean_source_label(src)
                stype = _source_type(label)
                key = src   # use full label as key to keep distinct addresses
                if key not in buckets:
                    buckets[key] = {"type": stype, "label": label,
                                    "pipelines": [], "wave_counts": {1:0,2:0,3:0}}
                buckets[key]["pipelines"].append(pid)
                if wave in (1,2,3): buckets[key]["wave_counts"][wave] += 1

    result = []
    for entry in buckets.values():
        entry["pipelines"] = sorted(set(entry["pipelines"]))
        entry["pipeline_count"] = len(entry["pipelines"])
        result.append(entry)

    result.sort(key=lambda e: -e["pipeline_count"])
    return result


def build_output_inventory(
    rows: List[Dict[str, Any]],
    advices: List[PipelineAdvice],
) -> List[Dict[str, Any]]:
    """
    Aggregate all terminal outputs (sinks + unresolved) across all pipelines.

    Returns a list sorted by pipeline count descending:
      [{type, label, pipeline_count, pipelines, wave_counts}]
    """
    advice_wave = {a.pipeline_id: a.wave for a in advices}
    buckets: Dict[str, Dict[str, Any]] = {}

    for row in rows:
        pid = row.get("pipeline", "")
        sinks = row.get("terminal_sinks", []) or []
        local_outs = row.get("local_outputs", []) or []
        wave = advice_wave.get(pid, 0)

        if not sinks and not local_outs:
            label = "(no output / dead end)"
            key = label
            if key not in buckets:
                buckets[key] = {"type": "dead_end", "label": label,
                                "pipelines": [], "wave_counts": {1:0,2:0,3:0}}
            buckets[key]["pipelines"].append(pid)
            if wave in (1,2,3): buckets[key]["wave_counts"][wave] += 1

        for sink in sinks:
            label = _clean_sink_label(sink)
            stype = _sink_type(label)
            key = sink
            if key not in buckets:
                buckets[key] = {"type": stype, "label": label,
                                "pipelines": [], "wave_counts": {1:0,2:0,3:0}}
            buckets[key]["pipelines"].append(pid)
            if wave in (1,2,3): buckets[key]["wave_counts"][wave] += 1

        # Show pipeline-to-pipeline handoffs as routing outputs
        for out in local_outs:
            label = f"→ pipeline:{out}"
            key = f"pipeline:{out}"
            if key not in buckets:
                buckets[key] = {"type": "pipeline", "label": label,
                                "pipelines": [], "wave_counts": {1:0,2:0,3:0}}
            buckets[key]["pipelines"].append(pid)
            if wave in (1,2,3): buckets[key]["wave_counts"][wave] += 1

    result = []
    for entry in buckets.values():
        entry["pipelines"] = sorted(set(entry["pipelines"]))
        entry["pipeline_count"] = len(entry["pipelines"])
        result.append(entry)

    result.sort(key=lambda e: (-e["pipeline_count"], e["label"]))
    return result


def build_global_field_inventory(advices: List[PipelineAdvice]) -> Dict[str, Any]:
    """
    Merge all per-pipeline field inventories into a single cross-pipeline view.

    Returns:
      {
        created:   [{field, pipelines}],   # sorted by pipeline count
        renamed:   [{from, to, pipelines}],
        removed:   [{field, pipelines}],
        grok_captures: [{field, pipelines}],
        enriched:  [{target, pipelines}],
        timestamp_fields: [{source, target, pipelines}],
      }
    """
    # field → [pipeline_ids]
    created_map:  Dict[str, List[str]] = defaultdict(list)
    removed_map:  Dict[str, List[str]] = defaultdict(list)
    grok_map:     Dict[str, List[str]] = defaultdict(list)
    enriched_map: Dict[str, List[str]] = defaultdict(list)
    renamed_map:  Dict[str, List[str]] = defaultdict(list)   # "src→dst" → [pids]
    ts_map:       Dict[str, List[str]] = defaultdict(list)   # "src→target" → [pids]

    for a in advices:
        pid = a.pipeline_id
        inv = a.field_inventory

        for f in inv.created:         created_map[f].append(pid)
        for f in inv.removed:         removed_map[f].append(pid)
        for f in inv.grok_targets:    grok_map[f].append(pid)
        for f in inv.enriched:        enriched_map[f].append(pid)
        for src, dst in inv.renamed:  renamed_map[f"{src}→{dst}"].append(pid)
        if inv.timestamp_source:
            key = f"{inv.timestamp_source}→{inv.timestamp_target}"
            ts_map[key].append(pid)

    def _sorted_entries(m: Dict[str, List[str]], key_name: str) -> List[Dict[str, Any]]:
        out = []
        for k, pids in m.items():
            unique = sorted(set(pids))
            out.append({key_name: k, "pipeline_count": len(unique), "pipelines": unique})
        out.sort(key=lambda e: (-e["pipeline_count"], e[key_name]))
        return out

    # Renamed needs a different structure
    renamed_entries = []
    for k, pids in renamed_map.items():
        parts = k.split("→", 1)
        src, dst = (parts[0], parts[1]) if len(parts) == 2 else (k, "?")
        unique = sorted(set(pids))
        renamed_entries.append({"from": src, "to": dst,
                                  "pipeline_count": len(unique), "pipelines": unique})
    renamed_entries.sort(key=lambda e: (-e["pipeline_count"], e["from"]))

    # Timestamp entries
    ts_entries = []
    for k, pids in ts_map.items():
        parts = k.split("→", 1)
        src, tgt = (parts[0], parts[1]) if len(parts) == 2 else (k, "@timestamp")
        unique = sorted(set(pids))
        ts_entries.append({"source": src, "target": tgt,
                            "pipeline_count": len(unique), "pipelines": unique})
    ts_entries.sort(key=lambda e: -e["pipeline_count"])

    return {
        "created":          _sorted_entries(created_map,  "field"),
        "renamed":          renamed_entries,
        "removed":          _sorted_entries(removed_map,  "field"),
        "grok_captures":    _sorted_entries(grok_map,     "field"),
        "enriched":         _sorted_entries(enriched_map, "target"),
        "timestamp_fields": ts_entries,
    }


# ─────────────────────────────────────────────────────────────
# 9b. External dependency extraction  (new)
# ─────────────────────────────────────────────────────────────

def extract_external_deps(row: Dict[str, Any]) -> List[ExternalDependency]:
    """
    Scan processor configs for files, DBs, and services the pipeline
    depends on outside of Elasticsearch / Logstash itself.

    Detects:
      translate  → dictionary_path (.yml/.csv dict file)
      ruby       → path (external .rb script)
      jdbc input → jdbc_connection_string, jdbc_driver_class, statement (SQL)
      grok       → patterns_dir (custom pattern directory)
      http input → url (external HTTP endpoint)
      http filter → url (outbound HTTP call)
    """
    deps: List[ExternalDependency] = []
    sources = row.get("input_sources", []) or []
    tree    = row.get("processors_ordered", {})

    # ── Input-level deps ──────────────────────────────────
    for src in sources:
        sl = src.lower()
        # JDBC connection string is in the raw input text, not the processor tree
        raw_in = row.get("raw_input_text", "") or ""
        if "jdbc" in sl:
            # Extract connection string if visible in raw text
            m = re.search(r'jdbc_connection_string\s*=>\s*["\']([^"\']+)', raw_in)
            conn = m.group(1) if m else "(see config)"
            deps.append(ExternalDependency(
                dep_type="jdbc_db", path=conn, plugin="jdbc",
                note="JDBC database connection — must be replaced with a connector or pre-ingestion job"))
            # Extract SQL statement file if referenced
            m2 = re.search(r'statement_filepath\s*=>\s*["\']([^"\']+)', raw_in)
            if m2:
                deps.append(ExternalDependency(
                    dep_type="sql_file", path=m2.group(1), plugin="jdbc",
                    note="External SQL statement file — must be ported to connector query config"))
        if "http_poller" in sl:
            m = re.search(r'url[s]?\s*=>\s*\{[^}]*["\']([^"\']+http[^"\']+)["\']', raw_in, re.IGNORECASE)
            url = m.group(1) if m else "(see config)"
            deps.append(ExternalDependency(
                dep_type="http_endpoint", path=url, plugin="http_poller",
                note="HTTP polling endpoint — evaluate Elastic Agent HTTP input for replacement"))

    # ── Processor-level deps ──────────────────────────────
    def walk(n: Dict[str, Any]) -> None:
        nt = n.get("node_type", "")
        if nt == "processor":
            plugin = n.get("plugin", "")
            config = n.get("config", {})
            metrics = n.get("metrics", {})

            if plugin == "translate":
                dp = config.get("dictionary_path", "")
                if dp:
                    deps.append(ExternalDependency(
                        dep_type="dict_file", path=dp, plugin="translate",
                        note="Dictionary file — pre-load into ES enrich index for migration"))

            elif plugin == "grok":
                pd = config.get("patterns_dir", "") or config.get("patterns_files_glob", "")
                if pd:
                    deps.append(ExternalDependency(
                        dep_type="patterns_dir", path=str(pd), plugin="grok",
                        note="Custom grok patterns directory — patterns must be added to ES grok processor config"))

            elif plugin == "ruby":
                ext = metrics.get("external_path", "") or config.get("path", "")
                if ext:
                    deps.append(ExternalDependency(
                        dep_type="ruby_script", path=str(ext), plugin="ruby",
                        note="External Ruby script — must be rewritten in Painless for ingest migration"))

            elif plugin in ("http", "elasticsearch", "jdbc_streaming", "memcached"):
                # Filter plugins that make outbound connections
                url = (config.get("url") or config.get("hosts") or
                       config.get("jdbc_connection_string") or "")
                if url:
                    type_map = {"http": "http_endpoint", "elasticsearch": "http_endpoint",
                                "jdbc_streaming": "jdbc_db", "memcached": "http_endpoint"}
                    deps.append(ExternalDependency(
                        dep_type=type_map.get(plugin, "http_endpoint"),
                        path=str(url), plugin=plugin,
                        note=f"{plugin} filter makes outbound calls — no ingest equivalent, redesign required"))

        elif nt == "sequence":
            for c in n.get("children", []): walk(c)
        elif nt == "conditional":
            for b in n.get("branches", []): walk(b.get("body", {}))

    walk(tree)

    # Deduplicate by (dep_type, path)
    seen: set = set()
    unique: List[ExternalDependency] = []
    for d in deps:
        key = (d.dep_type, d.path)
        if key not in seen:
            seen.add(key); unique.append(d)
    return unique


# ─────────────────────────────────────────────────────────────
# 9c. Business metadata sidecar  (new)
# ─────────────────────────────────────────────────────────────

def load_metadata_sidecar(path: Optional[str]) -> Dict[str, PipelineMetadata]:
    """
    Load optional pipeline business/operational metadata from a YAML or JSON
    sidecar file.

    Expected format (YAML):
      ---
      # pipeline_id: metadata
      aixsyslogcef:
        owner: "Network team"
        customer: "Bank A"
        environment: prod
        criticality: high
        volume: "500k events/day"
        notes: "PCI DSS scope"

      winlogbeat:
        owner: "Security team"
        criticality: critical

    If the file does not exist or cannot be parsed, returns an empty dict
    (all pipelines get default empty PipelineMetadata).

    Accepts both YAML and JSON. JSON must be a top-level object keyed by
    pipeline ID.
    """
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}

    raw = p.read_text(encoding="utf-8")

    data: Dict[str, Any] = {}
    try:
        # Try JSON first (no external deps)
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Try simple YAML-style parsing (key: value, indented blocks)
        # We implement a minimal YAML parser for the expected structure
        # to avoid requiring PyYAML as a dependency.
        current_pipeline: Optional[str] = None
        current_block: Dict[str, str] = {}
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"): continue
            if stripped.startswith("---"): continue

            indent = len(line) - len(line.lstrip())
            if indent == 0:
                # Top-level pipeline ID
                if current_pipeline and current_block:
                    data[current_pipeline] = current_block
                current_pipeline = stripped.rstrip(":")
                current_block = {}
            elif indent > 0 and ":" in stripped:
                # Metadata field
                k, _, v = stripped.partition(":")
                current_block[k.strip()] = v.strip().strip('"').strip("'")

        if current_pipeline and current_block:
            data[current_pipeline] = current_block

    result: Dict[str, PipelineMetadata] = {}
    for pid, meta in data.items():
        if isinstance(meta, dict):
            result[pid] = PipelineMetadata(
                owner=       str(meta.get("owner",       "")),
                team=        str(meta.get("team",        "")),
                customer=    str(meta.get("customer",    "")),
                environment= str(meta.get("environment", "")),
                criticality= str(meta.get("criticality", "")),
                volume=      str(meta.get("volume",      "")),
                notes=       str(meta.get("notes",       "")),
            )
    return result


# ─────────────────────────────────────────────────────────────
# 9d. Current → Target architecture summary  (new)
# ─────────────────────────────────────────────────────────────

def build_architecture(
    row: Dict[str, Any],
    deps: List[ExternalDependency],
    blockers: List[Blocker],
    wave: int,
    is_pure: bool,
    is_orch: bool,
) -> Dict[str, Any]:
    """
    Generate a structured current→target architecture summary for one pipeline.

    Returns:
      {
        current:  { inputs, filters, outputs, notes }
        target:   { inputs, ingest_pipeline, manual_rewrites, outputs, notes }
        gap:      [ list of gap descriptions ]
      }
    """
    sources    = row.get("input_sources", []) or []
    sinks      = row.get("terminal_sinks", []) or []
    procs      = row.get("local_processors", {}) or {}
    fts        = int(row.get("filter_transform_score", 0) or 0)
    frs        = int(row.get("full_replacement_score",  0) or 0)

    # ── Current ───────────────────────────────────────────
    cur_inputs  = [s.replace("SOURCE:", "") for s in sources] or ["(pipeline input)"]
    cur_filters = sorted(procs.keys())
    cur_outputs = [s.replace("SINK:", "") for s in sinks] or ["(pipeline output)"]
    cur_notes   = []
    if deps:
        cur_notes.append(f"{len(deps)} external file/service dep(s): " +
                         ", ".join(f"{d.dep_type}:{Path(d.path).name}" for d in deps[:4]))

    # ── Target ────────────────────────────────────────────
    # Inputs
    if any("jdbc" in s.lower() for s in sources):
        tgt_inputs = ["Elastic JDBC Connector  OR  Kafka Connect JDBC Source"]
    elif any("beats" in s.lower() for s in sources):
        tgt_inputs = ["Elastic Agent (Fleet)"]
    elif any("kafka" in s.lower() for s in sources):
        tgt_inputs = ["Elastic Agent (Kafka input)  — verify option parity"]
    elif any("http_poller" in s.lower() for s in sources):
        tgt_inputs = ["Elastic Agent HTTP input  OR  custom Fleet integration"]
    elif not sources:
        tgt_inputs = ["(unchanged — receives from upstream ingest pipeline)"]
    else:
        tgt_inputs = ["Elastic Agent or Beats"]

    # Filter → ingest
    supported   = [p for p in cur_filters if p in INGEST_NATIVE]
    partial     = [p for p in cur_filters if p in INGEST_PARTIAL]
    unsupported = [p for p in cur_filters if p in INGEST_BLOCKERS]

    tgt_ingest  = []
    if supported:  tgt_ingest.append(f"Auto-migrate: {', '.join(sorted(supported))}")
    if partial:    tgt_ingest.append(f"Needs work:   {', '.join(sorted(partial))}")

    manual_rewrites = []
    if unsupported:
        for p in sorted(unsupported):
            advice_map = {
                "ruby":      "Rewrite in Painless script processor",
                "aggregate": "Redesign as enrich policy or application-layer logic",
                "elapsed":   "Replace with APM timing",
                "clone":     "Redesign as pipeline fan-out",
                "metrics":   "Replace with ES aggregations",
                "jdbc_streaming": "Pre-load to enrich index",
                "memcached": "Replace with enrich policy",
                "cipher":    "Evaluate Painless or pre/post-process",
                "http":      "Pre-enrich upstream",
                "elasticsearch": "Replace with enrich policy",
                "dns":       "Pre-resolve or accept missing enrichment",
            }
            manual_rewrites.append(f"{p}: {advice_map.get(p, 'Manual redesign required')}")

    # Outputs
    es_sinks = [s for s in sinks if "elasticsearch" in s.lower() or "opensearch" in s.lower()]
    if wave == 1 or (wave == 2 and not any("kafka" in s.lower() or "file:" in s.lower() for s in sinks)):
        tgt_outputs = [s.replace("SINK:", "") for s in es_sinks] or ["Elasticsearch (direct)"]
        if len(sinks) > len(es_sinks):
            other = [s.replace("SINK:","") for s in sinks if s not in es_sinks]
            tgt_outputs.append(f"(Keep in Logstash: {', '.join(other)})")
    else:
        tgt_outputs = [s.replace("SINK:", "") for s in sinks]

    tgt_notes = []
    if wave == 2 and is_pure:
        tgt_notes.append(f"Filter coverage: {fts}% auto-translatable")
    if wave == 3 and is_orch:
        tgt_notes.append("Keep orchestration in Logstash; filter logic may move to ingest")

    # ── Gaps ─────────────────────────────────────────────
    gaps: List[str] = []
    for b in blockers:
        if b.severity == "hard":
            gaps.append(f"✗ {b.name}: {b.description[:70]}")
        elif b.severity == "workaround":
            gaps.append(f"⚠ {b.name}: {b.description[:70]}")
    for d in deps:
        gaps.append(f"  Dep: {d.dep_type} ({Path(d.path).name}) — {d.note[:60]}")

    return {
        "current": {
            "inputs":  cur_inputs,
            "filters": cur_filters,
            "outputs": cur_outputs,
            "notes":   cur_notes,
        },
        "target": {
            "inputs":          tgt_inputs,
            "ingest_pipeline": tgt_ingest,
            "manual_rewrites": manual_rewrites,
            "outputs":         tgt_outputs,
            "notes":           tgt_notes,
        },
        "gap": gaps,
        "coverage_pct": fts,
    }


# ─────────────────────────────────────────────────────────────
# 9e. Pipeline pattern classifier
# ─────────────────────────────────────────────────────────────

# Primary pattern labels — evaluated top-to-bottom, first match wins
PRIMARY_PATTERNS = [
    "jdbc_polling",
    "api_polling",
    "kafka_consumer",
    "xml_parsing",
    "stateful_aggregation",
    "ruby_custom",
    "multi_output_routing",
    "syslog_parsing",
    "heavy_grok",
    "json_ingestion",
    "passthrough",
    "enrichment_only",
    "beats_simple",
    "standard_transform",
]

# Workshop-friendly descriptions for each primary pattern
PATTERN_DESCRIPTIONS: Dict[str, str] = {
    "jdbc_polling":          "Scheduled JDBC database polling — no Elastic Agent equivalent",
    "api_polling":           "HTTP API polling input — limited Elastic Agent parity",
    "kafka_consumer":        "Kafka consumer — Elastic Agent Kafka input is the replacement path",
    "xml_parsing":           "XML parsing — no native ingest equivalent, needs Painless or pre-parse",
    "stateful_aggregation":  "Stateful aggregation (aggregate/elapsed) — architectural redesign required",
    "ruby_custom":           "Non-trivial Ruby logic — must be rewritten in Painless or pre-processed",
    "multi_output_routing":  "Fan-out to multiple outputs — ingest pipelines write to one index",
    "syslog_parsing":        "Syslog/TCP/UDP input with grok parsing — Elastic Agent syslog input",
    "heavy_grok":            "Complex grok parsing — consider dissect optimisation before migrating",
    "json_ingestion":        "JSON field parsing without complex grok — clean ingest candidate",
    "passthrough":           "Minimal filtering — pure pass-through, trivial to migrate",
    "enrichment_only":       "Enrichment only (geoip/useragent) — clean ingest candidate",
    "beats_simple":          "Simple Beats/Filebeat pipeline — best Wave 1 migration candidate",
    "standard_transform":    "Standard grok+mutate+date transform — typical ingest migration",
}

# Migration portability per primary pattern (0–100 starting point before adjustments)
PATTERN_BASE_PORTABILITY: Dict[str, int] = {
    "jdbc_polling":          20,
    "api_polling":           35,
    "kafka_consumer":        60,
    "xml_parsing":           40,
    "stateful_aggregation":  10,
    "ruby_custom":           35,
    "multi_output_routing":  45,
    "syslog_parsing":        75,
    "heavy_grok":            70,
    "json_ingestion":        90,
    "passthrough":           98,
    "enrichment_only":       88,
    "beats_simple":          92,
    "standard_transform":    78,
}


def _grok_perf_band(row: Dict[str, Any]) -> str:
    """Return the worst grok performance band across all groks in a pipeline."""
    tree = row.get("processors_ordered", {})
    worst = "Fast"
    order = {"Fast": 0, "Moderate": 1, "Slow": 2, "Very Slow": 3}

    def walk(n: Dict[str, Any]) -> None:
        nonlocal worst
        nt = n.get("node_type", "")
        if nt == "processor" and n.get("plugin") == "grok":
            da = n.get("dissect_analysis") or {}
            # Fall back to metrics-based scoring if dissect_analysis not present
            metrics = n.get("metrics", {})
            if metrics:
                pc    = int(metrics.get("pattern_count", 0) or 0)
                chars = int(metrics.get("pattern_chars",  0) or 0)
                ac    = int(metrics.get("alternation_count", 0) or 0)
                nc    = int(metrics.get("named_capture_count", 0) or 0)
                score = pc * 3 + ac + nc + chars // 50
                if metrics.get("heavy"): score += 5
                band = ("Very Slow" if score >= 30 else
                        "Slow"      if score >= 15 else
                        "Moderate"  if score >= 6  else "Fast")
                if order.get(band, 0) > order.get(worst, 0):
                    worst = band
        elif nt == "sequence":
            for c in n.get("children", []): walk(c)
        elif nt == "conditional":
            for b in n.get("branches", []): walk(b.get("body", {}))

    walk(tree)
    return worst


def classify_pipeline(row: Dict[str, Any]) -> PipelinePattern:
    """
    Assign one primary pattern label and any number of secondary tags.

    Primary:  first matching rule in priority order (most specific first).
    Tags:     all applicable traits — not mutually exclusive.
    """
    procs   = set((row.get("local_processors", {}) or {}).keys())
    sources = row.get("input_sources",  []) or []
    sinks   = row.get("terminal_sinks", []) or []
    flags   = row.get("flags", []) or []
    stmts   = int(row.get("total_statements", 0) or 0)
    fts     = int(row.get("filter_transform_score", 0) or 0)

    src_types = {s.lower() for s in sources}
    sink_str  = " ".join(s.lower() for s in sinks)

    def has_src(*types): return any(t in sl for t in types for sl in src_types)
    def has_sink(*types): return any(t in sink_str for t in types)

    grok_count = int((row.get("local_processors") or {}).get("grok", 0))
    ruby_count = int((row.get("local_processors") or {}).get("ruby", 0))

    # Grok metrics from tree
    grok_band = _grok_perf_band(row)

    # Get ruby complexity from metrics if available
    ruby_complex = False
    if ruby_count > 0:
        for p in flatten_processors(row.get("processors_ordered", {})):
            if p.get("plugin") == "ruby":
                m = p.get("metrics", {})
                ruby_complex = (
                    int(m.get("inline_code_chars", 0) or 0) > 100 or
                    bool(m.get("external_path")) or
                    int(m.get("loop_keywords", 0) or 0) > 0 or
                    bool(m.get("has_http")) or
                    bool(m.get("has_require"))
                )
                if ruby_complex: break

    es_only_output = (bool(sinks) and
                      all("elasticsearch" in s.lower() or "opensearch" in s.lower()
                          for s in sinks))
    multi_out = (len(sinks) > 1 or
                 len([o for o in (row.get("local_outputs") or []) if o]) > 1)
    branch_count = int((row.get("migration") or {}).get("penalties", {}).get("branching", 0) > 0 or
                       row.get("migration", {}) and row["migration"].get("filter_transform_score", 100) < 100 or 0)
    # Use raw branch_count from aggregated data
    bc = int(row.get("aggregated_processors", {}).get("grok", 0))  # placeholder; real below
    # Safely get branch info
    mig  = row.get("migration", {}) or {}
    reasons = " ".join(mig.get("reasons", []))
    has_branches = "conditional" in reasons or "branch" in reasons

    # ── Primary pattern rules (priority order) ──────────────
    if has_src("jdbc"):
        primary = "jdbc_polling"
    elif has_src("http_poller"):
        primary = "api_polling"
    elif has_src("kafka"):
        primary = "kafka_consumer"
    elif "xml" in procs:
        primary = "xml_parsing"
    elif "aggregate" in procs or "elapsed" in procs:
        primary = "stateful_aggregation"
    elif ruby_count > 0 and ruby_complex:
        primary = "ruby_custom"
    elif multi_out:
        primary = "multi_output_routing"
    elif has_src("syslog", "tcp", "udp"):
        primary = "syslog_parsing"
    elif grok_count >= 2 or grok_band in ("Slow", "Very Slow"):
        primary = "heavy_grok"
    elif "json" in procs and grok_count == 0 and ruby_count == 0:
        primary = "json_ingestion"
    elif stmts <= 2 and not (procs & {"grok", "ruby", "xml", "aggregate"}):
        primary = "passthrough"
    elif not (procs - {"geoip", "useragent", "mutate", "date"}) and (
            "geoip" in procs or "useragent" in procs):
        primary = "enrichment_only"
    elif has_src("beats") and grok_count <= 1 and ruby_count == 0:
        primary = "beats_simple"
    else:
        primary = "standard_transform"

    # ── Secondary tags (computed independently) ──────────────
    tags: List[str] = []

    if ruby_count > 0:
        tags.append("has_ruby")
    if has_branches:
        tags.append("has_conditionals")
    if has_sink("kafka"):
        tags.append("kafka_output")
    if has_sink("file:"):
        tags.append("file_output")
    if "translate" in procs:
        tags.append("has_translate")
    if "geoip" in procs:
        tags.append("has_geoip")
    if "useragent" in procs:
        tags.append("has_useragent")
    if es_only_output:
        tags.append("es_only_output")
    if grok_band in ("Slow", "Very Slow"):
        tags.append("high_grok_cost")
    if any(d.dep_type in ("dict_file", "ruby_script", "patterns_dir")
           for d in []):  # ext_deps not available here — set from caller
        tags.append("has_external_deps")
    if len((row.get("files") or [])) > 1:
        tags.append("split_file_pair")
    if not (row.get("input_sources") or []) and not (row.get("terminal_sinks") or []):
        tags.append("chain_pipeline")
    if any(f.startswith("dead_end") for f in flags):
        tags.append("dead_end")
    if any(f.startswith("unresolved") for f in flags):
        tags.append("unresolved_routing")
    if grok_count > 0:
        tags.append(f"grok_perf_{grok_band.lower().replace(' ','_')}")
    if "dissect" in procs:
        tags.append("uses_dissect")
    if "fingerprint" in procs:
        tags.append("uses_fingerprint")

    # ── Portability and coupling scores ──────────────────────
    portability = PATTERN_BASE_PORTABILITY.get(primary, 70)
    # Adjust portability
    if ruby_count > 0 and ruby_complex: portability -= 20
    elif ruby_count > 0:               portability -= 10
    if "aggregate" in procs:           portability -= 25
    if "xml" in procs:                 portability -= 15
    if multi_out:                      portability -= 10
    if "translate" in procs:           portability -= 10
    if has_sink("kafka"):              portability -= 10
    if has_sink("file:"):              portability -= 8
    if grok_band == "Very Slow":       portability -= 8
    if grok_band == "Slow":            portability -= 4
    if es_only_output:                 portability += 8
    portability = max(0, min(100, portability))

    # Coupling score (0–100 — higher = more external dependencies)
    coupling = 0
    if has_src("jdbc"):                coupling += 30
    if has_src("http_poller"):         coupling += 20
    if ruby_count > 0 and ruby_complex: coupling += 15
    if "translate" in procs:           coupling += 10
    if has_src("kafka"):               coupling += 10
    if has_sink("kafka"):              coupling += 10
    if multi_out:                      coupling += 10
    if "elasticsearch" in procs:       coupling += 8   # ES lookup filter
    coupling = min(100, coupling)

    # ── Complexity band ───────────────────────────────────────
    score = int(row.get("total_score", 0) or 0)
    stmts = int(row.get("total_statements", 0) or 0)
    complexity = ("High"   if score > 120 or stmts > 60 or
                             "stateful" in primary or "ruby_custom" == primary
                  else "Medium" if score > 40 or stmts > 20
                  else "Low")

    return PipelinePattern(
        primary=primary,
        tags=sorted(set(tags)),
        portability=portability,
        coupling=coupling,
        complexity=complexity,
    )


# ─────────────────────────────────────────────────────────────
# 9f. Anti-pattern detection
# ─────────────────────────────────────────────────────────────

def detect_anti_patterns(row: Dict[str, Any]) -> List[AntiPatternFlag]:
    """
    Scan one pipeline row for concrete anti-patterns.
    Returns a list of AntiPatternFlag objects, one per finding.
    """
    flags: List[AntiPatternFlag] = []
    procs   = row.get("local_processors", {}) or {}
    sources = row.get("input_sources",  []) or []
    sinks   = row.get("terminal_sinks", []) or []
    row_flags = row.get("flags", []) or []
    tree    = row.get("processors_ordered", {})
    all_procs = flatten_processors(tree)

    src_types = {s.lower() for s in sources}
    sink_str  = " ".join(s.lower() for s in sinks)

    # ── AP-1: Dead-end pipeline ───────────────────────────────
    if not sinks and not (row.get("local_outputs") or []):
        flags.append(AntiPatternFlag(
            anti_pattern_id="dead_end_pipeline",
            name="Dead-end pipeline",
            severity="high",
            description="Pipeline has no output destination — events are silently dropped.",
            recommendation="Add an Elasticsearch or pipeline output, or confirm this pipeline "
                           "is intentionally disabled.",
        ))

    # ── AP-2: GREEDYDATA in non-final position ────────────────
    for p in all_procs:
        if p.get("plugin") != "grok": continue
        config = p.get("config", {})
        match  = config.get("match", {})
        patterns: List[str] = []
        if isinstance(match, dict):
            for v in match.values():
                if isinstance(v, str): patterns.append(v)
                elif isinstance(v, list): patterns.extend(v)
        elif isinstance(match, list):
            for i in range(1, len(match), 2): patterns.append(str(match[i]))
        for pat in patterns:
            parts = re.findall(r'%\{([^}]+)\}', pat)
            for i, inner in enumerate(parts):
                pname = inner.split(":")[0].upper()
                if pname == "GREEDYDATA" and i < len(parts) - 1:
                    flags.append(AntiPatternFlag(
                        anti_pattern_id="greedydata_non_final",
                        name="GREEDYDATA in non-final position",
                        severity="high",
                        description=f"Pattern '{pat[:70]}' uses GREEDYDATA before the last capture. "
                                    "This matches everything including delimiters and causes "
                                    "catastrophic backtracking.",
                        recommendation="Move GREEDYDATA to the final position, or replace "
                                       "mid-pattern usage with DATA (lazy match).",
                    ))
                    break  # one flag per grok block is enough

    # ── AP-3: Multi-pattern grok with alternation ─────────────
    for p in all_procs:
        if p.get("plugin") != "grok": continue
        m = p.get("metrics", {})
        pc = int(m.get("pattern_count", 0) or 0)
        ac = int(m.get("alternation_count", 0) or 0)
        if pc >= 3 or (pc >= 2 and ac >= 2):
            flags.append(AntiPatternFlag(
                anti_pattern_id="high_alternation_grok",
                name="High-alternation grok",
                severity="medium",
                description=f"Grok has {pc} match pattern(s) with {ac} alternation(s). "
                            "Multiple alternatives cause excessive backtracking under load.",
                recommendation="Use dissect for the common case + grok as a fallback only. "
                               "Pre-filter events by type before hitting the grok block.",
            ))
            break  # one flag per pipeline

    # ── AP-4: Ruby for trivial field manipulation ─────────────
    for p in all_procs:
        if p.get("plugin") != "ruby": continue
        m = p.get("metrics", {})
        lines  = int(m.get("inline_code_lines", 0) or 0)
        chars  = int(m.get("inline_code_chars", 0) or 0)
        has_loop = int(m.get("loop_keywords", 0) or 0) > 0
        has_http = bool(m.get("has_http"))
        has_req  = bool(m.get("has_require"))
        ext      = m.get("external_path")
        if not (has_loop or has_http or has_req or ext) and lines <= 4 and chars <= 200:
            flags.append(AntiPatternFlag(
                anti_pattern_id="trivial_ruby",
                name="Ruby used for simple field mutation",
                severity="medium",
                description=f"Ruby block is {lines} line(s) / {chars} chars with no loops, "
                            "HTTP calls, or requires — likely replaceable with mutate or "
                            "a script processor.",
                recommendation="Replace with mutate (add_field, rename, convert) or a "
                               "minimal Painless script processor. Removes the JRuby overhead.",
            ))

    # ── AP-5: Unresolved send_to target ───────────────────────
    if any(f.startswith("unresolved") for f in row_flags):
        unresolved = [o for o in (row.get("local_outputs") or [])
                      if o and not o.startswith("SINK:")]
        flags.append(AntiPatternFlag(
            anti_pattern_id="unresolved_routing",
            name="Unresolved pipeline routing target",
            severity="high",
            description=f"Pipeline routes to address(es) {unresolved[:3]} that have no "
                        "matching input definition in the scanned files.",
            recommendation="Locate the missing pipeline definition, or confirm routing "
                           "is intentionally external (e.g. a different pipelines.yml).",
        ))

    # ── AP-6: JDBC with no schedule (runs once at startup) ────
    if any("jdbc" in s.lower() for s in sources):
        raw_in = row.get("raw_input_text", "") or ""
        has_schedule = "schedule" in raw_in.lower()
        if not has_schedule:
            flags.append(AntiPatternFlag(
                anti_pattern_id="jdbc_no_schedule",
                name="JDBC input with no schedule",
                severity="medium",
                description="JDBC input has no schedule => directive — runs once at "
                            "Logstash startup only, then stops.",
                recommendation="Add a schedule (e.g. '* * * * *') or confirm this "
                               "pipeline is triggered externally via the Logstash API.",
            ))

    # ── AP-7: Large inline translate dictionary ───────────────
    for p in all_procs:
        if p.get("plugin") != "translate": continue
        m = p.get("metrics", {})
        entries  = int(m.get("dictionary_entries", 0) or 0)
        has_file = bool(m.get("has_file"))
        if entries > 50 and not has_file:
            flags.append(AntiPatternFlag(
                anti_pattern_id="large_inline_dictionary",
                name="Large inline translate dictionary",
                severity="low",
                description=f"Translate filter has {entries} inline dictionary entries. "
                            "Large inline dicts increase config size and slow reloads.",
                recommendation="Move dictionary to dictionary_path file, or pre-load "
                               "into an Elasticsearch enrich index for ingest migration.",
            ))

    # ── AP-8: Kafka output without Elasticsearch output ───────
    has_kafka_out = "kafka" in sink_str
    has_es_out    = "elasticsearch" in sink_str or "opensearch" in sink_str
    if has_kafka_out and not has_es_out:
        flags.append(AntiPatternFlag(
            anti_pattern_id="kafka_only_output",
            name="Kafka-only output (no Elasticsearch)",
            severity="info",
            description="Pipeline writes only to Kafka, not directly to Elasticsearch. "
                        "This is a routing/transformation layer, not a terminal indexing step.",
            recommendation="Document data flow clearly. During migration, determine whether "
                           "the downstream Kafka consumer also needs to be migrated.",
        ))

    # ── AP-9: Duplicate grok pattern (cross-pipeline) ─────────
    # This one is computed cross-pipeline in build_anti_pattern_summary;
    # here we just mark a flag that can be set by the caller.
    # (Skipped per-pipeline — handled at the summary level)

    # ── AP-10: Clone filter (event duplication without fan-out config) ──
    if "clone" in procs:
        flags.append(AntiPatternFlag(
            anti_pattern_id="clone_filter",
            name="clone filter (event duplication)",
            severity="medium",
            description="clone creates duplicate events in-pipeline. "
                        "No ingest pipeline equivalent exists.",
            recommendation="Redesign as pipeline fan-out at the data source level, "
                           "or use index aliases / cross-cluster replication.",
        ))

    # ── AP-11: Multiple outputs to same Elasticsearch cluster ─
    es_sinks = [s for s in sinks if "elasticsearch" in s.lower() or "opensearch" in s.lower()]
    if len(es_sinks) > 1:
        flags.append(AntiPatternFlag(
            anti_pattern_id="multiple_es_outputs",
            name="Multiple Elasticsearch outputs",
            severity="low",
            description=f"Pipeline writes to {len(es_sinks)} separate Elasticsearch outputs: "
                        f"{', '.join(s[:40] for s in es_sinks[:3])}.",
            recommendation="Consider using dynamic index naming (%{{[field]}}) in a single "
                           "output, or route via pipeline fan-out.",
        ))

    return flags


# ─────────────────────────────────────────────────────────────
# 9g. Cross-pipeline pattern and anti-pattern summaries
# ─────────────────────────────────────────────────────────────

def build_pattern_summary(advices: List[PipelineAdvice]) -> List[Dict[str, Any]]:
    """
    Aggregate per-pipeline patterns into a workshop-ready summary table.

    One row per primary pattern, sorted by pipeline count descending.
    """
    buckets: Dict[str, List[PipelineAdvice]] = defaultdict(list)
    for a in advices:
        if a.pattern:
            buckets[a.pattern.primary].append(a)
        else:
            buckets["unknown"].append(a)

    rows_out: List[Dict[str, Any]] = []
    for primary, members in buckets.items():
        total = len(members)
        if total == 0: continue

        # Common plugins across all pipelines in this pattern
        plugin_counter: Counter = Counter()
        for a in members:
            # pipeline_id → row map not available here; use fingerprint for plugins
            fp = a.processor_fingerprint or ""
            # Extract proc names from fingerprint: "procs:grok+mutate|src:..."
            m = re.match(r'procs:([^|]+)', fp)
            if m:
                for plugin in m.group(1).split("+"):
                    if plugin and plugin != "(none)":
                        plugin_counter[plugin] += 1
        top_plugins = [p for p, _ in plugin_counter.most_common(6)]

        avg_portability = round(sum(a.pattern.portability for a in members
                                    if a.pattern) / total, 0) if total else 0
        avg_coupling    = round(sum(a.pattern.coupling    for a in members
                                    if a.pattern) / total, 0) if total else 0
        avg_benefit     = round(sum(a.operational_benefit for a in members) / total, 0)
        avg_fts         = round(sum(int(a.architecture.get("coverage_pct", 0) or 0)
                                    for a in members) / total, 0)

        wave_dist = Counter(a.wave for a in members)
        complexity_dist = Counter(a.pattern.complexity for a in members if a.pattern)

        rows_out.append({
            "pattern":             primary,
            "description":         PATTERN_DESCRIPTIONS.get(primary, ""),
            "pipeline_count":      total,
            "pct_of_total":        0.0,   # filled in after
            "top_plugins":         top_plugins,
            "complexity_dist":     dict(complexity_dist),
            "dominant_complexity": complexity_dist.most_common(1)[0][0] if complexity_dist else "?",
            "avg_portability":     int(avg_portability),
            "avg_coupling":        int(avg_coupling),
            "avg_benefit":         int(avg_benefit),
            "avg_filter_coverage": int(avg_fts),
            "wave_distribution":   dict(wave_dist),
            "wave1_count":         wave_dist.get(1, 0),
            "wave2_count":         wave_dist.get(2, 0),
            "wave3_count":         wave_dist.get(3, 0),
            "pipeline_ids":        [a.pipeline_id for a in members],
        })

    # Fill in percentages
    grand_total = sum(r["pipeline_count"] for r in rows_out)
    for r in rows_out:
        r["pct_of_total"] = round(r["pipeline_count"] * 100 / grand_total, 1) if grand_total else 0

    rows_out.sort(key=lambda r: -r["pipeline_count"])
    return rows_out


def build_anti_pattern_summary(advices: List[PipelineAdvice]) -> List[Dict[str, Any]]:
    """
    Aggregate all anti-pattern findings cross-pipeline.

    One row per anti-pattern type, sorted by pipeline count descending.
    Also adds cross-pipeline "duplicate grok pattern" detection.
    """
    # Cross-pipeline duplicate grok pattern detection
    grok_pattern_index: Dict[str, List[str]] = defaultdict(list)
    for a in advices:
        # Get grok patterns from the fingerprint or field inventory
        for target in a.field_inventory.grok_targets:
            grok_pattern_index[target].append(a.pipeline_id)

    duplicate_grok_pipelines: Set[str] = set()
    for target, pids in grok_pattern_index.items():
        if len(pids) >= 3:
            for pid in pids:
                duplicate_grok_pipelines.add(pid)

    # Inject duplicate_grok flag on relevant advices
    for a in advices:
        if a.pipeline_id in duplicate_grok_pipelines:
            already = any(ap.anti_pattern_id == "duplicate_grok_pattern"
                          for ap in a.anti_patterns)
            if not already:
                a.anti_patterns.append(AntiPatternFlag(
                    anti_pattern_id="duplicate_grok_pattern",
                    name="Duplicate grok capture fields",
                    severity="medium",
                    description="This pipeline captures the same named fields as 3+ other pipelines, "
                                "suggesting repeated parsing logic that could be standardised.",
                    recommendation="Consider a shared ingest pipeline template for the common "
                                   "parsing logic, reducing duplication across pipelines.",
                ))

    # Aggregate by anti_pattern_id
    buckets: Dict[str, List[Tuple[str, AntiPatternFlag]]] = defaultdict(list)
    for a in advices:
        for ap in a.anti_patterns:
            buckets[ap.anti_pattern_id].append((a.pipeline_id, ap))

    rows_out: List[Dict[str, Any]] = []
    for apid, entries in buckets.items():
        pipeline_ids = list(dict.fromkeys(pid for pid, _ in entries))
        sample_flag  = entries[0][1]
        rows_out.append({
            "anti_pattern_id":  apid,
            "name":             sample_flag.name,
            "severity":         sample_flag.severity,
            "pipeline_count":   len(pipeline_ids),
            "description":      sample_flag.description,
            "recommendation":   sample_flag.recommendation,
            "pipeline_ids":     pipeline_ids,
        })

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    rows_out.sort(key=lambda r: (severity_order.get(r["severity"], 9), -r["pipeline_count"]))
    return rows_out


# ─────────────────────────────────────────────────────────────
# 9. Main analysis pass
# ─────────────────────────────────────────────────────────────

def analyse(data: Dict[str, Any], metadata_path: Optional[str] = None) -> MigrationPlan:
    """Run the full advisor analysis over the analyzer JSON output."""
    rows    = data.get("logical_pipelines", [])
    edges   = data.get("logical_edges", {})
    summary = data.get("overall_summary", {})
    scan_root = summary.get("scan_root", "")

    all_ids = {r.get("pipeline", "") for r in rows}

    # Load optional business metadata sidecar
    metadata_map = load_metadata_sidecar(metadata_path)

    advices: List[PipelineAdvice] = []

    for row in rows:
        pid  = row.get("pipeline", "")
        fts  = int(row.get("filter_transform_score", 0) or 0)
        frs  = int(row.get("full_replacement_score",  0) or 0)
        tree = row.get("processors_ordered", {})

        # Field inventory
        inv = build_field_inventory(tree)

        # External dependencies
        ext_deps = extract_external_deps(row)

        # Blockers
        blockers = extract_blockers(row)

        # Effort
        effort_band, effort_score = compute_effort(row, blockers)

        # Operational benefit
        benefit, benefit_breakdown = compute_operational_benefit(row, all_ids, edges)

        # Character
        is_pure, is_orch = classify_character(row)

        # Wave
        wave, wave_reason = assign_wave(row, benefit, effort_score,
                                        blockers, is_pure, is_orch)

        # Decision
        decision = make_decision(wave, is_pure, is_orch, fts, frs)

        # Architecture summary
        arch = build_architecture(row, ext_deps, blockers, wave, is_pure, is_orch)

        # Fingerprint
        fp = build_fingerprint(row)

        # Business metadata (empty defaults if not in sidecar)
        meta = metadata_map.get(pid, PipelineMetadata())

        # Pattern classification
        pat = classify_pipeline(row)

        # Anti-pattern detection
        anti_pats = detect_anti_patterns(row)

        advices.append(PipelineAdvice(
            pipeline_id=pid,
            wave=wave,
            wave_reason=wave_reason,
            operational_benefit=benefit,
            benefit_breakdown=benefit_breakdown,
            migration_effort=effort_band,
            effort_score=effort_score,
            decision=decision,
            blockers=blockers,
            field_inventory=inv,
            external_deps=ext_deps,
            metadata=meta,
            architecture=arch,
            cluster_id=None,
            cluster_template=False,
            processor_fingerprint=fp,
            is_pure_transformer=is_pure,
            is_orchestrator=is_orch,
            pattern=pat,
            anti_patterns=anti_pats,
        ))

    # Sort within wave by benefit descending (best ROI first)
    advices.sort(key=lambda a: (a.wave, -a.operational_benefit))

    # Cluster
    clusters = cluster_pipelines(advices)

    # Populate avg_fts on clusters properly
    row_map = {r.get("pipeline",""): r for r in rows}
    for c in clusters:
        fts_vals = [int(row_map.get(p, {}).get("filter_transform_score", 0) or 0)
                    for p in c.pipeline_ids]
        c.avg_fts = round(sum(fts_vals) / len(fts_vals), 1) if fts_vals else 0.0

    # Wave counts
    wave_counts = Counter(a.wave for a in advices)

    # Summary text
    w1 = wave_counts.get(1, 0)
    w2 = wave_counts.get(2, 0)
    w3 = wave_counts.get(3, 0)
    multi_clusters = [c for c in clusters if c.size > 1]
    summary_text = (
        f"Analysed {len(advices)} pipeline(s) across {len(clusters)} structural pattern(s).\n"
        f"  Wave 1 (Quick wins):    {w1:3d} pipeline(s) — migrate now\n"
        f"  Wave 2 (Medium effort): {w2:3d} pipeline(s) — partial or redesign-then-migrate\n"
        f"  Wave 3 (Keep/redesign): {w3:3d} pipeline(s) — architectural work needed\n"
        f"  Pattern clusters with >1 pipeline: {len(multi_clusters)} "
        f"(template reuse potential)\n"
    )

    import datetime
    all_inputs  = build_input_inventory(rows, advices)
    all_outputs = build_output_inventory(rows, advices)
    all_fields  = build_global_field_inventory(advices)
    pat_summary  = build_pattern_summary(advices)
    anti_summary = build_anti_pattern_summary(advices)  # also injects cross-pipeline flags

    # Enrich summary_text with pattern counts
    pat_counts = Counter(a.pattern.primary for a in advices if a.pattern)
    top_patterns = pat_counts.most_common(4)
    pat_line = "  Top patterns: " + "  •  ".join(
        f"{p} ({n})" for p, n in top_patterns
    )
    total_anti = sum(len(a.anti_patterns) for a in advices)
    anti_line  = f"  Anti-patterns detected: {total_anti} across {sum(1 for a in advices if a.anti_patterns)} pipeline(s)\n"

    return MigrationPlan(
        generated_at=datetime.datetime.now().isoformat(timespec="seconds"),
        scan_root=scan_root,
        total_pipelines=len(advices),
        wave_counts=dict(wave_counts),
        clusters=clusters,
        pipelines=advices,
        summary_text=summary_text + pat_line + "\n" + anti_line,
        all_inputs=all_inputs,
        all_outputs=all_outputs,
        all_fields=all_fields,
        pattern_summary=pat_summary,
        anti_pattern_summary=anti_summary,
    )

# ─────────────────────────────────────────────────────────────
# 10. Output formatting
# ─────────────────────────────────────────────────────────────

WAVE_LABELS = {
    1: "Wave 1 — Quick wins        (migrate now)",
    2: "Wave 2 — Medium effort     (partial/redesign-then-migrate)",
    3: "Wave 3 — Keep / Redesign   (architectural work needed)",
}

WAVE_COLORS_ANSI = {1: "\033[92m", 2: "\033[93m", 3: "\033[91m"}
RESET = "\033[0m"

def col(text: str, width: int) -> str:
    t = str(text)
    return t[:width].ljust(width) if len(t) <= width else t[:width-1] + "…"


def print_plan(plan: MigrationPlan, wave_filter: Optional[int], top_n: int,
               use_color: bool = True):
    C = WAVE_COLORS_ANSI if use_color else {1:"",2:"",3:""}

    print("=" * 90)
    print("LOGSTASH MIGRATION ADVISORY PLAN")
    print("=" * 90)
    print(plan.summary_text)

    # ── Pattern clusters ──────────────────────────────────
    multi = [c for c in plan.clusters if c.size > 1]
    if multi:
        print("─" * 90)
        print("PATTERN CLUSTERS  (families sharing the same processor structure)")
        print()
        print(f"{'ID':<6} {'Size':>4}  {'AvgFilt%':>8}  {'AvgBenefit':>10}  "
              f"{'Representative':<30}  Description")
        print("─" * 90)
        for c in multi[:20]:
            desc = c.description[:52]
            print(f"{c.cluster_id:<6} {c.size:>4}  {c.avg_fts:>7.0f}%  "
                  f"{c.avg_benefit:>10.0f}  {col(c.representative,30)}  {desc}")
        print()

    # ── Per-wave pipeline tables ──────────────────────────
    for wave_num in (1, 2, 3):
        if wave_filter and wave_filter != wave_num:
            continue
        members = [a for a in plan.pipelines if a.wave == wave_num][:top_n]
        if not members:
            continue

        wc = C.get(wave_num, "")
        print("─" * 90)
        print(f"{wc}{WAVE_LABELS[wave_num]}{RESET}")
        print()
        print(f"{'PIPELINE':<36} {'Pattern':<22} {'Port':>4} {'Benefit':>7} {'Effort':<7} {'Decision':<38}")
        print("─" * 90)
        for a in members:
            crit = a.metadata.criticality
            crit_badge = f" [{crit.upper()}]" if crit else ""
            pat_label  = a.pattern.primary if a.pattern else "?"
            port       = a.pattern.portability if a.pattern else 0
            ap_badge   = f" ⚑{len(a.anti_patterns)}" if a.anti_patterns else ""
            print(f"{wc}{col(a.pipeline_id,36)}{RESET} "
                  f"{col(pat_label,22)} {port:>4}  "
                  f"{a.operational_benefit:>7}  {a.migration_effort:<7}"
                  f"{col(a.decision, 38)}{crit_badge}{ap_badge}")

        # Detail for Wave 1 (most actionable)
        if wave_num == 1:
            print()
            print("  Suggested migration order (benefit-first within Wave 1):")
            for i, a in enumerate(members, 1):
                icon = "⭐" if a.is_pure_transformer else "→"
                tmpl = f" [cluster template: {a.cluster_id}]" if a.cluster_template else ""
                meta_str = ""
                if a.metadata.customer:  meta_str += f"  customer={a.metadata.customer}"
                if a.metadata.criticality: meta_str += f"  criticality={a.metadata.criticality}"
                print(f"  {i:2d}. {icon} {a.pipeline_id}{tmpl}{meta_str}")
                print(f"       Pattern:  {a.pattern.primary if a.pattern else '?'}"
                      f"  tags=[{', '.join((a.pattern.tags or [])[:4])}]"
                      f"  portability={a.pattern.portability if a.pattern else '?'}"
                      f"  coupling={a.pattern.coupling if a.pattern else '?'}"
                      if a.pattern else f"  {a.pipeline_id}")
                print(f"       Benefit: {a.operational_benefit}/100  "
                      f"Effort: {a.migration_effort} ({a.effort_score})  "
                      f"Decision: {a.decision}")
                if a.blockers:
                    for b in a.blockers[:2]:
                        sev_icon = {"hard":"✗","workaround":"⚠","decision":"?"}[b.severity]
                        print(f"       {sev_icon} {b.name}: {b.recommendation[:65]}")
                if a.external_deps:
                    for d in a.external_deps[:2]:
                        print(f"       📎 {d.dep_type}: {d.path[:55]}")
                if a.anti_patterns:
                    for ap in a.anti_patterns[:2]:
                        sev_icon = {"high":"✗","medium":"⚠","low":"·","info":"ℹ"}.get(ap.severity,"·")
                        print(f"       {sev_icon} AP: {ap.name}")
                print()

        elif wave_num == 2:
            print()
            for a in members[:8]:
                meta_str = f"  [{a.metadata.criticality.upper()}]" if a.metadata.criticality else ""
                pat_str  = f"  pattern={a.pattern.primary}" if a.pattern else ""
                print(f"  • {a.pipeline_id}{meta_str}{pat_str}")
                print(f"    Decision: {a.decision}")
                print(f"    Reason:   {a.wave_reason[:80]}")
                if a.blockers:
                    for b in a.blockers[:3]:
                        sev_icon = {"hard":"✗","workaround":"⚠","decision":"?"}[b.severity]
                        print(f"    {sev_icon} {b.name}: {b.recommendation[:65]}")
                if a.external_deps:
                    print(f"    📎 Deps: {', '.join(d.dep_type+':'+Path(d.path).name for d in a.external_deps[:3])}")
                if a.anti_patterns:
                    for ap in a.anti_patterns[:2]:
                        sev_icon = {"high":"✗","medium":"⚠","low":"·","info":"ℹ"}.get(ap.severity,"·")
                        print(f"    {sev_icon} AP: {ap.name}: {ap.recommendation[:60]}")
                print()

        elif wave_num == 3:
            print()
            for a in members[:8]:
                meta_str = f"  [{a.metadata.criticality.upper()}]" if a.metadata.criticality else ""
                print(f"  • {a.pipeline_id}{meta_str}")
                print(f"    Decision: {a.decision}")
                hard_names = [b.name for b in a.blockers if b.severity == "hard"]
                if hard_names:
                    print(f"    Hard blockers: {', '.join(hard_names)}")
                if a.external_deps:
                    print(f"    📎 Deps: {', '.join(d.dep_type+':'+Path(d.path).name for d in a.external_deps[:3])}")
                print()

    # ── PATTERN SUMMARY ───────────────────────────────────
    if plan.pattern_summary:
        print("─" * 90)
        print("PATTERN SUMMARY  (workshop view — all pipelines classified by primary pattern)")
        print()
        # Header
        print(f"  {'PATTERN':<24} {'#':>4} {'%':>5}  {'Complexity':<10} "
              f"{'Port':>4} {'Coup':>4}  {'W1':>3} {'W2':>3} {'W3':>3}  "
              f"{'Filt%':>5}  Description")
        print(f"  {'─'*24} {'─'*4} {'─'*5}  {'─'*10} "
              f"{'─'*4} {'─'*4}  {'─'*3} {'─'*3} {'─'*3}  "
              f"{'─'*5}  {'─'*38}")
        for r in plan.pattern_summary:
            desc = PATTERN_DESCRIPTIONS.get(r["pattern"], "")[:38]
            print(f"  {r['pattern']:<24} {r['pipeline_count']:>4} {r['pct_of_total']:>5.1f}%"
                  f"  {r['dominant_complexity']:<10} "
                  f"{r['avg_portability']:>4} {r['avg_coupling']:>4}  "
                  f"{r['wave1_count']:>3} {r['wave2_count']:>3} {r['wave3_count']:>3}  "
                  f"{r['avg_filter_coverage']:>4}%  {desc}")
        print()
        # Summary notes for workshop
        print("  Notes:")
        print("    Port = Portability score (0–100, higher = easier to migrate)")
        print("    Coup = Coupling score (0–100, higher = more external dependencies)")
        print("    W1/W2/W3 = pipeline count per migration wave")
        print()

    # ── ANTI-PATTERNS DETECTED ────────────────────────────
    if plan.anti_pattern_summary:
        print("─" * 90)
        print("ANTI-PATTERNS DETECTED  (across all pipelines)")
        print()
        sev_colors = {
            "high":   "\033[91m" if use_color else "",
            "medium": "\033[93m" if use_color else "",
            "low":    "\033[96m" if use_color else "",
            "info":   "\033[90m" if use_color else "",
        }
        print(f"  {'SEV':<7} {'ANTI-PATTERN':<36} {'PIPELINES':>9}  RECOMMENDATION")
        print(f"  {'─'*7} {'─'*36} {'─'*9}  {'─'*40}")
        for r in plan.anti_pattern_summary:
            sc = sev_colors.get(r["severity"], "")
            print(f"  {sc}{r['severity'].upper():<7}{RESET} "
                  f"{col(r['name'], 36)} {r['pipeline_count']:>9}  "
                  f"{r['recommendation'][:50]}")
        print()
        # Per-pipeline list for high-severity findings
        high = [r for r in plan.anti_pattern_summary if r["severity"] == "high"]
        if high:
            print("  High-severity detail:")
            for r in high:
                pids = ", ".join(r["pipeline_ids"][:5])
                overflow = f"  … +{len(r['pipeline_ids'])-5} more" if len(r['pipeline_ids']) > 5 else ""
                print(f"  ✗ {r['name']}")
                print(f"    Pipelines: {pids}{overflow}")
                print(f"    Fix: {r['recommendation'][:75]}")
                print()

    # ── CURRENT → TARGET ARCHITECTURE ────────────────────
    print("─" * 90)
    print("CURRENT → TARGET ARCHITECTURE  (per pipeline)")
    print()
    shown = 0
    # Show Wave 1 first, then Wave 2, capped at top_n total
    for a in plan.pipelines:
        if shown >= min(top_n, 20): break
        arch = a.architecture
        cur  = arch.get("current", {})
        tgt  = arch.get("target",  {})
        gaps = arch.get("gap",     [])
        cov  = arch.get("coverage_pct", 0)

        meta_tags = []
        if a.metadata.customer:    meta_tags.append(f"customer={a.metadata.customer}")
        if a.metadata.environment: meta_tags.append(f"env={a.metadata.environment}")
        if a.metadata.owner:       meta_tags.append(f"owner={a.metadata.owner}")
        meta_str = f"  ({', '.join(meta_tags)})" if meta_tags else ""

        wc_color = C.get(a.wave, "")
        print(f"  {wc_color}{'─'*3} {a.pipeline_id}  [Wave {a.wave}]{RESET}{meta_str}")

        # Current
        print(f"  │  CURRENT:")
        print(f"  │    Input:   {', '.join(cur.get('inputs', []))}")
        print(f"  │    Filters: {', '.join(cur.get('filters', [])) or '(none)'}")
        print(f"  │    Output:  {', '.join(cur.get('outputs', []))}")
        for note in cur.get("notes", []):
            print(f"  │    ⚠ {note}")

        # Target
        print(f"  │  TARGET  (filter coverage: {cov}%):")
        print(f"  │    Input:   {', '.join(tgt.get('inputs', []))}")
        ingest = tgt.get("ingest_pipeline", [])
        if ingest:
            for line in ingest: print(f"  │    Ingest:  {line}")
        rewrites = tgt.get("manual_rewrites", [])
        if rewrites:
            for r in rewrites: print(f"  │    ✎ Manual: {r}")
        print(f"  │    Output:  {', '.join(tgt.get('outputs', []))}")
        for note in tgt.get("notes", []):
            print(f"  │    ℹ {note}")

        # Gaps
        if gaps:
            print(f"  │  GAPS:")
            for g in gaps[:4]: print(f"  │    {g}")

        print(f"  │")
        shown += 1

    # ── EXTERNAL DEPENDENCIES ─────────────────────────────
    all_deps = [(a.pipeline_id, d) for a in plan.pipelines for d in a.external_deps]
    if all_deps:
        print("─" * 90)
        print("EXTERNAL DEPENDENCIES  (files, DBs, services referenced across all pipelines)")
        print()
        by_type: Dict[str, List[Tuple[str,ExternalDependency]]] = defaultdict(list)
        for pid, d in all_deps:
            by_type[d.dep_type].append((pid, d))
        for dtype, entries in sorted(by_type.items()):
            print(f"  ┌─ {dtype.replace('_',' ').title()} ({len(entries)}) {'─'*max(0,50-len(dtype))}")
            for pid, d in entries[:15]:
                print(f"  │  {pid:<30}  {d.path[:50]}")
                print(f"  │  {'':30}  → {d.note[:55]}")
            if len(entries) > 15:
                print(f"  │  … {len(entries)-15} more")
            print(f"  └{'─'*60}")
            print()

    # ── ALL INPUTS ────────────────────────────────────────
    print("─" * 90)
    print("ALL INPUTS  (distinct sources across all pipelines)")
    print()
    if plan.all_inputs:
        print(f"  {'TYPE':<14} {'COUNT':>5}   {'W1':>3} {'W2':>3} {'W3':>3}   LABEL")
        print(f"  {'─'*14} {'─'*5}   {'─'*3} {'─'*3} {'─'*3}   {'─'*40}")
        for e in plan.all_inputs:
            wc = e.get("wave_counts", {})
            print(f"  {e['type']:<14} {e['pipeline_count']:>5}   "
                  f"{wc.get(1,0):>3} {wc.get(2,0):>3} {wc.get(3,0):>3}   "
                  f"{e['label'][:60]}")
    else:
        print("  (no external inputs detected — all pipelines use pipeline routing)")
    print()

    # ── ALL OUTPUTS ───────────────────────────────────────
    print("─" * 90)
    print("ALL OUTPUTS  (distinct sinks across all pipelines)")
    print()
    if plan.all_outputs:
        print(f"  {'TYPE':<14} {'COUNT':>5}   {'W1':>3} {'W2':>3} {'W3':>3}   LABEL")
        print(f"  {'─'*14} {'─'*5}   {'─'*3} {'─'*3} {'─'*3}   {'─'*50}")
        for e in plan.all_outputs:
            wc = e.get("wave_counts", {})
            print(f"  {e['type']:<14} {e['pipeline_count']:>5}   "
                  f"{wc.get(1,0):>3} {wc.get(2,0):>3} {wc.get(3,0):>3}   "
                  f"{e['label'][:65]}")
    else:
        print("  (no terminal sinks detected)")
    print()

    # ── ALL FIELDS ────────────────────────────────────────
    print("─" * 90)
    print("ALL FIELDS  (union of field operations across all pipelines)")
    print()

    af = plan.all_fields

    def _print_field_section(title: str, entries: List[Dict[str, Any]],
                              key: str, max_rows: int = 30) -> None:
        if not entries:
            return
        print(f"  ┌─ {title} ({len(entries)} distinct) {'─'*max(0, 50-len(title))}")
        print(f"  │  {'FIELD':<40} {'PIPELINES':>9}   USED IN")
        for e in entries[:max_rows]:
            pcount = e["pipeline_count"]
            plist  = ", ".join(e["pipelines"][:3])
            if pcount > 3: plist += f"  … +{pcount-3} more"
            print(f"  │  {e[key]:<40} {pcount:>9}   {plist}")
        if len(entries) > max_rows:
            print(f"  │  … {len(entries)-max_rows} more not shown")
        print(f"  └{'─'*60}")
        print()

    def _print_renamed_section(entries: List[Dict[str, Any]], max_rows: int = 30) -> None:
        if not entries:
            return
        print(f"  ┌─ Renamed fields ({len(entries)} distinct rename operations) {'─'*14}")
        print(f"  │  {'FROM':<28} {'TO':<28} {'PIPELINES':>9}")
        for e in entries[:max_rows]:
            pcount = e["pipeline_count"]
            print(f"  │  {e['from']:<28} {e['to']:<28} {pcount:>9}")
        if len(entries) > max_rows:
            print(f"  │  … {len(entries)-max_rows} more not shown")
        print(f"  └{'─'*60}")
        print()

    def _print_timestamp_section(entries: List[Dict[str, Any]]) -> None:
        if not entries:
            return
        print(f"  ┌─ Timestamp parsing ({len(entries)} distinct source→target pairs) {'─'*8}")
        print(f"  │  {'SOURCE FIELD':<30} {'TARGET':<20} {'PIPELINES':>9}")
        for e in entries:
            pcount = e["pipeline_count"]
            print(f"  │  {e['source']:<30} {e['target']:<20} {pcount:>9}")
        print(f"  └{'─'*60}")
        print()

    _print_field_section("Fields created (set / add_field / copy)",
                         af.get("created", []), "field")
    _print_renamed_section(af.get("renamed", []))
    _print_field_section("Fields removed (remove_field)",
                         af.get("removed", []), "field")
    _print_field_section("Grok named captures",
                         af.get("grok_captures", []), "field")
    _print_field_section("Enrichment targets (geoip / useragent)",
                         af.get("enriched", []), "target")
    _print_timestamp_section(af.get("timestamp_fields", []))


def write_json(plan: MigrationPlan, path: str) -> None:
    """Write the full advisory plan to JSON."""
    def _ser(obj):
        if hasattr(obj, '__dataclass_fields__'):
            return asdict(obj)
        raise TypeError(f"Not serialisable: {type(obj)}")

    out = {
        "generated_at":    plan.generated_at,
        "scan_root":       plan.scan_root,
        "total_pipelines": plan.total_pipelines,
        "wave_counts":     plan.wave_counts,
        "summary":         plan.summary_text,
        "clusters": [
            {
                "cluster_id":    c.cluster_id,
                "fingerprint":   c.fingerprint,
                "pipeline_ids":  c.pipeline_ids,
                "representative": c.representative,
                "size":          c.size,
                "avg_benefit":   c.avg_benefit,
                "avg_fts":       c.avg_fts,
                "description":   c.description,
            }
            for c in plan.clusters
        ],
        "pipelines": [
            {
                "pipeline_id":        a.pipeline_id,
                "wave":               a.wave,
                "wave_reason":        a.wave_reason,
                "decision":           a.decision,
                "operational_benefit": a.operational_benefit,
                "benefit_breakdown":  a.benefit_breakdown,
                "migration_effort":   a.migration_effort,
                "effort_score":       a.effort_score,
                "is_pure_transformer": a.is_pure_transformer,
                "is_orchestrator":    a.is_orchestrator,
                "cluster_id":         a.cluster_id,
                "cluster_template":   a.cluster_template,
                "processor_fingerprint": a.processor_fingerprint,
                "blockers": [
                    {
                        "name":           b.name,
                        "severity":       b.severity,
                        "description":    b.description,
                        "recommendation": b.recommendation,
                    }
                    for b in a.blockers
                ],
                "field_inventory": {
                    "created":          a.field_inventory.created,
                    "renamed":          [{"from": s, "to": d} for s, d in a.field_inventory.renamed],
                    "removed":          a.field_inventory.removed,
                    "grok_targets":     a.field_inventory.grok_targets,
                    "enriched":         a.field_inventory.enriched,
                    "timestamp_source": a.field_inventory.timestamp_source,
                    "timestamp_target": a.field_inventory.timestamp_target,
                    "kv_target":        a.field_inventory.kv_target,
                },
                "external_deps": [
                    {"dep_type": d.dep_type, "path": d.path,
                     "plugin": d.plugin, "note": d.note}
                    for d in a.external_deps
                ],
                "metadata": {
                    "owner":       a.metadata.owner,
                    "team":        a.metadata.team,
                    "customer":    a.metadata.customer,
                    "environment": a.metadata.environment,
                    "criticality": a.metadata.criticality,
                    "volume":      a.metadata.volume,
                    "notes":       a.metadata.notes,
                },
                "architecture": a.architecture,
                "pattern": {
                    "primary":     a.pattern.primary     if a.pattern else None,
                    "tags":        a.pattern.tags         if a.pattern else [],
                    "portability": a.pattern.portability  if a.pattern else None,
                    "coupling":    a.pattern.coupling     if a.pattern else None,
                    "complexity":  a.pattern.complexity   if a.pattern else None,
                } if a.pattern else None,
                "anti_patterns": [
                    {
                        "id":             ap.anti_pattern_id,
                        "name":           ap.name,
                        "severity":       ap.severity,
                        "description":    ap.description,
                        "recommendation": ap.recommendation,
                    }
                    for ap in a.anti_patterns
                ],
            }
            for a in plan.pipelines
        ],
    }
    # ── Aggregate inventories ─────────────────────────────
    out["all_inputs"]          = plan.all_inputs
    out["all_outputs"]         = plan.all_outputs
    out["all_fields"]          = plan.all_fields
    out["pattern_summary"]     = plan.pattern_summary
    out["anti_pattern_summary"] = plan.anti_pattern_summary

    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(plan: MigrationPlan, path: str) -> None:
    """Write a flat CSV migration plan — one row per pipeline."""
    fieldnames = [
        "wave", "pipeline_id", "decision", "operational_benefit", "migration_effort",
        "effort_score", "is_pure_transformer", "is_orchestrator",
        "primary_pattern", "pattern_tags", "portability", "coupling", "complexity",
        "anti_pattern_count", "anti_pattern_ids", "anti_pattern_severities",
        "cluster_id", "cluster_template", "cluster_size",
        "hard_blockers", "workaround_blockers", "decision_blockers",
        "blocker_names", "wave_reason",
        "external_deps", "dep_count",
        "owner", "team", "customer", "environment", "criticality", "volume",
        "fields_created", "fields_renamed", "fields_removed",
        "grok_targets", "enriched_targets", "timestamp_source",
        "arch_current_input", "arch_current_filters", "arch_target_input",
        "arch_coverage_pct", "arch_manual_rewrites",
    ]
    cluster_size_map = {c.cluster_id: c.size for c in plan.clusters}

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for a in plan.pipelines:
            hard  = [b for b in a.blockers if b.severity == "hard"]
            work  = [b for b in a.blockers if b.severity == "workaround"]
            dec   = [b for b in a.blockers if b.severity == "decision"]
            inv   = a.field_inventory
            meta  = a.metadata
            arch  = a.architecture
            cur   = arch.get("current", {})
            tgt   = arch.get("target",  {})
            cid   = a.cluster_id or ""
            csz   = cluster_size_map.get(cid, 1)
            deps_str = " | ".join(f"{d.dep_type}:{d.path}" for d in a.external_deps[:6])
            writer.writerow({
                "wave":               a.wave,
                "pipeline_id":        a.pipeline_id,
                "decision":           a.decision,
                "operational_benefit": a.operational_benefit,
                "migration_effort":   a.migration_effort,
                "effort_score":       a.effort_score,
                "is_pure_transformer": a.is_pure_transformer,
                "is_orchestrator":    a.is_orchestrator,
                "primary_pattern":    a.pattern.primary     if a.pattern else "",
                "pattern_tags":       " | ".join(a.pattern.tags or []) if a.pattern else "",
                "portability":        a.pattern.portability  if a.pattern else "",
                "coupling":           a.pattern.coupling     if a.pattern else "",
                "complexity":         a.pattern.complexity   if a.pattern else "",
                "anti_pattern_count": len(a.anti_patterns),
                "anti_pattern_ids":   " | ".join(ap.anti_pattern_id for ap in a.anti_patterns),
                "anti_pattern_severities": " | ".join(ap.severity for ap in a.anti_patterns),
                "cluster_id":         cid,
                "cluster_template":   a.cluster_template,
                "cluster_size":       csz,
                "hard_blockers":      len(hard),
                "workaround_blockers": len(work),
                "decision_blockers":  len(dec),
                "blocker_names":      " | ".join(b.name for b in a.blockers),
                "wave_reason":        a.wave_reason,
                "external_deps":      deps_str,
                "dep_count":          len(a.external_deps),
                "owner":              meta.owner,
                "team":               meta.team,
                "customer":           meta.customer,
                "environment":        meta.environment,
                "criticality":        meta.criticality,
                "volume":             meta.volume,
                "fields_created":     " | ".join(inv.created[:10]),
                "fields_renamed":     " | ".join(f"{s}→{d}" for s,d in inv.renamed[:8]),
                "fields_removed":     " | ".join(inv.removed[:10]),
                "grok_targets":       " | ".join(inv.grok_targets[:10]),
                "enriched_targets":   " | ".join(inv.enriched[:5]),
                "timestamp_source":   inv.timestamp_source or "",
                "arch_current_input":   ", ".join(cur.get("inputs", [])),
                "arch_current_filters": ", ".join(cur.get("filters", [])),
                "arch_target_input":    ", ".join(tgt.get("inputs", [])),
                "arch_coverage_pct":    arch.get("coverage_pct", 0),
                "arch_manual_rewrites": " | ".join(tgt.get("manual_rewrites", [])),
            })

# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def write_inventory_csv(plan: MigrationPlan, base_path: str) -> None:
    """
    Write three separate CSV files for the aggregate inventories:
      <base>_inputs.csv
      <base>_outputs.csv
      <base>_fields.csv
    """
    stem = base_path[:-4] if base_path.lower().endswith(".csv") else base_path

    # ── inputs ────────────────────────────────────────────
    with open(f"{stem}_inputs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["type","label","pipeline_count",
                                            "wave1_count","wave2_count","wave3_count","pipelines"])
        w.writeheader()
        for e in plan.all_inputs:
            wc = e.get("wave_counts", {})
            w.writerow({"type": e["type"], "label": e["label"],
                        "pipeline_count": e["pipeline_count"],
                        "wave1_count": wc.get(1,0), "wave2_count": wc.get(2,0),
                        "wave3_count": wc.get(3,0),
                        "pipelines": " | ".join(e["pipelines"])})

    # ── outputs ───────────────────────────────────────────
    with open(f"{stem}_outputs.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["type","label","pipeline_count",
                                            "wave1_count","wave2_count","wave3_count","pipelines"])
        w.writeheader()
        for e in plan.all_outputs:
            wc = e.get("wave_counts", {})
            w.writerow({"type": e["type"], "label": e["label"],
                        "pipeline_count": e["pipeline_count"],
                        "wave1_count": wc.get(1,0), "wave2_count": wc.get(2,0),
                        "wave3_count": wc.get(3,0),
                        "pipelines": " | ".join(e["pipelines"])})

    # ── fields ────────────────────────────────────────────
    af = plan.all_fields
    with open(f"{stem}_fields.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["operation","field","from","to",
                                            "pipeline_count","pipelines"])
        w.writeheader()
        for e in af.get("created", []):
            w.writerow({"operation":"created","field":e["field"],"from":"","to":"",
                        "pipeline_count":e["pipeline_count"],
                        "pipelines":" | ".join(e["pipelines"])})
        for e in af.get("renamed", []):
            w.writerow({"operation":"renamed","field":f"{e['from']}→{e['to']}",
                        "from":e["from"],"to":e["to"],
                        "pipeline_count":e["pipeline_count"],
                        "pipelines":" | ".join(e["pipelines"])})
        for e in af.get("removed", []):
            w.writerow({"operation":"removed","field":e["field"],"from":"","to":"",
                        "pipeline_count":e["pipeline_count"],
                        "pipelines":" | ".join(e["pipelines"])})
        for e in af.get("grok_captures", []):
            w.writerow({"operation":"grok_capture","field":e["field"],"from":"","to":"",
                        "pipeline_count":e["pipeline_count"],
                        "pipelines":" | ".join(e["pipelines"])})
        for e in af.get("enriched", []):
            w.writerow({"operation":"enriched","field":e["target"],"from":"","to":"",
                        "pipeline_count":e["pipeline_count"],
                        "pipelines":" | ".join(e["pipelines"])})
        for e in af.get("timestamp_fields", []):
            w.writerow({"operation":"timestamp","field":f"{e['source']}→{e['target']}",
                        "from":e["source"],"to":e["target"],
                        "pipeline_count":e["pipeline_count"],
                        "pipelines":" | ".join(e["pipelines"])})

    print(f"  Inputs CSV:  {stem}_inputs.csv")
    print(f"  Outputs CSV: {stem}_outputs.csv")
    print(f"  Fields CSV:  {stem}_fields.csv")

    # ── pattern summary ────────────────────────────────────
    if plan.pattern_summary:
        with open(f"{stem}_patterns.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=[
                "pattern", "description", "pipeline_count", "pct_of_total",
                "dominant_complexity", "avg_portability", "avg_coupling",
                "avg_benefit", "avg_filter_coverage",
                "wave1_count", "wave2_count", "wave3_count",
                "top_plugins", "pipeline_ids",
            ])
            w.writeheader()
            for r in plan.pattern_summary:
                w.writerow({
                    "pattern":             r["pattern"],
                    "description":         r["description"],
                    "pipeline_count":      r["pipeline_count"],
                    "pct_of_total":        r["pct_of_total"],
                    "dominant_complexity": r["dominant_complexity"],
                    "avg_portability":     r["avg_portability"],
                    "avg_coupling":        r["avg_coupling"],
                    "avg_benefit":         r["avg_benefit"],
                    "avg_filter_coverage": r["avg_filter_coverage"],
                    "wave1_count":         r["wave1_count"],
                    "wave2_count":         r["wave2_count"],
                    "wave3_count":         r["wave3_count"],
                    "top_plugins":         " | ".join(r.get("top_plugins", [])),
                    "pipeline_ids":        " | ".join(r.get("pipeline_ids", [])),
                })
        print(f"  Patterns CSV: {stem}_patterns.csv")

    # ── anti-pattern summary ───────────────────────────────
    if plan.anti_pattern_summary:
        with open(f"{stem}_anti_patterns.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=[
                "anti_pattern_id", "name", "severity", "pipeline_count",
                "description", "recommendation", "pipeline_ids",
            ])
            w.writeheader()
            for r in plan.anti_pattern_summary:
                w.writerow({
                    "anti_pattern_id": r["anti_pattern_id"],
                    "name":            r["name"],
                    "severity":        r["severity"],
                    "pipeline_count":  r["pipeline_count"],
                    "description":     r["description"],
                    "recommendation":  r["recommendation"],
                    "pipeline_ids":    " | ".join(r.get("pipeline_ids", [])),
                })
        print(f"  Anti-patterns CSV: {stem}_anti_patterns.csv")


def main():
    ap = argparse.ArgumentParser(
        description="Logstash migration advisor — wave planner, clustering, benefit scoring, inventories")
    ap.add_argument("analysis_json",
                    help="JSON output from logstash_pipeline_analyzer_v12.py")
    ap.add_argument("--json-out",  help="Write full advisory plan to JSON file")
    ap.add_argument("--csv-out",   help="Write pipeline plan CSV; also writes _inputs/_outputs/_fields CSVs")
    ap.add_argument("--metadata",  help="Optional YAML/JSON sidecar with pipeline business metadata "
                                        "(owner, customer, criticality, etc.)")
    ap.add_argument("--wave", type=int, choices=[1,2,3],
                    help="Only show pipelines in this wave")
    ap.add_argument("--top-n", type=int, default=50,
                    help="Max pipelines shown per wave (default 50)")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable ANSI color output")
    args = ap.parse_args()

    data = json.loads(Path(args.analysis_json).read_text(encoding="utf-8"))
    plan = analyse(data, metadata_path=args.metadata)

    print_plan(plan, wave_filter=args.wave, top_n=args.top_n,
               use_color=not args.no_color)

    if args.json_out:
        write_json(plan, args.json_out)
        print(f"\nJSON written: {args.json_out}")

    if args.csv_out:
        write_csv(plan, args.csv_out)
        print(f"CSV  written: {args.csv_out}")
        print("Inventory CSVs:")
        write_inventory_csv(plan, args.csv_out)


if __name__ == "__main__":
    main()
