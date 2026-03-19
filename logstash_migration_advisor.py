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
    created:   List[str] = field(default_factory=list)   # set/add_field
    renamed:   List[Tuple[str, str]] = field(default_factory=list)  # (src, dst)
    removed:   List[str] = field(default_factory=list)
    enriched:  List[str] = field(default_factory=list)   # geoip/useragent targets
    timestamp_source: Optional[str] = None               # date processor source
    timestamp_target: str = "@timestamp"
    grok_targets: List[str] = field(default_factory=list) # named capture fields
    kv_target:    Optional[str] = None


@dataclass
class Blocker:
    name: str
    severity: str      # "hard" | "workaround" | "decision"
    description: str
    recommendation: str


@dataclass
class PipelineAdvice:
    pipeline_id:        str
    wave:               int            # 1, 2, or 3
    wave_reason:        str
    operational_benefit: int           # 0-100
    benefit_breakdown:  Dict[str, float]
    migration_effort:   str            # "Low" | "Medium" | "High"
    effort_score:       int            # 0-100 (higher = more effort)
    decision:           str            # "Migrate now" | "Partially migrate" | "Redesign first" | "Keep on Logstash"
    blockers:           List[Blocker]
    field_inventory:    FieldInventory
    cluster_id:         Optional[str]  # which pattern cluster this belongs to
    cluster_template:   bool           # is this the representative of its cluster?
    processor_fingerprint: str         # canonical processor sequence string
    is_pure_transformer: bool          # input→filter→ES only, no orchestration
    is_orchestrator:     bool          # JDBC/multi-output/stateful/routing-heavy


@dataclass
class PatternCluster:
    cluster_id:     str
    fingerprint:    str
    pipeline_ids:   List[str]
    representative: str          # the pipeline to use as migration template
    size:           int
    avg_benefit:    float
    avg_fts:        float
    description:    str          # human-readable cluster description


@dataclass
class MigrationPlan:
    generated_at:       str
    scan_root:          str
    total_pipelines:    int
    wave_counts:        Dict[int, int]
    clusters:           List[PatternCluster]
    pipelines:          List[PipelineAdvice]
    summary_text:       str
    # ── Cross-pipeline aggregate inventories (new) ──
    all_inputs:         List[Dict[str, Any]] = field(default_factory=list)
    # [{type, label, pipeline_count, pipelines}]
    all_outputs:        List[Dict[str, Any]] = field(default_factory=list)
    # [{type, label, pipeline_count, pipelines}]
    all_fields:         Dict[str, Any] = field(default_factory=dict)
    # {created, renamed, removed, grok_captures, enriched, timestamp_fields}

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
# 9. Main analysis pass
# ─────────────────────────────────────────────────────────────

def analyse(data: Dict[str, Any]) -> MigrationPlan:
    """Run the full advisor analysis over the analyzer JSON output."""
    rows    = data.get("logical_pipelines", [])
    edges   = data.get("logical_edges", {})
    summary = data.get("overall_summary", {})
    scan_root = summary.get("scan_root", "")

    all_ids = {r.get("pipeline", "") for r in rows}

    advices: List[PipelineAdvice] = []

    for row in rows:
        pid  = row.get("pipeline", "")
        fts  = int(row.get("filter_transform_score", 0) or 0)
        frs  = int(row.get("full_replacement_score",  0) or 0)
        tree = row.get("processors_ordered", {})

        # Field inventory
        inv = build_field_inventory(tree)

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

        # Fingerprint
        fp = build_fingerprint(row)

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
            cluster_id=None,       # filled in by cluster_pipelines
            cluster_template=False,
            processor_fingerprint=fp,
            is_pure_transformer=is_pure,
            is_orchestrator=is_orch,
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

    return MigrationPlan(
        generated_at=datetime.datetime.now().isoformat(timespec="seconds"),
        scan_root=scan_root,
        total_pipelines=len(advices),
        wave_counts=dict(wave_counts),
        clusters=clusters,
        pipelines=advices,
        summary_text=summary_text,
        all_inputs=all_inputs,
        all_outputs=all_outputs,
        all_fields=all_fields,
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
        print(f"{'PIPELINE':<36} {'Benefit':>7} {'Effort':<7} {'FTS':>4} {'Decision':<45}")
        print("─" * 90)
        for a in members:
            print(f"{wc}{col(a.pipeline_id,36)}{RESET} "
                  f"{a.operational_benefit:>7}  {a.migration_effort:<7}"
                  f"{col(a.wave_reason[:4] if False else str(int(a.pipeline_id and 0) or 0),0)}"  # placeholder
                  f"{col(a.decision, 45)}")

        # Detail for Wave 1 (most actionable)
        if wave_num == 1:
            print()
            print("  Suggested migration order (benefit-first within Wave 1):")
            for i, a in enumerate(members, 1):
                icon = "⭐" if a.is_pure_transformer else "→"
                tmpl = f" [cluster template: {a.cluster_id}]" if a.cluster_template else ""
                print(f"  {i:2d}. {icon} {a.pipeline_id}{tmpl}")
                print(f"       Benefit: {a.operational_benefit}/100  "
                      f"Effort: {a.migration_effort} ({a.effort_score})  "
                      f"Decision: {a.decision}")
                if a.blockers:
                    for b in a.blockers[:2]:
                        sev_icon = {"hard":"✗","workaround":"⚠","decision":"?"}[b.severity]
                        print(f"       {sev_icon} {b.name}: {b.recommendation[:65]}")
                print()

        elif wave_num == 2:
            print()
            for a in members[:8]:
                print(f"  • {a.pipeline_id}")
                print(f"    Decision: {a.decision}")
                print(f"    Reason:   {a.wave_reason[:80]}")
                if a.blockers:
                    for b in a.blockers[:3]:
                        sev_icon = {"hard":"✗","workaround":"⚠","decision":"?"}[b.severity]
                        print(f"    {sev_icon} {b.name}: {b.recommendation[:65]}")
                print()

        elif wave_num == 3:
            print()
            for a in members[:8]:
                print(f"  • {a.pipeline_id}")
                print(f"    Decision: {a.decision}")
                hard_names = [b.name for b in a.blockers if b.severity == "hard"]
                if hard_names:
                    print(f"    Hard blockers: {', '.join(hard_names)}")
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
            }
            for a in plan.pipelines
        ],
    }
    # ── Aggregate inventories ─────────────────────────────
    out["all_inputs"]  = plan.all_inputs
    out["all_outputs"] = plan.all_outputs
    out["all_fields"]  = plan.all_fields

    Path(path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")


def write_csv(plan: MigrationPlan, path: str) -> None:
    """Write a flat CSV migration plan — one row per pipeline."""
    fieldnames = [
        "wave", "pipeline_id", "decision", "operational_benefit", "migration_effort",
        "effort_score", "filter_transform_score", "full_replacement_score",
        "is_pure_transformer", "is_orchestrator",
        "cluster_id", "cluster_template", "cluster_size",
        "hard_blockers", "workaround_blockers", "decision_blockers",
        "blocker_names", "wave_reason",
        "fields_created", "fields_renamed", "fields_removed",
        "grok_targets", "enriched_targets", "timestamp_source",
    ]
    cluster_map = {a.pipeline_id: a.cluster_id for a in plan.pipelines}
    cluster_size_map = {c.cluster_id: c.size for c in plan.clusters}

    # We need the original fts/frs — store from pipeline_id lookup
    # (not stored on PipelineAdvice, so we just leave blank — the JSON has it)

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for a in plan.pipelines:
            hard   = [b for b in a.blockers if b.severity == "hard"]
            work   = [b for b in a.blockers if b.severity == "workaround"]
            dec    = [b for b in a.blockers if b.severity == "decision"]
            inv    = a.field_inventory
            cid    = a.cluster_id or ""
            csz    = cluster_size_map.get(cid, 1)
            writer.writerow({
                "wave":               a.wave,
                "pipeline_id":        a.pipeline_id,
                "decision":           a.decision,
                "operational_benefit": a.operational_benefit,
                "migration_effort":   a.migration_effort,
                "effort_score":       a.effort_score,
                "filter_transform_score": "",  # from source JSON
                "full_replacement_score":  "",
                "is_pure_transformer": a.is_pure_transformer,
                "is_orchestrator":    a.is_orchestrator,
                "cluster_id":         cid,
                "cluster_template":   a.cluster_template,
                "cluster_size":       csz,
                "hard_blockers":      len(hard),
                "workaround_blockers": len(work),
                "decision_blockers":  len(dec),
                "blocker_names":      " | ".join(b.name for b in a.blockers),
                "wave_reason":        a.wave_reason,
                "fields_created":     " | ".join(inv.created[:10]),
                "fields_renamed":     " | ".join(f"{s}→{d}" for s,d in inv.renamed[:8]),
                "fields_removed":     " | ".join(inv.removed[:10]),
                "grok_targets":       " | ".join(inv.grok_targets[:10]),
                "enriched_targets":   " | ".join(inv.enriched[:5]),
                "timestamp_source":   inv.timestamp_source or "",
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


def main():
    ap = argparse.ArgumentParser(
        description="Logstash migration advisor — wave planner, clustering, benefit scoring, inventories")
    ap.add_argument("analysis_json",
                    help="JSON output from logstash_pipeline_analyzer_v12.py")
    ap.add_argument("--json-out",  help="Write full advisory plan to JSON file")
    ap.add_argument("--csv-out",   help="Write pipeline plan CSV; also writes _inputs/_outputs/_fields CSVs")
    ap.add_argument("--wave", type=int, choices=[1,2,3],
                    help="Only show pipelines in this wave")
    ap.add_argument("--top-n", type=int, default=50,
                    help="Max pipelines shown per wave (default 50)")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable ANSI color output")
    args = ap.parse_args()

    data = json.loads(Path(args.analysis_json).read_text(encoding="utf-8"))
    plan = analyse(data)

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
