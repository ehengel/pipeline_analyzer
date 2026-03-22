#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logstash_pipeline_visualizer_v4.py
═══════════════════════════════════════════════════════════════════════════
Stage 4 — Kibana-style processor-level pipeline visualizer (v4).

New in v4
─────────
- Four advisor tabs in the detail panel (Pipeline, Blockers, Architecture, Patterns/APs)
- Load advisory plan via --plan migration_plan.json to activate advisor tabs
- Pipeline tab: wave, decision, pattern classification, portability/coupling scores
- Blockers tab: migration blockers, anti-patterns, external dependencies per pipeline
- Architecture tab: current→target arch, field inventory, business metadata
- Patterns/APs tab: cross-pipeline pattern summary + anti-pattern summary,
  with current pipeline highlighted (▶) in both tables

New in v3
─────────
•  Filter radio buttons removed — all processors always shown, colour-coded.
   The colour on each node already communicates support status at a glance.

•  "Show Ingest JSON" replaces "Export Ingest JSON".
   Opens a side-by-side comparison window:
     Left pane  : Raw Logstash config  (input { } / filter { } / output { })
     Right pane : Generated ES ingest pipeline JSON
   An "Export to file" button sits inside that window.
   Also works per-processor: clicking a node shows its Logstash snippet on
   the left and the equivalent ES processor JSON on the right.

•  Grok complexity scoring — the detail panel for any grok processor now
   shows a performance impact score:
     pattern_count        × 3   (each match pattern)
     alternation_count    × 1   (| in patterns — backtracking risk)
     named_capture_count  × 1   (each %{...} or (?<...>))
     pattern_chars        / 50  (raw character length)
     heavy_grok flag      + 5   (pattern > 200 chars)
     backtrack_risk flag  + 5   (unbounded .* or .+ detected)
   Score → band:  ≤5 = Fast, 6-14 = Moderate, 15-29 = Slow, ≥30 = Very Slow

•  Toolbar simplified — View / Direction / Reset / Show Ingest JSON only.
═══════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import argparse
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────
# Layout constants  — horizontal mode
# ─────────────────────────────────────────────────────────────
H_PROC_W      = 180   # processor node width
H_PROC_H      = 64    # processor node height (compact)
H_PROC_H_FULL = 110   # processor node height (detailed)
H_GAP         = 28    # gap between nodes along the main axis
V_GAP         = 20    # gap along the cross axis / between branches
BRANCH_INDENT = 24    # indent per conditional depth (horizontal mode only)
IO_W          = 150   # input/output node width  (horizontal)
IO_H          = 80    # input/output node height (horizontal)

# ─────────────────────────────────────────────────────────────
# Layout constants  — vertical mode
# ─────────────────────────────────────────────────────────────
V_PROC_W      = 220   # wider node so label fits in the column
V_PROC_H      = 72    # compact height in vertical mode
V_PROC_H_FULL = 116   # detailed height in vertical mode
V_MAIN_GAP    = 24    # gap between nodes along the vertical axis
V_BRANCH_GAP  = 20    # horizontal gap between side-by-side branches
V_IO_W        = 220   # IO node width  (vertical — matches proc width)
V_IO_H        = 64    # IO node height (vertical)

CANVAS_PAD    = 40    # canvas padding (both modes)

# ─────────────────────────────────────────────────────────────
# Color scheme
# ─────────────────────────────────────────────────────────────
STATUS_COLORS = {
    "supported":   {"fill": "#c8f5c8", "outline": "#2ca25f", "text": "#003300"},
    "partial":     {"fill": "#fff5b0", "outline": "#b08800", "text": "#4a3200"},
    "unsupported": {"fill": "#ffd6d6", "outline": "#cb181d", "text": "#5a0000"},
    "unknown":     {"fill": "#f0f0f0", "outline": "#888888", "text": "#333333"},
}
IO_COLORS = {
    "input":       {"fill": "#dff3ff", "outline": "#2c7fb8", "text": "#003050"},
    "output":      {"fill": "#e7f7df", "outline": "#2ca25f", "text": "#004000"},
    "unresolved":  {"fill": "#ffe4e1", "outline": "#cb181d", "text": "#5a0000"},
}
COND_COLORS = {
    "fill":    "#fafafa",
    "outline": "#999999",
    "text":    "#555555",
    "header":  "#eeeeee",
}
STATUS_ICONS = {"supported": "✅", "partial": "⚠️", "unsupported": "❌", "unknown": "?"}

# ─────────────────────────────────────────────────────────────
# Short descriptions for processor nodes
# ─────────────────────────────────────────────────────────────
PROC_DESCRIPTIONS: Dict[str, str] = {
    "grok":        "Extract fields from text",
    "dissect":     "Fast field extraction",
    "date":        "Parse @timestamp",
    "mutate":      "Rename / set / remove fields",
    "json":        "Parse JSON field",
    "geoip":       "Add geo enrichment",
    "useragent":   "Parse user-agent string",
    "kv":          "Key-value field splitting",
    "fingerprint": "Generate event fingerprint",
    "urldecode":   "Decode URL-encoded field",
    "drop":        "Drop the event",
    "csv":         "Parse CSV fields",
    "de_dot":      "Expand dotted field names",
    "translate":   "Dictionary field lookup",
    "ruby":        "Custom Ruby code",
    "aggregate":   "Stateful event aggregation",
    "elapsed":     "Measure event time elapsed",
    "clone":       "Clone event",
    "metrics":     "Compute metrics",
    "xml":         "Parse XML field",
    "dns":         "DNS reverse lookup",
    "jdbc_streaming": "JDBC database lookup",
    "elasticsearch": "Elasticsearch lookup",
    "cidr":        "CIDR network matching",
    "split":       "Split field into multiple events",
}

def proc_short_desc(plugin: str) -> str:
    return PROC_DESCRIPTIONS.get(plugin, plugin)

# ─────────────────────────────────────────────────────────────
# Grok performance / complexity scoring
# ─────────────────────────────────────────────────────────────
import re as _re

GROK_PERF_BANDS = [
    (5,  "Fast",      "#c8f5c8", "#2ca25f"),   # green
    (14, "Moderate",  "#fff5b0", "#b08800"),   # amber
    (29, "Slow",      "#ffd6d6", "#cb181d"),   # red
]
GROK_PERF_WORST = ("Very Slow", "#ffd6d6", "#8b0000")

_BACKTRACK_RE = _re.compile(r'\.\*|\.\+')

def score_grok_performance(metrics: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute a performance impact score for a grok processor block from
    the metrics dict produced by the analyzer.

    Returns:
      score       : int  (higher = more expensive at runtime)
      band        : str  ("Fast" | "Moderate" | "Slow" | "Very Slow")
      fill_color  : str  (hex bg colour matching migration palette)
      text_color  : str  (hex text colour)
      reasons     : List[str]  (bullet-point explanations)
    """
    score   = 0
    reasons = []

    pc = int(metrics.get("pattern_count", 0) or 0)
    ac = int(metrics.get("alternation_count", 0) or 0)
    nc = int(metrics.get("named_capture_count", 0) or 0)
    chars = int(metrics.get("pattern_chars", 0) or 0)
    heavy = bool(metrics.get("heavy", False))

    # Pattern count: each pattern = a full regex compile + match attempt
    if pc > 0:
        score += pc * 3
        reasons.append(f"{pc} match pattern(s) × 3 = {pc*3}")

    # Alternation: | forces backtracking branches
    if ac > 0:
        score += ac
        reasons.append(f"{ac} alternation(s) (|) = {ac}  ← backtracking risk")

    # Named captures: each %{...} expands to a named group
    if nc > 0:
        score += nc
        reasons.append(f"{nc} named capture(s) (%{{...}} / (?<...>)) = {nc}")

    # Raw pattern length
    len_score = chars // 50
    if len_score > 0:
        score += len_score
        reasons.append(f"{chars} total pattern chars ÷ 50 = {len_score}")

    # Heavy grok flag from analyzer
    if heavy:
        score += 5
        reasons.append("+5  pattern > 200 chars (heavy flag)")

    # Detect unbounded .* / .+ in raw patterns (analyzer stores them)
    raw_patterns = metrics.get("raw_patterns", [])
    if not raw_patterns and chars > 0:
        # raw_patterns not stored — infer from metrics
        raw_patterns = []
    backtrack_found = any(_BACKTRACK_RE.search(p) for p in raw_patterns if p)
    if backtrack_found:
        score += 5
        reasons.append("+5  unbounded .* or .+ detected (catastrophic backtrack risk)")

    # Determine band
    fill, text = GROK_PERF_WORST[1], GROK_PERF_WORST[2]
    band = GROK_PERF_WORST[0]
    for threshold, b_name, b_fill, b_text in GROK_PERF_BANDS:
        if score <= threshold:
            band, fill, text = b_name, b_fill, b_text
            break

    return {
        "score":      score,
        "band":       band,
        "fill_color": fill,
        "text_color": text,
        "reasons":    reasons,
    }

# ─────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────

def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def get_pipelines(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return data.get("logical_pipelines", [])

def get_pipeline(data: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    for p in get_pipelines(data):
        if p.get("pipeline") == name: return p
    return None

def short(s: str, n: int = 24) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n-1] + "…"

# ─────────────────────────────────────────────────────────────
# Canvas node model
# ─────────────────────────────────────────────────────────────

class CanvasNode:
    """A positioned, clickable node on the canvas."""
    def __init__(self, x: int, y: int, w: int, h: int, label: str,
                 color: Dict[str, str], payload: Dict[str, Any],
                 node_kind: str = "processor"):
        self.x, self.y, self.w, self.h = x, y, w, h
        self.label = label
        self.color = color
        self.payload = payload
        self.kind = node_kind   # "processor" | "input" | "output" | "cond_header"
        self.canvas_items: List[int] = []   # tkinter canvas item IDs

    @property
    def cx(self) -> float: return self.x + self.w / 2
    @property
    def cy(self) -> float: return self.y + self.h / 2
    @property
    def right(self) -> int: return self.x + self.w
    @property
    def bottom(self) -> int: return self.y + self.h

# ─────────────────────────────────────────────────────────────
# Layout engine
# ─────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────
# Layout engine  — supports "horizontal" and "vertical" modes
# ─────────────────────────────────────────────────────────────

class LayoutEngine:
    """
    Dual-mode layout engine.

    Horizontal (direction="horizontal")
    ────────────────────────────────────
    Processors flow left → right.
    Conditional branches stack vertically (one branch per row),
    indented slightly from the left edge of the conditional block.
    Inputs on the left, outputs on the right.

    Vertical (direction="vertical")
    ────────────────────────────────
    Processors flow top → bottom (Kibana style).
    Conditional branches spread left → right in a row at the same Y
    level, each branch's body continuing downward.
    Inputs at the top, outputs at the bottom.

    In both modes _layout_node() returns (nodes, width, height) where
    width/height describe the bounding box consumed by that sub-tree.
    """

    def __init__(self, detailed: bool = False, direction: str = "horizontal"):
        self.detailed   = detailed
        self.direction  = direction   # "horizontal" | "vertical"
        self._vertical  = direction == "vertical"

        if self._vertical:
            self._pw = V_PROC_W
            self._ph = V_PROC_H_FULL if detailed else V_PROC_H
        else:
            self._pw = H_PROC_W
            self._ph = H_PROC_H_FULL if detailed else H_PROC_H

    # ── public entry ─────────────────────────────────────────

    def layout_tree(self, tree_dict: Dict[str, Any], x0: int, y0: int
                    ) -> Tuple[List[CanvasNode], int, int]:
        nodes, w, h = self._layout_node(tree_dict, x0, y0, depth=0)
        return nodes, w, h

    # ── dispatcher ───────────────────────────────────────────

    def _layout_node(self, node: Dict[str, Any], x: int, y: int, depth: int
                     ) -> Tuple[List[CanvasNode], int, int]:
        nt = node.get("node_type", "")
        if nt == "sequence":
            return (self._layout_sequence_v if self._vertical
                    else self._layout_sequence_h)(node, x, y, depth)
        if nt == "processor":
            return self._layout_processor(node, x, y, depth)
        if nt == "conditional":
            return (self._layout_conditional_v if self._vertical
                    else self._layout_conditional_h)(node, x, y, depth)
        return [], 0, 0

    # ── processor node (shared) ───────────────────────────────

    def _layout_processor(self, node: Dict[str, Any], x: int, y: int, depth: int
                           ) -> Tuple[List[CanvasNode], int, int]:
        plugin = node.get("plugin", "?")
        status = node.get("ingest_status", "unknown")
        icon   = STATUS_ICONS.get(status, "?")
        color  = STATUS_COLORS.get(status, STATUS_COLORS["unknown"])

        # Grok performance band — embedded in label so it's visible on the canvas
        grok_perf: Optional[Dict[str, Any]] = None
        if plugin == "grok":
            metrics = node.get("metrics", {})
            if metrics:
                grok_perf = score_grok_performance(metrics)

        if self.detailed:
            label = (f"{icon} {plugin.upper()}\n"
                     f"{short(proc_short_desc(plugin), 22)}\n"
                     f"{short(node.get('ingest_note',''), 26)}")
        else:
            label = f"{icon} {plugin.upper()}\n{short(proc_short_desc(plugin), 22)}"

        # Append perf band on a third line for grok nodes
        if grok_perf:
            label += f"\nPerf: {grok_perf['band']} ({grok_perf['score']})"

        payload = {**node, "node_label": plugin.upper()}
        if grok_perf:
            payload["_grok_perf"] = grok_perf   # used by _draw_node for footer stripe

        cn = CanvasNode(x, y, self._pw, self._ph, label, color,
                        payload=payload, node_kind="processor")
        return [cn], self._pw, self._ph

    # ── HORIZONTAL sequences ──────────────────────────────────

    def _layout_sequence_h(self, node: Dict[str, Any], x: int, y: int, depth: int
                            ) -> Tuple[List[CanvasNode], int, int]:
        """Children placed left-to-right; height = max child height."""
        all_nodes: List[CanvasNode] = []
        cx = x; max_h = 0
        for child in node.get("children", []):
            cnodes, cw, ch = self._layout_node(child, cx, y, depth)
            all_nodes.extend(cnodes)
            cx += cw + H_GAP
            max_h = max(max_h, ch)
        total_w = max(0, cx - x - H_GAP)
        return all_nodes, total_w, max_h

    def _layout_conditional_h(self, node: Dict[str, Any], x: int, y: int, depth: int
                               ) -> Tuple[List[CanvasNode], int, int]:
        """
        Horizontal mode: branches stack vertically.
        Each branch = [label row] + [body nodes running right].
        """
        branches = node.get("branches", [])
        if not branches:
            return [], 0, 0

        all_nodes: List[CanvasNode] = []
        INDENT    = BRANCH_INDENT
        LBL_H     = 22
        cur_y     = y + LBL_H   # room for an implied "conditional" header
        max_bw    = 0

        for branch in branches:
            btype    = branch.get("branch_type", "if")
            cond_str = branch.get("condition", "")
            body     = branch.get("body", {})

            lbl_txt  = (f"{'if' if btype == 'if' else btype} {{ … }}"
                        if btype != "else" else "else")
            lbl_color = {"fill": COND_COLORS["header"],
                         "outline": COND_COLORS["outline"],
                         "text": COND_COLORS["text"]}
            lbl_node  = CanvasNode(
                x + INDENT, cur_y, self._pw + 40, LBL_H - 4,
                lbl_txt, lbl_color,
                payload={"node_type": "branch_label",
                         "condition": cond_str, "branch_type": btype},
                node_kind="cond_header")
            all_nodes.append(lbl_node)
            cur_y += LBL_H

            body_nodes, bw, bh = self._layout_node(
                body, x + INDENT * 2, cur_y, depth + 1)
            all_nodes.extend(body_nodes)
            max_bw  = max(max_bw, bw + INDENT * 2)
            cur_y  += bh + V_GAP

        total_h = cur_y - y
        total_w = max(max_bw, self._pw)
        return all_nodes, total_w, total_h

    # ── VERTICAL sequences ────────────────────────────────────

    def _layout_sequence_v(self, node: Dict[str, Any], x: int, y: int, depth: int
                            ) -> Tuple[List[CanvasNode], int, int]:
        """Children placed top-to-bottom; width = max child width."""
        all_nodes: List[CanvasNode] = []
        cy = y; max_w = 0
        for child in node.get("children", []):
            cnodes, cw, ch = self._layout_node(child, x, cy, depth)
            all_nodes.extend(cnodes)
            cy    += ch + V_MAIN_GAP
            max_w  = max(max_w, cw)
        total_h = max(0, cy - y - V_MAIN_GAP)
        return all_nodes, max_w, total_h

    def _layout_conditional_v(self, node: Dict[str, Any], x: int, y: int, depth: int
                               ) -> Tuple[List[CanvasNode], int, int]:
        """
        Vertical mode: branches spread left-to-right in a row.
        Each branch = [label box at the top] + [body nodes stacked below].
        All branches start at the same Y; the total height = tallest branch.
        """
        branches = node.get("branches", [])
        if not branches:
            return [], 0, 0

        all_nodes: List[CanvasNode] = []
        LBL_H    = 28
        LBL_W    = self._pw
        body_y   = y + LBL_H + V_MAIN_GAP   # bodies all start here

        cur_x    = x
        max_bh   = 0
        col_widths: List[int] = []

        # First pass: compute each branch body width/height
        branch_layouts: List[Tuple[List[CanvasNode], int, int]] = []
        for branch in branches:
            body = branch.get("body", {})
            bnodes, bw, bh = self._layout_node(body, 0, 0, depth + 1)
            branch_layouts.append((bnodes, bw, bh))
            max_bh = max(max_bh, bh)
            col_widths.append(max(bw, LBL_W))

        # Second pass: position each branch
        for i, branch in enumerate(branches):
            btype    = branch.get("branch_type", "if")
            cond_str = branch.get("condition", "")
            bnodes, bw, bh = branch_layouts[i]
            col_w = col_widths[i]

            lbl_txt   = (f"{'if' if btype == 'if' else btype} {{ … }}"
                         if btype != "else" else "else")
            lbl_color  = {"fill": COND_COLORS["header"],
                          "outline": COND_COLORS["outline"],
                          "text": COND_COLORS["text"]}
            lbl_node   = CanvasNode(
                cur_x, y, LBL_W, LBL_H,
                lbl_txt, lbl_color,
                payload={"node_type": "branch_label",
                         "condition": cond_str, "branch_type": btype},
                node_kind="cond_header")
            all_nodes.append(lbl_node)

            # Re-position body nodes to actual column x
            dx = cur_x - 0   # offset from dummy 0 used above
            for n in bnodes:
                n.x += dx; n.y += body_y
                all_nodes.append(n)

            cur_x += col_w + V_BRANCH_GAP

        total_w = max(0, cur_x - x - V_BRANCH_GAP)
        total_h = LBL_H + V_MAIN_GAP + max_bh
        return all_nodes, total_w, total_h

# ─────────────────────────────────────────────────────────────
# ProcessorDetailPanel  (v4)
# ─────────────────────────────────────────────────────────────

class ProcessorDetailPanel(ttk.Frame):
    """
    Seven-tab detail panel.

      Tab 1  Info           — plugin name, ingest support, grok perf, dissect analysis
      Tab 2  Logstash       — raw Logstash config text
      Tab 3  Ingest JSON    — equivalent ES ingest processor JSON
      ── advisor tabs (populated when a plan JSON is loaded) ──
      Tab 4  Pipeline       — wave, decision, pattern, scores for the current pipeline
      Tab 5  Blockers       — structured blocker list with recommendations
      Tab 6  Architecture   — current → target architecture block + field inventory
      Tab 7  Anti-Patterns  — anti-pattern flags for this pipeline +
                              cross-pipeline pattern summary table
    """

    def __init__(self, parent):
        super().__init__(parent)
        self._plan_by_id: Dict[str, Dict[str, Any]] = {}
        self._plan_summary: List[Dict[str, Any]] = []
        self._plan_anti_summary: List[Dict[str, Any]] = []
        self._plan: Dict[str, Any] = {}
        self._current_pipeline_id: Optional[str] = None

        ttk.Label(self, text="Processor Details", font=("Segoe UI", 9, "bold")).pack(
            anchor="w", padx=8, pady=(6, 2))

        self._nb = ttk.Notebook(self)
        self._nb.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Tab 1: Info ─────────────────────────────────
        info_frame = ttk.Frame(self._nb)
        self._nb.add(info_frame, text="Info")
        self.info_text = tk.Text(info_frame, wrap="word", font=("Segoe UI", 9), height=14)
        isb = ttk.Scrollbar(info_frame, orient="vertical", command=self.info_text.yview)
        self.info_text.configure(yscrollcommand=isb.set)
        self.info_text.pack(side="left", fill="both", expand=True)
        isb.pack(side="right", fill="y")
        self.info_text.configure(state="disabled")

        # colour tags
        for tag, fg, bold in [
            ("supported",   "#2ca25f", True),
            ("partial",     "#b08800", True),
            ("unsupported", "#cb181d", True),
            ("heading",     "#000000", True),
            ("grok_fast",       "#2ca25f", True),
            ("grok_mod",        "#b08800", True),
            ("grok_slow",       "#cb181d", True),
            ("grok_vslow",      "#8b0000", True),
            ("dissect_high",    "#2ca25f", True),
            ("dissect_medium",  "#b08800", True),
            ("dissect_no",      "#cb181d", True),
            ("dim",             "#666666", False),
        ]:
            kw: Dict[str, Any] = {"foreground": fg}
            if bold: kw["font"] = ("Segoe UI", 9, "bold")
            self.info_text.tag_configure(tag, **kw)

        # ── Tab 2: Logstash raw config ───────────────────
        raw_frame = ttk.Frame(self._nb)
        self._nb.add(raw_frame, text="Logstash")
        self.raw_text = tk.Text(raw_frame, wrap="none", font=("Consolas", 9))
        rsb  = ttk.Scrollbar(raw_frame, orient="vertical",   command=self.raw_text.yview)
        rhsb = ttk.Scrollbar(raw_frame, orient="horizontal", command=self.raw_text.xview)
        self.raw_text.configure(yscrollcommand=rsb.set, xscrollcommand=rhsb.set)
        self.raw_text.grid(row=0, column=0, sticky="nsew")
        rsb.grid(row=0, column=1, sticky="ns")
        rhsb.grid(row=1, column=0, sticky="ew")
        raw_frame.rowconfigure(0, weight=1); raw_frame.columnconfigure(0, weight=1)
        self.raw_text.configure(state="disabled")

        # ── Tab 3: Ingest JSON (per-processor) ──────────
        ingest_frame = ttk.Frame(self._nb)
        self._nb.add(ingest_frame, text="Ingest JSON")
        ingest_frame.rowconfigure(1, weight=1); ingest_frame.columnconfigure(0, weight=1)

        hdr = ttk.Frame(ingest_frame)
        hdr.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 2))
        ttk.Label(hdr, text="Generated ES ingest processor equivalent",
                  font=("Segoe UI", 8), foreground="#555").pack(side="left")
        ttk.Button(hdr, text="Copy", command=self._copy_ingest).pack(side="right")

        self.ingest_text = tk.Text(ingest_frame, wrap="none", font=("Consolas", 9))
        iesb  = ttk.Scrollbar(ingest_frame, orient="vertical",   command=self.ingest_text.yview)
        iehsb = ttk.Scrollbar(ingest_frame, orient="horizontal", command=self.ingest_text.xview)
        self.ingest_text.configure(yscrollcommand=iesb.set, xscrollcommand=iehsb.set)
        self.ingest_text.grid(row=1, column=0, sticky="nsew")
        iesb.grid(row=1, column=1, sticky="ns")
        iehsb.grid(row=2, column=0, sticky="ew")
        self.ingest_text.configure(state="disabled")

        self.ingest_text.tag_configure("key",     foreground="#0000aa")
        self.ingest_text.tag_configure("str_val", foreground="#007700")
        self.ingest_text.tag_configure("comment", foreground="#888888", font=("Consolas", 9, "italic"))
        self.ingest_text.tag_configure("warn",    foreground="#bb6600", font=("Consolas", 9, "bold"))

        # ── Tabs 4-7: Advisor tabs ───────────────────────
        # These are always created; they show a "no plan loaded" message
        # until set_plan() is called from PipelineVisualizer.

        self._adv_pipeline_text = self._make_advisor_tab("Pipeline")
        self._adv_blockers_text = self._make_advisor_tab("Blockers")
        self._adv_arch_text     = self._make_advisor_tab("Architecture")
        self._adv_patterns_text = self._make_advisor_tab("Patterns / APs")

        # Seed the advisor tabs with a placeholder message
        self._adv_no_plan_message()

    def _copy_ingest(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self.ingest_text.get("1.0", tk.END))
        except Exception:
            pass

    def _make_advisor_tab(self, label: str) -> tk.Text:
        """Create one advisor tab with a header label. Returns the Text widget."""
        frame = ttk.Frame(self._nb)
        self._nb.add(frame, text=label)
        frame.rowconfigure(1, weight=1); frame.columnconfigure(0, weight=1)

        # Thin header showing scope
        hdr = ttk.Frame(frame)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew", padx=2, pady=(2, 0))
        ttk.Label(hdr, text=f"{label} — selected pipeline",
                  font=("Segoe UI", 8), foreground="#888").pack(side="left", padx=4)

        # Scrollable text body
        t = tk.Text(frame, wrap="word", font=("Segoe UI", 9),
                    relief="flat", background="#fafafa")
        sb = ttk.Scrollbar(frame, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.grid(row=1, column=0, sticky="nsew")
        sb.grid(row=1, column=1, sticky="ns")

        for tag, fg, bold in [
            ("h1",    "#1a1a2e", True),  ("h2",    "#333333", True),
            ("good",  "#2ca25f", True),  ("warn",  "#b08800", True),
            ("bad",   "#cb181d", True),  ("dim",   "#888888", False),
            ("label", "#555555", False), ("mono",  "#222222", False),
            ("wave1", "#2ca25f", True),  ("wave2", "#b08800", True),
            ("wave3", "#cb181d", True),  ("info",  "#333333", False),
            ("sev_high",   "#cb181d", True), ("sev_medium", "#b08800", True),
            ("sev_low",    "#555555", False),("sev_info",   "#888888", False),
        ]:
            kw2: Dict[str, Any] = {"foreground": fg}
            if bold: kw2["font"] = ("Segoe UI", 9, "bold")
            if tag == "mono": kw2["font"] = ("Consolas", 9)
            t.tag_configure(tag, **kw2)
        t.configure(state="disabled")
        return t

    def _adv_no_plan_message(self):
        """Fill advisor tabs with placeholder when no plan is loaded."""
        msg = ("No advisor plan loaded.\n\n"
               "Run the advisor to generate a plan:\n"
               "  python logstash_migration_advisor.py analysis.json \\\n"
               "      --json-out migration_plan.json\n\n"
               "Then launch the visualiser with:\n"
               "  python logstash_pipeline_visualizer_v4.py analysis.json \\\n"
               "      --plan migration_plan.json")
        for t in (self._adv_pipeline_text, self._adv_blockers_text,
                  self._adv_arch_text, self._adv_patterns_text):
            t.configure(state="normal")
            t.delete("1.0", tk.END)
            t.insert(tk.END, msg, "dim")
            t.configure(state="disabled")

    # ── Plan injection (called once from PipelineVisualizer) ────

    def set_plan(self, plan: Dict[str, Any]):
        """
        Load the full advisor plan into the detail panel.
        Called once after construction when --plan is provided.
        Stores pipeline lookup, pattern summary, and anti-pattern summary.
        """
        self._plan           = plan
        self._plan_by_id      = {p["pipeline_id"]: p for p in plan.get("pipelines", [])}
        self._plan_summary    = plan.get("pattern_summary", [])
        self._plan_anti_summary = plan.get("anti_pattern_summary", [])
        # Populate the Patterns/APs tab with cross-pipeline summaries immediately
        self._populate_patterns_tab()

    # ── Public API ────────────────────────────────────────────────

    def show(self, payload: Dict[str, Any]):
        """Called when a processor node is clicked on the canvas."""
        node_type = payload.get("node_type", "")
        self._populate_info(payload, node_type)
        self._populate_raw(payload, node_type)
        self._populate_ingest_json(payload, node_type)
        self._nb.select(0)

    def show_pipeline(self, pipeline_id: str):
        """
        Called when a new pipeline is loaded.
        Updates the four advisor tabs for that pipeline.
        """
        self._current_pipeline_id = pipeline_id
        p = self._plan_by_id.get(pipeline_id)
        self._populate_pipeline_tab(p, pipeline_id)
        self._populate_blockers_tab(p)
        self._populate_arch_tab(p)
        self._populate_patterns_tab(highlight_pid=pipeline_id)

    # ── Advisor tab populators ─────────────────────────────────────

    def _adv_write(self, t: tk.Text, parts: List[Tuple[str, str]]):
        """Helper: write (text, tag) pairs to an advisor Text widget."""
        t.configure(state="normal"); t.delete("1.0", tk.END)
        for text, tag in parts:
            t.insert(tk.END, text, tag if tag else "")
        t.configure(state="disabled")

    def _populate_pipeline_tab(self, p: Optional[Dict[str, Any]], pid: str):
        t = self._adv_pipeline_text
        if p is None:
            self._adv_write(t, [(f"No advisor data for: {pid}\n", "dim")])
            return
        wave     = p.get("wave", "?")
        wave_tag = f"wave{wave}" if wave in (1, 2, 3) else "info"
        pat      = p.get("pattern") or {}
        parts: List[Tuple[str, str]] = []

        parts += [(f"{pid}\n", "h1"),
                  (f"Wave {wave}  —  {p.get('decision','')}\n", wave_tag),
                  (f"{p.get('wave_reason','')}\n\n", "dim")]

        if pat:
            parts += [("── Pattern ──\n", "h2"),
                      ("  Primary:     ", "label"),
                      (f"{pat.get('primary','?')}\n", "good"),
                      (f"  Complexity:  {pat.get('complexity','?')}\n", "info")]
            port = pat.get("portability", 0)
            coup = pat.get("coupling", 0)
            parts += [("  Portability: ", "label"),
                      (f"{port}/100\n",
                       "good" if port >= 75 else "warn" if port >= 40 else "bad"),
                      ("  Coupling:    ", "label"),
                      (f"{coup}/100\n",
                       "bad" if coup >= 60 else "warn" if coup >= 25 else "good")]
            tags = pat.get("tags", [])
            if tags:
                parts += [("  Tags:  ", "label"), (f"{', '.join(tags)}\n", "dim")]
            parts += [("\n", "")]

        parts += [("── Scores ──\n", "h2"),
                  (f"  Operational benefit:  {p.get('operational_benefit','?')}/100\n", "info"),
                  (f"  Migration effort:     {p.get('migration_effort','?')}"
                   f" (score {p.get('effort_score','?')})\n", "info")]
        for k, v in (p.get("benefit_breakdown") or {}).items():
            parts += [(f"    {k:<20} {v}\n", "dim")]
        self._adv_write(t, parts)

    def _populate_blockers_tab(self, p: Optional[Dict[str, Any]]):
        t = self._adv_blockers_text
        if p is None:
            self._adv_write(t, [("Select a pipeline to see blocker detail.\n", "dim")])
            return
        blockers = p.get("blockers") or []
        aps      = p.get("anti_patterns") or []
        ext_deps = p.get("external_deps") or []
        parts: List[Tuple[str, str]] = []

        if blockers:
            parts += [("── Migration Blockers ──\n", "h2")]
            for b in blockers:
                sev  = b.get("severity", "")
                icon = {"hard":"✗","workaround":"⚠","decision":"?"}.get(sev,"·")
                clr  = {"hard":"bad","workaround":"warn","decision":"info"}.get(sev,"info")
                parts += [(f"\n{icon} [{sev.upper()}]  {b.get('name','')}\n", clr),
                          (f"  {b.get('description','')[:100]}\n", "dim"),
                          (f"  → {b.get('recommendation','')[:100]}\n", "info")]
        else:
            parts += [("── Migration Blockers ──\n", "h2"),
                      ("  No blockers detected.\n\n", "good")]

        if aps:
            parts += [("\n── Anti-patterns on this pipeline ──\n", "h2")]
            sev_tag = {"high":"sev_high","medium":"sev_medium",
                       "low":"sev_low","info":"sev_info"}
            for ap in aps:
                sev  = ap.get("severity","info")
                icon = {"high":"✗","medium":"⚠","low":"·","info":"ℹ"}.get(sev,"·")
                parts += [(f"\n{icon} {ap.get('name','')}\n", sev_tag.get(sev,"dim")),
                          (f"  {ap.get('description','')[:100]}\n", "dim"),
                          (f"  → {ap.get('recommendation','')[:100]}\n", "info")]

        if ext_deps:
            parts += [("\n── External Dependencies ──\n", "h2")]
            for d in ext_deps:
                parts += [(f"  📎 [{d.get('dep_type','')}]  ", "warn"),
                          (f"{d.get('path','')}\n", "mono"),
                          (f"     → {d.get('note','')[:90]}\n", "dim")]

        if not parts:
            parts = [("No blockers, anti-patterns, or external dependencies.\n", "good")]
        self._adv_write(t, parts)

    def _populate_arch_tab(self, p: Optional[Dict[str, Any]]):
        t = self._adv_arch_text
        if p is None:
            self._adv_write(t, [("Select a pipeline to see architecture detail.\n", "dim")])
            return
        arch = p.get("architecture") or {}
        inv  = p.get("field_inventory") or {}
        meta = p.get("metadata") or {}
        cur  = arch.get("current", {})
        tgt  = arch.get("target",  {})
        cov  = arch.get("coverage_pct", 0)
        parts: List[Tuple[str, str]] = []

        parts += [("── Current Architecture ──\n", "h2"),
                  ("  Input:    ", "label"), (f"{', '.join(cur.get('inputs',[]))}\n", "mono"),
                  ("  Filters:  ", "label"), (f"{', '.join(cur.get('filters',[]))}\n", "mono"),
                  ("  Output:   ", "label"), (f"{', '.join(cur.get('outputs',[]))}\n", "mono")]
        for note in cur.get("notes", []):
            parts += [(f"  ⚠ {note}\n", "warn")]

        parts += [(f"\n── Target Architecture  (filter coverage: {cov}%) ──\n", "h2"),
                  ("  Input:    ", "label"),
                  (f"{', '.join(tgt.get('inputs', []))}\n", "mono")]
        for line in tgt.get("ingest_pipeline", []):
            parts += [(f"  {line}\n", "good")]
        for line in tgt.get("manual_rewrites", []):
            parts += [(f"  ✎ {line}\n", "warn")]
        parts += [("  Output:   ", "label"), (f"{', '.join(tgt.get('outputs',[]))}\n", "mono")]
        for g in arch.get("gap", [])[:8]:
            parts += [(f"  ✗ {g[:90]}\n", "bad")]

        if any(inv.get(k) for k in ("created","renamed","removed","grok_targets","enriched")):
            parts += [("\n── Field Inventory ──\n", "h2")]
            for key, label in [("created","Created"), ("removed","Removed"),
                                ("grok_targets","Grok→"), ("enriched","Enriched")]:
                if inv.get(key):
                    parts += [(f"  {label:<12} ", "label"),
                              (", ".join(inv[key][:8]) + "\n", "mono")]
            if inv.get("renamed"):
                pairs = [f"{r['from']}→{r['to']}" for r in inv["renamed"][:6]]
                parts += [("  Renamed      ", "label"), (", ".join(pairs) + "\n", "mono")]
            if inv.get("timestamp_source"):
                parts += [("  Timestamp    ", "label"),
                          (f"{inv['timestamp_source']} → "
                           f"{inv.get('timestamp_target','@timestamp')}\n", "mono")]

        if any(meta.get(k) for k in ("owner","customer","criticality","volume","notes")):
            parts += [("\n── Business Metadata ──\n", "h2")]
            for k in ("owner","team","customer","environment","criticality","volume","notes"):
                if meta.get(k):
                    parts += [(f"  {k.capitalize():<14} ", "label"), (f"{meta[k]}\n", "info")]
        self._adv_write(t, parts)

    def _populate_patterns_tab(self, highlight_pid: Optional[str] = None):
        """Pattern summary + anti-pattern summary; highlights current pipeline's pattern."""
        t = self._adv_patterns_text
        if not self._plan_summary and not self._plan_anti_summary:
            self._adv_write(t, [("No plan loaded.\n", "dim")])
            return

        highlight_pat: Optional[str] = None
        if highlight_pid and highlight_pid in self._plan_by_id:
            pp = self._plan_by_id[highlight_pid].get("pattern") or {}
            highlight_pat = pp.get("primary")

        cur_ap_ids: set = set()
        if highlight_pid and highlight_pid in self._plan_by_id:
            for ap in (self._plan_by_id[highlight_pid].get("anti_patterns") or []):
                cur_ap_ids.add(ap.get("anti_pattern_id",""))

        parts: List[Tuple[str, str]] = []

        # ── Pattern summary table ─────────────────────────────
        parts += [("── Pattern Summary  "
                   "(Port=Portability  Coup=Coupling  W1/W2/W3=wave count) ──\n", "h2"),
                  (f"  {'Pattern':<24} {'#':>3}  {'Port':>4} {'Coup':>4}"
                   f"  {'W1':>3} {'W2':>3} {'W3':>3}  {'Filt%':>5}\n", "label"),
                  ("  " + "─"*58 + "\n", "dim")]

        for r in self._plan_summary:
            pat_name = r.get("pattern","")
            is_cur   = pat_name == highlight_pat
            port     = r.get("avg_portability", 0)
            row_tag  = "good" if port >= 75 else ("warn" if port >= 40 else "bad")
            marker   = "▶ " if is_cur else "  "
            if is_cur: row_tag = "h1"
            parts += [(f"{marker}{pat_name:<24} {r.get('pipeline_count',0):>3}"
                       f"  {port:>4} {r.get('avg_coupling',0):>4}"
                       f"  {r.get('wave1_count',0):>3} {r.get('wave2_count',0):>3}"
                       f" {r.get('wave3_count',0):>3}  {r.get('avg_filter_coverage',0):>4}%"
                       f"  {r.get('description','')[:30]}\n", row_tag)]

        # ── Anti-pattern summary ──────────────────────────────
        if self._plan_anti_summary:
            parts += [("\n── Anti-patterns  (all pipelines) ──\n", "h2")]
            sev_icons = {"high":"✗","medium":"⚠","low":"·","info":"ℹ"}
            sev_tags  = {"high":"sev_high","medium":"sev_medium",
                         "low":"sev_low","info":"sev_info"}
            for r in self._plan_anti_summary:
                apid   = r.get("anti_pattern_id","")
                sev    = r.get("severity","info")
                icon   = sev_icons.get(sev,"·")
                is_cur = apid in cur_ap_ids
                marker = "▶ " if is_cur else "  "
                row_tag = "h1" if is_cur else sev_tags.get(sev,"dim")
                parts += [(f"{marker}{icon} {r.get('name',''):<38}"
                            f" {r.get('pipeline_count',0):>3} pipeline(s)\n", row_tag),
                           (f"    → {r.get('recommendation','')[:80]}\n", "dim")]

        self._adv_write(t, parts)

    # ── Info tab ──────────────────────────────────────────────

    def _populate_info(self, payload: Dict[str, Any], node_type: str):
        t = self.info_text
        t.configure(state="normal"); t.delete("1.0", tk.END)

        if node_type == "processor":
            plugin  = payload.get("plugin", "?")
            status  = payload.get("ingest_status", "unknown")
            note    = payload.get("ingest_note", "")
            iproc   = payload.get("ingest_processor")
            config  = payload.get("config", {})
            metrics = payload.get("metrics", {})
            cpath   = payload.get("condition_path", [])
            seq     = payload.get("seq_index", 0)
            icon    = STATUS_ICONS.get(status, "?")

            t.insert(tk.END, f"{icon} {plugin.upper()}\n", "heading")
            t.insert(tk.END, f"Execution order: #{seq}\n")
            if cpath:
                t.insert(tk.END, f"Inside: {' → '.join(cpath)}\n")

            t.insert(tk.END, "\nIngest support: ", "heading")
            t.insert(tk.END, f"{status.upper()}\n", status)
            if iproc:
                t.insert(tk.END, f"ES processor: {iproc}\n")
            t.insert(tk.END, f"{note}\n", "dim")

            # ── Grok performance section ──────────────────
            if plugin == "grok" and metrics:
                perf = score_grok_performance(metrics)
                band = perf["band"]
                score = perf["score"]
                band_tag = {"Fast": "grok_fast", "Moderate": "grok_mod",
                            "Slow": "grok_slow", "Very Slow": "grok_vslow"}.get(band, "dim")

                t.insert(tk.END, "\n── Grok Performance ──\n", "heading")
                t.insert(tk.END, f"Impact score: {score}  →  ", "dim")
                t.insert(tk.END, f"{band}\n", band_tag)

                # Score breakdown
                for reason in perf["reasons"]:
                    t.insert(tk.END, f"  • {reason}\n", "dim")

                # Practical advice per band
                advice = {
                    "Fast":      "✓ Low overhead — fine for high-volume pipelines.",
                    "Moderate":  "⚠ Acceptable, but test under load on large events.",
                    "Slow":      "⚠ Consider dissect or pre-filtering to reduce workload.",
                    "Very Slow": "✗ High backtracking risk. Profile and optimise patterns.",
                }
                t.insert(tk.END, f"\n{advice.get(band,'')}\n", "dim")

            # ── Dissect replacement analysis ──────────────
            if plugin == "grok":
                da = payload.get("dissect_analysis")
                if da:
                    t.insert(tk.END, "\n── Dissect Replacement ──\n", "heading")
                    convertible = da.get("overall_convertible", False)
                    confidence  = da.get("overall_confidence", "not_convertible")
                    summary     = da.get("summary", "")

                    conf_tag = {
                        "high":           "dissect_high",
                        "medium":         "dissect_medium",
                        "not_convertible":"dissect_no",
                    }.get(confidence, "dim")

                    t.insert(tk.END, f"{summary}\n", conf_tag)

                    # Per-pattern breakdown when there are multiple match patterns
                    per = da.get("per_pattern", [])
                    if len(per) > 1:
                        t.insert(tk.END, "\nPer-pattern detail:\n", "dim")
                        for pp in per:
                            icon_p = "✓" if pp.get("convertible") else "✗"
                            src    = pp.get("source_field", "?")
                            gpat   = pp.get("grok_pattern", "")
                            dpat   = pp.get("dissect_pattern", "")
                            reason = pp.get("reason", "")
                            t.insert(tk.END, f"  {icon_p} [{src}]\n", "dim")
                            t.insert(tk.END, f"    grok:    {short(gpat, 60)}\n", "dim")
                            if dpat:
                                t.insert(tk.END, f"    dissect: {short(dpat, 60)}\n",
                                         "dissect_high" if pp.get("confidence") == "high"
                                         else "dissect_medium")
                            elif reason:
                                t.insert(tk.END, f"    reason:  {short(reason, 60)}\n", "dissect_no")
                    elif len(per) == 1 and convertible:
                        # Single pattern — show the dissect equivalent prominently
                        dp = per[0].get("dissect_pattern", "")
                        src = per[0].get("source_field", "message")
                        if dp:
                            t.insert(tk.END, "\nEquivalent dissect processor:\n", "dim")
                            t.insert(tk.END,
                                f'  dissect {{\n'
                                f'    field   => "{src}"\n'
                                f'    mapping => {{ "{src}" => "{dp}" }}\n'
                                f'  }}\n', "dim")

                    # Caveats — deduplicated, most important first
                    caveats = da.get("all_caveats", [])
                    if caveats:
                        t.insert(tk.END, "\nCaveats:\n", "heading")
                        for caveat in caveats[:4]:
                            t.insert(tk.END, f"  ⚠ {short(caveat, 80)}\n", "dim")

                    # Validation patterns lost
                    lost = da.get("all_validation_lost", [])
                    if lost and convertible:
                        t.insert(tk.END,
                            f"\nFormat validation removed: {', '.join(lost)}\n"
                            "Grok rejects malformed input (via tag_on_failure);\n"
                            "dissect silently extracts whatever is present.\n",
                            "dissect_medium")

            # ── Config summary ────────────────────────────
            if config:
                t.insert(tk.END, "\n── Configuration ──\n", "heading")
                for k, v in list(config.items())[:12]:
                    vstr = str(v)
                    if len(vstr) > 90: vstr = vstr[:87] + "…"
                    t.insert(tk.END, f"  {k}: ")
                    t.insert(tk.END, f"{vstr}\n", "dim")

            # ── Metrics summary ───────────────────────────
            interesting = {k: v for k, v in metrics.items()
                           if v and v != 0 and v is not False and v is not None
                           and k != "raw_patterns"}
            if interesting:
                t.insert(tk.END, "\n── Metrics ──\n", "heading")
                for k, v in interesting.items():
                    t.insert(tk.END, f"  {k}: ", "dim")
                    t.insert(tk.END, f"{v}\n")

        elif node_type == "branch_label":
            btype = payload.get("branch_type", "if")
            cond  = payload.get("condition", "")
            t.insert(tk.END, f"Conditional: {btype.upper()}\n", "heading")
            t.insert(tk.END, "\nCondition expression:\n")
            t.insert(tk.END, f"  {cond or '(see source file)'}\n", "dim")
            t.insert(tk.END,
                "\n⚠  Logstash condition expressions must be\n"
                "manually translated to Painless 'if' clauses\n"
                "in the ES ingest pipeline.\n", "partial")
        else:
            t.insert(tk.END, str(payload))

        t.configure(state="disabled")

    # ── Logstash tab ──────────────────────────────────────────

    def _populate_raw(self, payload: Dict[str, Any], node_type: str):
        t = self.raw_text
        t.configure(state="normal"); t.delete("1.0", tk.END)
        raw = payload.get("raw_config", "")
        t.insert(tk.END, raw if raw else "(raw config not stored for this node)")
        t.configure(state="disabled")

    # ── Ingest JSON tab ───────────────────────────────────────

    def _populate_ingest_json(self, payload: Dict[str, Any], node_type: str):
        t = self.ingest_text
        t.configure(state="normal"); t.delete("1.0", tk.END)

        if node_type != "processor":
            t.insert(tk.END, "(Select a processor node to see its ingest JSON equivalent)")
            t.configure(state="disabled")
            return

        try:
            from logstash_ingest_transformer import dispatch_processor
            result = dispatch_processor(payload, parent_condition=None)
            if result.processors:
                ingest_str = json.dumps(result.processors, indent=2, ensure_ascii=False)
            else:
                ingest_str = "// No ingest processor generated"

            if result.warnings:
                for w in result.warnings:
                    t.insert(tk.END, f"// ⚠  {w}\n", "warn")
                t.insert(tk.END, "\n")

            # Insert with simple syntax highlighting
            _insert_json_highlighted(t, ingest_str)

        except ImportError:
            t.insert(tk.END,
                "// logstash_ingest_transformer.py not found.\n"
                "// Place it in the same directory as this script.\n", "comment")
        except Exception as e:
            t.insert(tk.END, f"// Error generating ingest JSON:\n// {e}\n", "warn")

        t.configure(state="disabled")


def _insert_json_highlighted(widget: tk.Text, json_str: str):
    """Very lightweight JSON syntax highlighting for the ingest JSON tab."""
    for line in json_str.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith("//"):
            widget.insert(tk.END, line, "comment")
        elif stripped.startswith('"') and ":" in stripped:
            # Key: value line
            colon = line.index(":")
            widget.insert(tk.END, line[:colon+1], "key")
            rest = line[colon+1:]
            widget.insert(tk.END, rest, "str_val" if '"' in rest else "")
        else:
            widget.insert(tk.END, line)

# ─────────────────────────────────────────────────────────────
# PipelineFlowCanvas
# ─────────────────────────────────────────────────────────────

class PipelineFlowCanvas(ttk.Frame):
    """
    The main flow canvas for one pipeline.
    Renders: Inputs → processor chain (with branches) → Outputs
    """
    def __init__(self, parent, detail_panel: ProcessorDetailPanel):
        super().__init__(parent)
        self.detail_panel = detail_panel
        self._nodes: List[CanvasNode] = []
        self._edges: List[Tuple[float,float,float,float]] = []
        self._detailed_mode = tk.BooleanVar(value=False)
        self._direction_var = tk.StringVar(value="horizontal")   # "horizontal" | "vertical"
        self._scale = 1.0
        self._drag_start: Optional[Tuple[int,int]] = None
        self._tooltip: Optional[tk.Toplevel] = None

        # Toolbar
        tb = ttk.Frame(self)
        tb.pack(fill="x", padx=4, pady=2)
        ttk.Label(tb, text="View:").pack(side="left")
        ttk.Radiobutton(tb, text="Compact",  variable=self._detailed_mode, value=False, command=self._redraw).pack(side="left", padx=2)
        ttk.Radiobutton(tb, text="Detailed", variable=self._detailed_mode, value=True,  command=self._redraw).pack(side="left")
        ttk.Separator(tb, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Label(tb, text="Direction:").pack(side="left")
        ttk.Radiobutton(tb, text="⟶ Horizontal", variable=self._direction_var, value="horizontal", command=self._redraw).pack(side="left", padx=2)
        ttk.Radiobutton(tb, text="⟱ Vertical",   variable=self._direction_var, value="vertical",   command=self._redraw).pack(side="left")
        ttk.Separator(tb, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(tb, text="⌂ Reset", command=self._reset_view).pack(side="left", padx=2)
        ttk.Button(tb, text="Show Ingest JSON", command=self._show_ingest_json).pack(side="right", padx=4)

        # Canvas
        cf = ttk.Frame(self)
        cf.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(cf, bg="white", cursor="crosshair")
        hbar = ttk.Scrollbar(cf, orient="horizontal", command=self.canvas.xview)
        vbar = ttk.Scrollbar(cf, orient="vertical",   command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        cf.rowconfigure(0, weight=1); cf.columnconfigure(0, weight=1)
        self.canvas.bind("<MouseWheel>", self._on_wheel)
        self.canvas.bind("<Button-4>",   lambda e: self._zoom(1.1, e))
        self.canvas.bind("<Button-5>",   lambda e: self._zoom(0.9, e))
        self.canvas.bind("<ButtonPress-2>",  self._pan_start)
        self.canvas.bind("<B2-Motion>",      self._pan_move)
        self.canvas.bind("<ButtonPress-3>",  self._pan_start)
        self.canvas.bind("<B3-Motion>",      self._pan_move)

        self._pipeline_row: Optional[Dict[str, Any]] = None

    def load_pipeline(self, row: Dict[str, Any]):
        self._pipeline_row = row
        pid = row.get("pipeline", "")
        # Update advisor tabs in the detail panel whenever a pipeline loads
        if pid:
            try:
                self.detail_panel.show_pipeline(pid)
            except Exception:
                pass
        self._redraw()

    def _redraw(self):
        if self._pipeline_row is None: return
        self.canvas.delete("all")
        self._nodes = []
        self._edges = []
        self._scale = 1.0

        row           = self._pipeline_row
        tree          = row.get("processors_ordered", {})
        inputs        = row.get("input_sources", []) or ["INPUT"]
        outputs       = row.get("terminal_sinks", []) or ["OUTPUT"]
        direction     = self._direction_var.get()
        vertical      = direction == "vertical"

        engine = LayoutEngine(detailed=self._detailed_mode.get(), direction=direction)

        if vertical:
            self._redraw_vertical(engine, tree, inputs, outputs)
        else:
            self._redraw_horizontal(engine, tree, inputs, outputs)

    # ── horizontal layout ─────────────────────────────────────

    def _redraw_horizontal(self, engine: LayoutEngine, tree, inputs, outputs):
        input_nodes: List[CanvasNode] = []
        for i, src in enumerate(inputs):
            lbl = src.replace("SOURCE:", "").replace("SINK:", "")
            cn  = CanvasNode(CANVAS_PAD, CANVAS_PAD + i*(IO_H+V_GAP),
                             IO_W, IO_H,
                             f"▶ Input\n{short(lbl,18)}", IO_COLORS["input"],
                             {"node_type": "input", "label": src}, "input")
            input_nodes.append(cn)

        tree_x = CANVAS_PAD + IO_W + H_GAP * 2
        tree_nodes, tree_w, tree_h = engine.layout_tree(tree, tree_x, CANVAS_PAD)

        output_x = tree_x + tree_w + H_GAP * 2
        output_nodes: List[CanvasNode] = []
        for i, sink in enumerate(outputs):
            lbl  = sink.replace("SINK:", "").replace("SOURCE:", "")
            kind = "unresolved" if "UNRESOLVED" in sink else "output"
            cn   = CanvasNode(output_x, CANVAS_PAD + i*(IO_H+V_GAP),
                              IO_W, IO_H,
                              f"◀ Output\n{short(lbl,18)}", IO_COLORS[kind],
                              {"node_type": "output", "label": sink}, "output")
            output_nodes.append(cn)

        self._finalise(input_nodes, tree_nodes, output_nodes, vertical=False)

    # ── vertical layout ───────────────────────────────────────

    def _redraw_vertical(self, engine: LayoutEngine, tree, inputs, outputs):
        # Inputs — horizontally centred as a row at the top
        iw, ih = V_IO_W, V_IO_H

        input_nodes: List[CanvasNode] = []
        for i, src in enumerate(inputs):
            lbl = src.replace("SOURCE:", "").replace("SINK:", "")
            cn  = CanvasNode(CANVAS_PAD + i*(iw+H_GAP), CANVAS_PAD,
                             iw, ih,
                             f"▼ Input\n{short(lbl,26)}", IO_COLORS["input"],
                             {"node_type": "input", "label": src}, "input")
            input_nodes.append(cn)

        tree_y = CANVAS_PAD + ih + V_MAIN_GAP * 2
        tree_nodes, tree_w, tree_h = engine.layout_tree(tree, CANVAS_PAD, tree_y)

        output_y = tree_y + tree_h + V_MAIN_GAP * 2
        output_nodes: List[CanvasNode] = []
        for i, sink in enumerate(outputs):
            lbl  = sink.replace("SINK:", "").replace("SOURCE:", "")
            kind = "unresolved" if "UNRESOLVED" in sink else "output"
            cn   = CanvasNode(CANVAS_PAD + i*(iw+H_GAP), output_y,
                              iw, ih,
                              f"▲ Output\n{short(lbl,26)}", IO_COLORS[kind],
                              {"node_type": "output", "label": sink}, "output")
            output_nodes.append(cn)

        self._finalise(input_nodes, tree_nodes, output_nodes, vertical=True)

    # ── shared finalisation ───────────────────────────────────

    def _finalise(self, input_nodes, tree_nodes, output_nodes, vertical: bool):
        all_nodes = input_nodes + tree_nodes + output_nodes

        all_x = [n.x for n in all_nodes] + [n.right  for n in all_nodes]
        all_y = [n.y for n in all_nodes] + [n.bottom for n in all_nodes]
        total_w = max(all_x, default=800) + CANVAS_PAD
        total_h = max(all_y, default=600) + CANVAS_PAD
        self.canvas.configure(scrollregion=(0, 0, total_w, total_h))

        proc_nodes = [n for n in tree_nodes if n.kind == "processor"]
        first_proc = proc_nodes[0] if proc_nodes else None
        last_proc  = proc_nodes[-1] if proc_nodes else None

        if vertical:
            # Input → first processor (or outputs): connect bottom-centre → top-centre
            for inp in input_nodes:
                if first_proc:
                    self._draw_arrow(inp.cx, inp.bottom, first_proc.cx, first_proc.y, vertical=True)
                else:
                    for out in output_nodes:
                        self._draw_arrow(inp.cx, inp.bottom, out.cx, out.y, vertical=True)

            # Consecutive processors: bottom → top
            for i in range(len(proc_nodes)-1):
                a, b = proc_nodes[i], proc_nodes[i+1]
                if a.bottom <= b.y:
                    self._draw_arrow(a.cx, a.bottom, b.cx, b.y, vertical=True)

            # Last processor → outputs
            if last_proc:
                for out in output_nodes:
                    self._draw_arrow(last_proc.cx, last_proc.bottom, out.cx, out.y, vertical=True)

        else:
            # Input → first processor: right → left
            for inp in input_nodes:
                if first_proc:
                    self._draw_arrow(inp.right, inp.cy, first_proc.x, first_proc.cy, vertical=False)
                else:
                    for out in output_nodes:
                        self._draw_arrow(inp.right, inp.cy, out.x, out.cy, vertical=False)

            # Consecutive processors: right → left (same row only)
            for i in range(len(proc_nodes)-1):
                a, b = proc_nodes[i], proc_nodes[i+1]
                if a.right <= b.x:
                    self._draw_arrow(a.right, a.cy, b.x, b.cy, vertical=False)

            # Last processor → outputs
            if last_proc:
                for out in output_nodes:
                    self._draw_arrow(last_proc.right, last_proc.cy, out.x, out.cy, vertical=False)

        for node in all_nodes:
            self._draw_node(node)

        self._nodes = all_nodes

    def _draw_node(self, node: CanvasNode):
        c = self.canvas
        x, y, w, h = node.x, node.y, node.w, node.h
        r = 6  # corner radius

        # Rounded rectangle via polygon
        pts = [x+r,y, x+w-r,y, x+w,y+r, x+w,y+h-r, x+w-r,y+h, x+r,y+h, x,y+h-r, x,y+r]
        rect = c.create_polygon(pts, smooth=True,
                                 fill=node.color["fill"],
                                 outline=node.color["outline"], width=2)

        # Grok performance footer stripe — a thin coloured bar at the bottom of the node
        grok_perf = node.payload.get("_grok_perf") if node.kind == "processor" else None
        if grok_perf:
            stripe_h = 10
            stripe_y = y + h - stripe_h
            fill_col = grok_perf["fill_color"]
            txt_col  = grok_perf["text_color"]
            band     = grok_perf["band"]
            # Draw stripe rectangle clipped to the rounded bottom corners
            spts = [x+r, stripe_y,
                    x+w-r, stripe_y,
                    x+w, stripe_y+r,
                    x+w, stripe_y+stripe_h-r,
                    x+w-r, stripe_y+stripe_h,
                    x+r, stripe_y+stripe_h,
                    x, stripe_y+stripe_h-r,
                    x, stripe_y+r]
            stripe = c.create_polygon(spts, smooth=True, fill=fill_col, outline=fill_col)
            # Band label inside stripe
            stxt = c.create_text(x + w//2, stripe_y + stripe_h//2,
                                  text=band, font=("Segoe UI", 7, "bold"),
                                  fill=txt_col, anchor="center")
            node.canvas_items = [rect, stripe, stxt]
        else:
            node.canvas_items = [rect]

        # Main label text (vertically centred in the non-stripe area)
        label_cy = y + (node.h - (10 if grok_perf else 0)) // 2
        txt = c.create_text(x + w//2, label_cy,
                             text=node.label, font=("Segoe UI", 9),
                             fill=node.color["text"], width=w - 10, justify="center")
        node.canvas_items.append(txt)

        # Click + hover bindings on all items
        for item in node.canvas_items:
            c.tag_bind(item, "<Button-1>", lambda e, n=node: self._on_node_click(n))
            c.tag_bind(item, "<Enter>",    lambda e, n=node: self._on_enter(e, n))
            c.tag_bind(item, "<Leave>",    lambda e: self._hide_tooltip())

    def _draw_arrow(self, x1, y1, x2, y2, vertical: bool = False):
        """
        Draw a connector arrow.

        Horizontal mode:
          • Same row (|y1-y2| < 4) → straight horizontal line.
          • Different rows (branches) → horizontal elbow: right, then down/up, then right.

        Vertical mode:
          • Same column (|x1-x2| < 4) → straight vertical line.
          • Different columns (branches) → vertical elbow: down, then left/right, then down.
        """
        if vertical:
            if abs(x1 - x2) < 6:
                self.canvas.create_line(x1, y1, x2, y2,
                                        arrow=tk.LAST, width=2, fill="#666666")
            else:
                my = (y1 + y2) / 2
                self.canvas.create_line(x1, y1, x1, my, x2, my, x2, y2,
                                        arrow=tk.LAST, width=2, fill="#999999", smooth=True)
        else:
            if abs(y1 - y2) < 6:
                self.canvas.create_line(x1, y1, x2, y2,
                                        arrow=tk.LAST, width=2, fill="#666666")
            else:
                mx = (x1 + x2) / 2
                self.canvas.create_line(x1, y1, mx, y1, mx, y2, x2, y2,
                                        arrow=tk.LAST, width=2, fill="#999999", smooth=True)

    def _on_node_click(self, node: CanvasNode):
        self.detail_panel.show(node.payload)

    def _on_enter(self, event, node: CanvasNode):
        if node.kind == "processor":
            grok_perf = node.payload.get("_grok_perf")
            if grok_perf:
                band  = grok_perf["band"]
                score = grok_perf["score"]
                reasons_short = "  |  ".join(grok_perf["reasons"][:2])
                tip = f"Grok performance: {band} (score {score})\n{reasons_short}"
            else:
                tip = node.payload.get("ingest_note", "")
            if tip: self._show_tooltip(event, tip)
        elif node.kind == "cond_header":
            btype = node.payload.get("branch_type", "if")
            cond  = node.payload.get("condition", "")
            if btype == "else":
                tip = "else  (no condition — default branch)"
            elif cond:
                tip = f"{btype}  {cond}"
            else:
                tip = f"{btype}  (condition expression not captured — re-run analyzer v12)"
            self._show_tooltip(event, tip)

    def _show_tooltip(self, event, text: str):
        self._hide_tooltip()
        win = tk.Toplevel(self)
        win.wm_overrideredirect(True)
        win.wm_geometry(f"+{event.x_root+14}+{event.y_root+14}")
        tk.Label(win, text=text, justify="left", relief="solid", borderwidth=1,
                 bg="#fffff0", font=("Segoe UI",9), wraplength=340, padx=6, pady=4).pack()
        self._tooltip = win

    def _hide_tooltip(self):
        if self._tooltip:
            self._tooltip.destroy()
            self._tooltip = None

    def _on_wheel(self, event):
        self._zoom(1.1 if event.delta > 0 else 0.9, event)

    def _zoom(self, factor: float, event=None):
        self._scale = max(0.2, min(4.0, self._scale * factor))
        cx = event.x if event else 400
        cy = event.y if event else 300
        self.canvas.scale("all", cx, cy, factor, factor)
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _pan_start(self, event): self._drag_start = (event.x, event.y)

    def _pan_move(self, event):
        if self._drag_start:
            dx = event.x - self._drag_start[0]
            dy = event.y - self._drag_start[1]
            self.canvas.move("all", dx, dy)
            self._drag_start = (event.x, event.y)
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _reset_view(self):
        self._scale = 1.0; self._redraw()

    def _show_ingest_json(self):
        if self._pipeline_row is None: return
        IngestCompareWindow(self, self._pipeline_row)

# ─────────────────────────────────────────────────────────────
# IngestCompareWindow  — side-by-side Logstash ↔ Ingest JSON
# ─────────────────────────────────────────────────────────────

class IngestCompareWindow(tk.Toplevel):
    """
    Full-pipeline side-by-side comparison window.

    Left pane  : Logstash source (input / filter / output blocks)
    Right pane : Generated ES ingest pipeline JSON

    A tab strip at the top lets the user switch between:
      • Full pipeline  — entire filter block vs entire ingest pipeline
      • Per-processor  — choose a single processor from a dropdown
    """

    def __init__(self, master, row: Dict[str, Any]):
        super().__init__(master)
        self.row = row
        pid = row.get("pipeline", "pipeline")
        self.title(f"Ingest Compare — {pid}")
        self.geometry("1400x860")

        # Build ingest pipeline once
        self._pipeline_json: Optional[Dict[str, Any]] = None
        self._warnings: List[str] = []
        self._coverage: float = 0.0
        self._ingest_error: str = ""
        self._proc_nodes: List[Dict[str, Any]] = []  # flat list of ProcessorNode dicts

        try:
            from logstash_ingest_transformer import build_ingest_pipeline
            self._pipeline_json, self._warnings, self._coverage = build_ingest_pipeline(row)
        except ImportError:
            self._ingest_error = ("logstash_ingest_transformer.py not found.\n"
                                  "Place it in the same directory as this script.")
        except Exception as e:
            self._ingest_error = str(e)

        # Flatten processor tree for per-processor dropdown
        tree = row.get("processors_ordered", {})
        self._proc_nodes = _flatten_processors(tree)

        # ── Header bar ───────────────────────────────────
        hdr = ttk.Frame(self)
        hdr.pack(fill="x", padx=8, pady=4)

        mc   = row.get("migration_class", "")
        fts  = row.get("filter_transform_score", row.get("migration_score", 0))
        frs  = row.get("full_replacement_score", fts)
        cov  = f"{self._coverage*100:.0f}%" if self._pipeline_json else "n/a"
        warn = f"  ·  {len(self._warnings)} warning(s)" if self._warnings else ""
        summary = (f"Pipeline: {pid}   Class: {mc}   "
                   f"Filter ease: {fts}/100   Full ease: {frs}/100   "
                   f"Coverage: {cov}{warn}")
        ttk.Label(hdr, text=summary, font=("Segoe UI", 9)).pack(side="left")

        btn_frame = ttk.Frame(hdr)
        btn_frame.pack(side="right")
        ttk.Button(btn_frame, text="Export to file…", command=self._export).pack(side="left", padx=4)

        # ── Mode selector ─────────────────────────────────
        mode_bar = ttk.Frame(self)
        mode_bar.pack(fill="x", padx=8, pady=(0,4))
        self._mode_var = tk.StringVar(value="full")
        ttk.Radiobutton(mode_bar, text="Full pipeline", variable=self._mode_var,
                        value="full", command=self._refresh).pack(side="left", padx=4)
        ttk.Radiobutton(mode_bar, text="Per-processor:", variable=self._mode_var,
                        value="proc", command=self._refresh).pack(side="left")

        proc_names = [f"#{p.get('seq_index',0)}  {p.get('plugin','?').upper()}"
                      for p in self._proc_nodes]
        self._proc_var = tk.StringVar(value=proc_names[0] if proc_names else "")
        self._proc_combo = ttk.Combobox(mode_bar, textvariable=self._proc_var,
                                        values=proc_names, width=28, state="readonly")
        self._proc_combo.pack(side="left", padx=4)
        self._proc_combo.bind("<<ComboboxSelected>>", lambda e: self._on_proc_select())

        # ── Column headers ────────────────────────────────
        col_hdr = ttk.Frame(self)
        col_hdr.pack(fill="x", padx=8, pady=(2,0))
        ttk.Label(col_hdr, text="Logstash source",
                  font=("Segoe UI", 9, "bold"), foreground="#003050").pack(side="left", expand=True, fill="x")
        ttk.Separator(col_hdr, orient="vertical").pack(side="left", fill="y", padx=4)
        ttk.Label(col_hdr, text="Elasticsearch ingest pipeline",
                  font=("Segoe UI", 9, "bold"), foreground="#004000").pack(side="left", expand=True, fill="x")

        # ── Main split pane ───────────────────────────────
        pane = ttk.Panedwindow(self, orient="horizontal")
        pane.pack(fill="both", expand=True, padx=8, pady=4)

        left_f  = ttk.Frame(pane); pane.add(left_f,  weight=1)
        right_f = ttk.Frame(pane); pane.add(right_f, weight=1)

        def make_text(parent, bg="#f8faff") -> tk.Text:
            t = tk.Text(parent, wrap="none", font=("Consolas", 9), bg=bg)
            vsb = ttk.Scrollbar(parent, orient="vertical",   command=t.yview)
            hsb = ttk.Scrollbar(parent, orient="horizontal", command=t.xview)
            t.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            t.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            parent.rowconfigure(0, weight=1); parent.columnconfigure(0, weight=1)
            return t

        self._left_text  = make_text(left_f,  bg="#f8faff")
        self._right_text = make_text(right_f, bg="#f8fff8")

        # Tags
        for t in (self._left_text, self._right_text):
            t.tag_configure("comment", foreground="#888888", font=("Consolas", 9, "italic"))
            t.tag_configure("key",     foreground="#0000aa")
            t.tag_configure("str_val", foreground="#007700")
            t.tag_configure("warn",    foreground="#bb6600", font=("Consolas", 9, "bold"))
            t.tag_configure("heading", font=("Consolas", 9, "bold"))

        # ── Warnings strip ────────────────────────────────
        if self._warnings:
            wf = ttk.Frame(self)
            wf.pack(fill="x", padx=8, pady=(0,4))
            wb = tk.Text(wf, wrap="word", height=3, font=("Segoe UI", 8),
                         bg="#fff8e1", relief="flat")
            wb.pack(fill="x")
            wb.insert(tk.END, "Warnings:\n")
            for w in self._warnings[:5]:
                wb.insert(tk.END, f"  ⚠  {w}\n")
            wb.configure(state="disabled")

        self._refresh()

    def _refresh(self):
        mode = self._mode_var.get()
        if mode == "full":
            self._show_full()
        else:
            self._show_proc()

    def _on_proc_select(self):
        self._mode_var.set("proc")
        self._show_proc()

    def _show_full(self):
        # Left: full filter block (plus input/output for context)
        left_parts = []
        for section in ("raw_input_text", "raw_filter_text", "raw_output_text"):
            txt = self.row.get(section, "")
            if txt: left_parts.append(txt)
        left_content = "\n\n".join(left_parts) or "(no Logstash source stored)"

        # Right: full ingest pipeline JSON
        if self._ingest_error:
            right_content = f"// ERROR:\n// {self._ingest_error}"
        elif self._pipeline_json:
            right_content = json.dumps(self._pipeline_json, indent=2, ensure_ascii=False)
        else:
            right_content = "// (not generated)"

        self._set_left(left_content)
        self._set_right_json(right_content)

    def _show_proc(self):
        idx = self._proc_combo.current()
        if idx < 0 or idx >= len(self._proc_nodes):
            self._set_left("(no processor selected)"); self._set_right_json(""); return

        proc = self._proc_nodes[idx]
        plugin = proc.get("plugin", "?")
        seq    = proc.get("seq_index", 0)

        # Left: raw Logstash config for this processor
        raw = proc.get("raw_config", "")
        left_content = raw if raw else f"// (raw config not stored for {plugin.upper()} #{seq})"
        self._set_left(left_content)

        # Right: equivalent ES ingest processor(s)
        if self._ingest_error:
            self._set_right_json(f"// ERROR:\n// {self._ingest_error}")
            return
        try:
            from logstash_ingest_transformer import dispatch_processor
            result = dispatch_processor(proc, parent_condition=None)
            if result.warnings:
                warn_str = "\n".join(f"// ⚠  {w}" for w in result.warnings) + "\n\n"
            else:
                warn_str = ""
            procs_str = json.dumps(result.processors, indent=2, ensure_ascii=False)
            self._set_right_json(warn_str + procs_str)
        except Exception as e:
            self._set_right_json(f"// Error: {e}")

    def _set_left(self, text: str):
        t = self._left_text
        t.configure(state="normal"); t.delete("1.0", tk.END)
        t.insert(tk.END, text)
        t.configure(state="disabled")

    def _set_right_json(self, text: str):
        t = self._right_text
        t.configure(state="normal"); t.delete("1.0", tk.END)
        _insert_json_highlighted(t, text)
        t.configure(state="disabled")

    def _export(self):
        if not self._pipeline_json and not self._ingest_error:
            messagebox.showinfo("Nothing to export", "No ingest pipeline generated yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files","*.json"),("All files","*.*")],
            title="Save ingest pipeline JSON")
        if path and self._pipeline_json:
            Path(path).write_text(
                json.dumps(self._pipeline_json, indent=2, ensure_ascii=False),
                encoding="utf-8")
            msg = f"Saved: {path}\nCoverage: {self._coverage*100:.0f}%"
            if self._warnings: msg += f"\n{len(self._warnings)} warning(s) — see compare window"
            messagebox.showinfo("Export complete", msg)


def _flatten_processors(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return all ProcessorNode dicts in execution order from a filter tree dict."""
    result: List[Dict[str, Any]] = []
    nt = node.get("node_type", "")
    if nt == "processor":
        result.append(node)
    elif nt == "sequence":
        for c in node.get("children", []): result.extend(_flatten_processors(c))
    elif nt == "conditional":
        for b in node.get("branches", []): result.extend(_flatten_processors(b.get("body", {})))
    return result


def pipeline_grok_score(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Sum the grok performance scores across ALL grok processors in a pipeline.
    Returns a dict {total_score, band, count} or None if no grok processors found.

    The band is derived from the *total* score using the same thresholds as
    the per-processor scoring, but scaled:
      ≤ 10  → Fast
      ≤ 29  → Moderate
      ≤ 59  → Slow
      ≥ 60  → Very Slow
    (thresholds doubled relative to per-processor, since multiple groks are normal)
    """
    tree = row.get("processors_ordered", {})
    all_procs = _flatten_processors(tree)
    grok_procs = [p for p in all_procs if p.get("plugin") == "grok"]
    if not grok_procs:
        return None

    total = 0
    for p in grok_procs:
        metrics = p.get("metrics", {})
        if metrics:
            total += score_grok_performance(metrics)["score"]

    # Band using pipeline-level thresholds
    if total <= 10:   band, fill, text = "Fast",      "#c8f5c8", "#003300"
    elif total <= 29: band, fill, text = "Moderate",  "#fff5b0", "#4a3200"
    elif total <= 59: band, fill, text = "Slow",      "#ffd6d6", "#5a0000"
    else:             band, fill, text = "Very Slow", "#ffd6d6", "#8b0000"

    return {"total_score": total, "band": band,
            "fill": fill, "text": text, "count": len(grok_procs)}


def pipeline_dissect_summary(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Scan all grok processors in a pipeline and summarise dissect replaceability.

    Returns None if there are no grok processors.
    Returns a dict:
      total_groks        : int
      convertible_high   : int   — high confidence replaceable
      convertible_medium : int   — medium confidence (loses validation)
      not_convertible    : int   — cannot be replaced (alternation, etc.)
      label              : str   — short display string for the column
      tag                : str   — colour tag name
    """
    tree = row.get("processors_ordered", {})

    def collect(n: Dict[str, Any]) -> List[Dict[str, Any]]:
        nt = n.get("node_type", "")
        if nt == "processor" and n.get("plugin") == "grok":
            return [n]
        elif nt == "sequence":
            return [x for c in n.get("children", []) for x in collect(c)]
        elif nt == "conditional":
            return [x for b in n.get("branches", []) for x in collect(b.get("body", {}))]
        return []

    grok_nodes = collect(tree)
    if not grok_nodes:
        return None

    high = medium = no = 0
    for gn in grok_nodes:
        da = gn.get("dissect_analysis")
        if not da:
            no += 1
            continue
        if da.get("overall_convertible"):
            if da.get("overall_confidence") == "high":
                high += 1
            else:
                medium += 1
        else:
            no += 1

    total = len(grok_nodes)

    if no == total:
        label = "✗ None replaceable"
        tag   = "dissect_no"
    elif high == total:
        label = f"✓ All ({total}) — high"
        tag   = "dissect_high"
    elif high + medium == total:
        label = f"✓ All ({total}) — medium"
        tag   = "dissect_med"
    elif high + medium > 0:
        replaceable = high + medium
        label = f"~{replaceable}/{total} replaceable"
        tag   = "dissect_med" if no > 0 else "dissect_high"
    else:
        label = "✗ None replaceable"
        tag   = "dissect_no"

    return {"total_groks": total, "convertible_high": high,
            "convertible_medium": medium, "not_convertible": no,
            "label": label, "tag": tag}

class PipelineVisualizer(tk.Tk):
    def __init__(self, data: Dict[str, Any], plan: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.data = data
        self.title("Logstash Pipeline Visualizer v4 — Processor-Level View")
        self.geometry("1700x960")

        rows = get_pipelines(data)

        # ── Filter bar ───────────────────────────────────
        top = ttk.Frame(self); top.pack(fill="x", padx=8, pady=4)
        self.search_var = tk.StringVar()
        self.class_var  = tk.StringVar(value="All")
        ttk.Label(top, text="Search pipeline:").pack(side="left")
        ttk.Entry(top, textvariable=self.search_var, width=30).pack(side="left", padx=(4,12))
        ttk.Label(top, text="Class:").pack(side="left")
        ttk.Combobox(top, textvariable=self.class_var,
                     values=["All","Easy","Medium","Hard"], width=9, state="readonly").pack(side="left", padx=(4,12))
        ttk.Button(top, text="Apply", command=self._refresh_list).pack(side="left", padx=4)
        ttk.Button(top, text="Reset", command=self._reset_filters).pack(side="left")

        # Plan status indicator + View All buttons
        if plan:
            sep = ttk.Separator(top, orient="vertical")
            sep.pack(side="left", fill="y", padx=(10,6), pady=2)
            ttk.Label(top, text="✓ Plan loaded:",
                      foreground="#2ca25f", font=("Segoe UI", 8, "bold")).pack(side="left")
            # Store plan ref so buttons can access it after __init__
            self._plan = plan
            ttk.Button(top, text="All Pipelines",
                       command=lambda: AllPipelinesWindow(self._plan)).pack(side="left", padx=2)
            ttk.Button(top, text="All Blockers",
                       command=lambda: AllBlockersWindow(self._plan)).pack(side="left", padx=2)
            ttk.Button(top, text="All Patterns",
                       command=lambda: AllPatternsWindow(self._plan)).pack(side="left", padx=2)
            ttk.Button(top, text="All Fields",
                       command=lambda: AllFieldsWindow(self._plan)).pack(side="left", padx=2)
        else:
            self._plan = {}

        # Summary labels
        total = len(rows)
        hard  = sum(1 for r in rows if r.get("migration_class")=="Hard")
        self._summary_var = tk.StringVar(value=f"  {total} pipelines  |  {hard} Hard")
        ttk.Label(top, textvariable=self._summary_var, foreground="#888").pack(side="right")

        # ── Body: pipeline list (left) + flow canvas + detail (right) ─
        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True)

        # Pipeline list panel
        list_frame = ttk.Frame(body, width=280)
        body.add(list_frame, weight=1)

        list_cols = ("pipeline", "class", "cov", "grok", "dissect", "pattern", "input", "output")
        self.pipeline_list = ttk.Treeview(list_frame, columns=list_cols, show="headings", height=30)
        self.pipeline_list.heading("pipeline", text="Pipeline",
                                   command=lambda: self._sort_list("pipeline"))
        self.pipeline_list.heading("class",    text="Class",
                                   command=lambda: self._sort_list("class"))
        self.pipeline_list.heading("cov",      text="Filt%",
                                   command=lambda: self._sort_list("cov"))
        self.pipeline_list.heading("grok",     text="Grok score",
                                   command=lambda: self._sort_list("grok"))
        self.pipeline_list.heading("dissect",  text="Dissect?",
                                   command=lambda: self._sort_list("dissect"))
        self.pipeline_list.heading("pattern",  text="Pattern",
                                   command=lambda: self._sort_list("pattern"))
        self.pipeline_list.heading("input",    text="Input",
                                   command=lambda: self._sort_list("input"))
        self.pipeline_list.heading("output",   text="Output",
                                   command=lambda: self._sort_list("output"))
        self.pipeline_list.column("pipeline",  width=130)
        self.pipeline_list.column("class",     width=52)
        self.pipeline_list.column("cov",       width=42)
        self.pipeline_list.column("grok",      width=96)
        self.pipeline_list.column("dissect",   width=100)
        self.pipeline_list.column("pattern",   width=140)
        self.pipeline_list.column("input",     width=100)
        self.pipeline_list.column("output",    width=130)
        self.pipeline_list.tag_configure("Easy",        background="#e8ffe8")
        self.pipeline_list.tag_configure("Medium",      background="#fffbe6")
        self.pipeline_list.tag_configure("Hard",        background="#ffe6e6")
        self.pipeline_list.tag_configure("grok_fast",   foreground="#2ca25f")
        self.pipeline_list.tag_configure("grok_mod",    foreground="#b08800")
        self.pipeline_list.tag_configure("grok_slow",   foreground="#cb181d")
        self.pipeline_list.tag_configure("dissect_high",foreground="#2ca25f")
        self.pipeline_list.tag_configure("dissect_med", foreground="#b08800")
        self.pipeline_list.tag_configure("dissect_no",  foreground="#cb181d")
        self._list_sort_col   = "pipeline"
        self._list_sort_desc  = False
        lsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.pipeline_list.yview)
        self.pipeline_list.configure(yscrollcommand=lsb.set)
        self.pipeline_list.pack(side="left", fill="both", expand=True)
        lsb.pack(side="right", fill="y")
        self.pipeline_list.bind("<<TreeviewSelect>>", self._on_select)

        # Right: canvas + detail pane
        right_pane = ttk.Panedwindow(body, orient="vertical")
        body.add(right_pane, weight=5)

        # Detail panel
        self.detail_panel = ProcessorDetailPanel(right_pane)
        right_pane.add(self.detail_panel, weight=1)

        # Load advisor plan into detail panel if provided
        if plan:
            self.detail_panel.set_plan(plan)

        # Flow canvas
        self.flow_canvas = PipelineFlowCanvas(right_pane, self.detail_panel)
        right_pane.add(self.flow_canvas, weight=4)

        self.all_rows = rows
        self.filtered_rows = list(rows)
        self.search_var.trace_add("write", lambda *a: self._refresh_list())
        self.class_var.trace_add("write",  lambda *a: self._refresh_list())
        self._refresh_list()

    def _reset_filters(self):
        self.search_var.set(""); self.class_var.set("All")

    def _row_grok_display(self, r: Dict[str, Any]) -> Tuple[str, str]:
        """Return (display_string, tag) for the Grok score column."""
        gs = pipeline_grok_score(r)
        if gs is None:
            return "—", ""
        band_tag = {
            "Fast":      "grok_fast",
            "Moderate":  "grok_mod",
            "Slow":      "grok_slow",
            "Very Slow": "grok_slow",
        }.get(gs["band"], "")
        n = gs["count"]
        label = f"{gs['band']} {gs['total_score']}  ({n} grok{'s' if n!=1 else ''})"
        return label, band_tag

    def _row_dissect_display(self, r: Dict[str, Any]) -> Tuple[str, str]:
        """Return (display_string, tag) for the Dissect column."""
        ds = pipeline_dissect_summary(r)
        if ds is None:
            return "—", ""
        return ds["label"], ds["tag"]

    def _refresh_list(self):
        q = self.search_var.get().strip().lower()
        c = self.class_var.get()
        self.filtered_rows = [
            r for r in self.all_rows
            if (not q or q in r.get("pipeline","").lower() or
                any(q in str(v).lower() for v in (r.get("local_processors",{}) or {}).keys()))
            and (c=="All" or r.get("migration_class","")==c)
        ]
        self._repopulate_list()

    def _repopulate_list(self):
        for item in self.pipeline_list.get_children():
            self.pipeline_list.delete(item)
        for r in self.filtered_rows:
            mc              = r.get("migration_class","")
            fts             = r.get("filter_transform_score", r.get("migration_score", 0))
            grok_lbl, gt    = self._row_grok_display(r)
            dissect_lbl, dt = self._row_dissect_display(r)

            # Pattern — from plan if available, else derive from processor fingerprint
            pat_lbl = ""
            if hasattr(self, '_detail_panel_ref'):
                pass  # handled below
            # Get pattern from detail panel's plan_by_id lookup
            pid = r.get("pipeline","")
            if hasattr(self, 'detail_panel') and self.detail_panel._plan_by_id:
                p_data = self.detail_panel._plan_by_id.get(pid)
                if p_data:
                    pat_lbl = (p_data.get("pattern") or {}).get("primary", "")

            # Input — short label from input_sources
            srcs = r.get("input_sources") or []
            if srcs:
                in_lbl = srcs[0].replace("SOURCE:","")
                # Shorten common prefixes
                for pfx in ("beats:","kafka:","jdbc:","http:","syslog:","tcp:","udp:","file:"):
                    if in_lbl.lower().startswith(pfx):
                        in_lbl = pfx.rstrip(":") + ":" + in_lbl[len(pfx):].split("/")[-1][:12]
                        break
                if len(srcs) > 1: in_lbl += f" +{len(srcs)-1}"
            else:
                in_lbl = "(pipeline)"

            # Output — short label from terminal_sinks or local_outputs
            sinks = r.get("terminal_sinks") or []
            outs  = r.get("local_outputs") or []
            if sinks:
                s = sinks[0].replace("SINK:","")
                # Shorten ES index pattern
                if "elasticsearch" in s.lower():
                    idx = s.split(":")[-1] if ":" in s else s
                    out_lbl = "ES:" + idx[:20]
                elif "kafka" in s.lower():
                    out_lbl = "kafka:" + s.split(":")[-1][:14]
                else:
                    out_lbl = s[:22]
                if len(sinks) > 1: out_lbl += f" +{len(sinks)-1}"
            elif outs:
                out_lbl = "→" + ",".join(outs[:2])[:22]
            else:
                out_lbl = "(none)"

            tags = tuple(t for t in (mc, gt, dt) if t)
            self.pipeline_list.insert("","end", iid=pid,
                tags=tags, values=(pid, mc, fts, grok_lbl, dissect_lbl,
                                   pat_lbl, in_lbl, out_lbl))
        if self.filtered_rows:
            first = self.filtered_rows[0]["pipeline"]
            self.pipeline_list.selection_set(first)
            self.pipeline_list.focus(first)

        hard = sum(1 for r in self.filtered_rows if r.get("migration_class")=="Hard")
        self._summary_var.set(f"  {len(self.filtered_rows)} pipelines  |  {hard} Hard")

    def _sort_list(self, col: str):
        """Click a column heading to sort; click again to reverse."""
        if self._list_sort_col == col:
            self._list_sort_desc = not self._list_sort_desc
        else:
            self._list_sort_col  = col
            self._list_sort_desc = False

        # Class sort: Hard=0, Medium=1, Easy=2 (so Hard sorts first by default)
        CLASS_ORDER = {"Hard": 0, "Medium": 1, "Easy": 2}

        def sort_key(r):
            if col == "pipeline":  return r.get("pipeline","").lower()
            if col == "class":     return CLASS_ORDER.get(r.get("migration_class",""), 9)
            if col == "cov":       return int(r.get("filter_transform_score", r.get("migration_score",0)) or 0)
            if col == "grok":
                gs = pipeline_grok_score(r)
                return gs["total_score"] if gs else -1
            if col == "dissect":
                ds = pipeline_dissect_summary(r)
                if ds is None: return -1
                return ds["convertible_high"] * 100 + ds["convertible_medium"] * 10
            if col == "pattern":
                pid = r.get("pipeline","")
                if hasattr(self, 'detail_panel') and self.detail_panel._plan_by_id:
                    p_data = self.detail_panel._plan_by_id.get(pid)
                    if p_data:
                        return (p_data.get("pattern") or {}).get("primary", "")
                return ""
            if col == "input":
                srcs = r.get("input_sources") or []
                return srcs[0].replace("SOURCE:","").lower() if srcs else "~pipeline"
            if col == "output":
                sinks = r.get("terminal_sinks") or []
                return sinks[0].replace("SINK:","").lower() if sinks else "~none"
            return ""

        self.filtered_rows.sort(key=sort_key, reverse=self._list_sort_desc)
        self._repopulate_list()

    def _on_select(self, event=None):
        sel = self.pipeline_list.selection()
        if not sel: return
        pid = sel[0]
        row = next((r for r in self.filtered_rows if r.get("pipeline")==pid), None)
        if row: self.flow_canvas.load_pipeline(row)

# ─────────────────────────────────────────────────────────────
# "View All" overview windows — opened from advisor tab buttons
# ─────────────────────────────────────────────────────────────

def _tv_window(title: str, width: int = 1100, height: int = 640) -> Tuple[tk.Toplevel, ttk.Frame]:
    win = tk.Toplevel()
    win.title(title)
    win.geometry(f"{width}x{height}")
    win.minsize(700, 400)
    win.columnconfigure(0, weight=1)
    win.rowconfigure(1, weight=1)
    frame = ttk.Frame(win)
    frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)
    frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
    return win, frame


def _add_treeview(frame: ttk.Frame, cols: List[Tuple[str,str,int]]) -> ttk.Treeview:
    tv = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings")
    vsb = ttk.Scrollbar(frame, orient="vertical",   command=tv.yview)
    hsb = ttk.Scrollbar(frame, orient="horizontal", command=tv.xview)
    tv.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
    tv.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")
    for cid, heading, w in cols:
        tv.heading(cid, text=heading, command=lambda c=cid, t=tv: _tv_sort(t, c))
        tv.column(cid, width=w, minwidth=30)
    return tv


_tv_sort_state: Dict[str, bool] = {}

def _tv_sort(tv: ttk.Treeview, col: str):
    key = f"{id(tv)}:{col}"
    desc = _tv_sort_state.get(key, False)
    _tv_sort_state[key] = not desc
    items = [(tv.set(k, col), k) for k in tv.get_children("")]
    try:
        items.sort(key=lambda x: float(x[0].rstrip("%")) if x[0].rstrip("%") else -1, reverse=desc)
    except ValueError:
        items.sort(key=lambda x: x[0].lower(), reverse=desc)
    for i, (_, k) in enumerate(items):
        tv.move(k, "", i)


def _csv_export(win: tk.Toplevel, tv: ttk.Treeview, default_name: str):
    import csv as csv_mod
    from tkinter import filedialog, messagebox
    path = filedialog.asksaveasfilename(
        parent=win, defaultextension=".csv",
        filetypes=[("CSV files","*.csv"),("All files","*.*")],
        initialfile=default_name)
    if not path: return
    cols = tv["columns"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        csv_mod.writer(fh).writerow(cols)
        for iid in tv.get_children(""):
            csv_mod.writer(fh).writerow(tv.item(iid)["values"])
    messagebox.showinfo("Exported",
                        f"Saved {len(tv.get_children(''))} rows to:\n{path}", parent=win)


def _add_toolbar(win: tk.Toplevel, tv: ttk.Treeview, summary_text: str, default_csv: str):
    bar = ttk.Frame(win)
    bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(6,2))
    ttk.Label(bar, text=summary_text,
              font=("Segoe UI", 9), foreground="#555").pack(side="left")
    ttk.Button(bar, text="Export CSV →",
               command=lambda: _csv_export(win, tv, default_csv)).pack(side="right")


# ── 1. All Pipelines ──────────────────────────────────────────

class AllPipelinesWindow:
    def __init__(self, plan: Dict[str, Any]):
        if not plan: return
        win, frame = _tv_window("All Pipelines — Migration Plan", 1160, 660)
        cols = [
            ("pipeline",  "Pipeline",   200), ("wave",  "Wave",  44),
            ("pattern",   "Pattern",    148), ("port",  "Port",  42),
            ("coup",      "Coup",        42), ("complexity","Complexity",74),
            ("benefit",   "Benefit",     54), ("effort","Effort",62),
            ("hard_blk",  "Hard",        38), ("aps",   "APs",   34),
            ("decision",  "Decision",   300),
        ]
        tv = _add_treeview(frame, cols)
        for w, clr in [(1,"#e8ffe8"),(2,"#fffbe6"),(3,"#ffe6e6")]:
            tv.tag_configure(f"w{w}", background=clr)
        tv.tag_configure("has_ap", foreground="#cb181d")

        rows = plan.get("pipelines", [])
        wc = plan.get("wave_counts", {})
        for p in sorted(rows, key=lambda x: (x.get("wave",9),
                                              -(x.get("operational_benefit",0) or 0))):
            wave = p.get("wave", 0)
            pat  = (p.get("pattern") or {})
            hard = sum(1 for b in (p.get("blockers") or []) if b.get("severity")=="hard")
            aps  = len(p.get("anti_patterns") or [])
            tags = (f"w{wave}", "has_ap") if aps else (f"w{wave}",)
            tv.insert("", "end", tags=tags, values=(
                p.get("pipeline_id",""), wave,
                pat.get("primary",""), pat.get("portability",""),
                pat.get("coupling",""), pat.get("complexity",""),
                p.get("operational_benefit",""), p.get("migration_effort",""),
                hard, f"⚑{aps}" if aps else "",
                (p.get("decision") or "")[:80],
            ))

        def _w(n): return wc.get(str(n), wc.get(n, 0))
        _add_toolbar(win, tv,
                     f"{len(rows)} pipelines  ·  W1:{_w(1)}  W2:{_w(2)}  W3:{_w(3)}"
                     f"  ·  Green=W1  Amber=W2  Red=W3  ·  Port=Portability  Coup=Coupling",
                     "all_pipelines.csv")


# ── 2. All Blockers ───────────────────────────────────────────

class AllBlockersWindow:
    def __init__(self, plan: Dict[str, Any]):
        if not plan: return
        win = tk.Toplevel()
        win.title("All Blockers & Anti-patterns")
        win.geometry("1080x640"); win.minsize(700, 400)
        win.columnconfigure(0, weight=1); win.rowconfigure(1, weight=1)

        nb = ttk.Notebook(win)
        nb.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)

        rows = plan.get("pipelines", [])

        # ── Blockers tab ──────────────────────────────────
        bf = ttk.Frame(nb); nb.add(bf, text="Migration Blockers")
        bf.rowconfigure(0, weight=1); bf.columnconfigure(0, weight=1)
        blk_tv = _add_treeview(bf, [
            ("pipeline","Pipeline",200),("wave","Wave",40),
            ("severity","Severity",70),("name","Blocker",180),
            ("recommendation","Recommendation",490),
        ])
        for sev, clr in [("hard","#ffe6e6"),("workaround","#fffbe6"),("decision","#f0f4ff")]:
            blk_tv.tag_configure(sev, background=clr)
        blk_count = 0
        for p in sorted(rows, key=lambda x: (x.get("wave",9), x.get("pipeline_id",""))):
            for b in (p.get("blockers") or []):
                sev = b.get("severity","")
                blk_tv.insert("", "end", tags=(sev,), values=(
                    p.get("pipeline_id",""), p.get("wave",""), sev.upper(),
                    b.get("name","")[:50], b.get("recommendation","")[:120],
                ))
                blk_count += 1

        # ── Anti-patterns tab ─────────────────────────────
        af = ttk.Frame(nb); nb.add(af, text="Anti-patterns")
        af.rowconfigure(0, weight=1); af.columnconfigure(0, weight=1)
        ap_tv = _add_treeview(af, [
            ("pipeline","Pipeline",200),("wave","Wave",40),
            ("severity","Severity",70),("name","Anti-pattern",180),
            ("recommendation","Recommendation",490),
        ])
        for sev, clr in [("high","#ffe6e6"),("medium","#fffbe6"),
                         ("low","#f0f0f0"),("info","#f5f5f5")]:
            ap_tv.tag_configure(sev, background=clr)
        ap_count = 0
        for p in sorted(rows, key=lambda x: (x.get("wave",9), x.get("pipeline_id",""))):
            for ap in (p.get("anti_patterns") or []):
                sev = ap.get("severity","info")
                ap_tv.insert("", "end", tags=(sev,), values=(
                    p.get("pipeline_id",""), p.get("wave",""), sev.upper(),
                    ap.get("name","")[:50], ap.get("recommendation","")[:120],
                ))
                ap_count += 1

        bar = ttk.Frame(win)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(6,2))
        ttk.Label(bar,
                  text=f"{blk_count} blockers  ·  {ap_count} anti-pattern findings"
                       f"  ·  Red=Hard  Amber=Workaround/Medium",
                  font=("Segoe UI", 9), foreground="#555").pack(side="left")
        def _export():
            tv = blk_tv if nb.index(nb.select()) == 0 else ap_tv
            nm = "all_blockers.csv" if nb.index(nb.select()) == 0 else "all_anti_patterns.csv"
            _csv_export(win, tv, nm)
        ttk.Button(bar, text="Export CSV →", command=_export).pack(side="right")


# ── 3. All Patterns ───────────────────────────────────────────

class AllPatternsWindow:
    def __init__(self, plan: Dict[str, Any]):
        if not plan: return
        win = tk.Toplevel()
        win.title("Pattern Summary & Anti-pattern Summary")
        win.geometry("1100x620"); win.minsize(700, 400)
        win.columnconfigure(0, weight=1); win.rowconfigure(1, weight=1)

        nb = ttk.Notebook(win)
        nb.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)

        # ── Pattern summary tab ───────────────────────────
        pf = ttk.Frame(nb); nb.add(pf, text="Pattern Summary")
        pf.rowconfigure(0, weight=1); pf.columnconfigure(0, weight=1)
        pat_tv = _add_treeview(pf, [
            ("pattern","Pattern",160),("count","#",38),("pct","%",50),
            ("complexity","Complexity",80),("port","Port",44),("coup","Coup",44),
            ("w1","W1",38),("w2","W2",38),("w3","W3",38),("filtpct","Filt%",50),
            ("description","Description",340),
        ])
        pat_tv.tag_configure("high_port", foreground="#2ca25f")
        pat_tv.tag_configure("low_port",  foreground="#cb181d")
        pat_tv.tag_configure("wave3_only",background="#fff0f0")
        for r in plan.get("pattern_summary", []):
            port     = r.get("avg_portability", 0)
            only_w3  = (r.get("wave3_count",0) > 0 and
                        r.get("wave1_count",0) == 0 and r.get("wave2_count",0) == 0)
            tag = "low_port" if port < 40 else ("high_port" if port > 80 else "")
            tags = tuple(t for t in (tag, "wave3_only" if only_w3 else "") if t)
            pat_tv.insert("", "end", tags=tags, values=(
                r.get("pattern",""),
                r.get("pipeline_count",""),
                f"{r.get('pct_of_total',0):.1f}%",
                r.get("dominant_complexity",""),
                port, r.get("avg_coupling",0),
                r.get("wave1_count",0), r.get("wave2_count",0), r.get("wave3_count",0),
                f"{r.get('avg_filter_coverage',0)}%",
                r.get("description","")[:80],
            ))

        # ── Anti-pattern summary tab ──────────────────────
        apsf = ttk.Frame(nb); nb.add(apsf, text="Anti-pattern Summary")
        apsf.rowconfigure(0, weight=1); apsf.columnconfigure(0, weight=1)
        aps_tv = _add_treeview(apsf, [
            ("severity","Severity",70),("name","Anti-pattern",220),
            ("count","Pipelines",70),
            ("description","Description",280),("recommendation","Recommendation",340),
        ])
        for sev, clr in [("HIGH","#ffe6e6"),("MEDIUM","#fffbe6"),
                         ("LOW","#f0f0f0"),("INFO","#f5f5f5")]:
            aps_tv.tag_configure(sev, background=clr)
        for r in plan.get("anti_pattern_summary", []):
            sev = r.get("severity","info").upper()
            aps_tv.insert("", "end", tags=(sev,), values=(
                sev, r.get("name",""), r.get("pipeline_count",""),
                r.get("description","")[:80], r.get("recommendation","")[:100],
            ))

        n_pat = len(plan.get("pattern_summary",[])); n_aps = len(plan.get("anti_pattern_summary",[]))
        bar = ttk.Frame(win)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(6,2))
        ttk.Label(bar, text=f"{n_pat} patterns  ·  {n_aps} anti-pattern types"
                  f"  ·  Green=high portability  Red=low portability",
                  font=("Segoe UI", 9), foreground="#555").pack(side="left")
        def _export():
            tv = pat_tv if nb.index(nb.select()) == 0 else aps_tv
            nm = "pattern_summary.csv" if nb.index(nb.select()) == 0 else "anti_pattern_summary.csv"
            _csv_export(win, tv, nm)
        ttk.Button(bar, text="Export CSV →", command=_export).pack(side="right")


# ── 4. All Fields ─────────────────────────────────────────────

class AllFieldsWindow:
    def __init__(self, plan: Dict[str, Any]):
        if not plan: return
        af = plan.get("all_fields", {})
        if not af: return

        win = tk.Toplevel()
        win.title("All Fields — Cross-pipeline Field Inventory")
        win.geometry("1060x620"); win.minsize(700, 400)
        win.columnconfigure(0, weight=1); win.rowconfigure(1, weight=1)

        nb = ttk.Notebook(win)
        nb.grid(row=1, column=0, sticky="nsew", padx=8, pady=4)

        tvs: List[Tuple[str, ttk.Treeview]] = []

        simple_cols = [("field","Field",260),("count","Pipelines",70),
                       ("pipelines","Used in",640)]

        def _simple_tab(tab_lbl: str, entries: List[Dict], field_key: str = "field"):
            f = ttk.Frame(nb); nb.add(f, text=f"{tab_lbl} ({len(entries)})")
            f.rowconfigure(0, weight=1); f.columnconfigure(0, weight=1)
            tv = _add_treeview(f, simple_cols)
            for e in entries:
                pids  = e.get("pipelines", [])
                plist = " | ".join(pids[:6]) + (f" … +{len(pids)-6}" if len(pids)>6 else "")
                tv.insert("", "end", values=(e.get(field_key,""), e.get("pipeline_count",""), plist))
            tvs.append((tab_lbl, tv))

        def _rename_tab():
            entries = af.get("renamed", [])
            f = ttk.Frame(nb); nb.add(f, text=f"Renamed ({len(entries)})")
            f.rowconfigure(0, weight=1); f.columnconfigure(0, weight=1)
            tv = _add_treeview(f, [("from","From",200),("to","To",200),
                                    ("count","Pipelines",70),("pipelines","Used in",500)])
            for e in entries:
                pids  = e.get("pipelines", [])
                plist = " | ".join(pids[:6]) + (f" … +{len(pids)-6}" if len(pids)>6 else "")
                tv.insert("", "end", values=(e.get("from",""), e.get("to",""),
                                              e.get("pipeline_count",""), plist))
            tvs.append(("Renamed", tv))

        def _ts_tab():
            entries = af.get("timestamp_fields", [])
            f = ttk.Frame(nb); nb.add(f, text=f"Timestamps ({len(entries)})")
            f.rowconfigure(0, weight=1); f.columnconfigure(0, weight=1)
            tv = _add_treeview(f, [("source","Source field",200),("target","Target",140),
                                    ("count","Pipelines",70),("pipelines","Used in",560)])
            for e in entries:
                pids  = e.get("pipelines", [])
                plist = " | ".join(pids[:6]) + (f" … +{len(pids)-6}" if len(pids)>6 else "")
                tv.insert("", "end", values=(e.get("source",""), e.get("target",""),
                                              e.get("pipeline_count",""), plist))
            tvs.append(("Timestamps", tv))

        _simple_tab("Created",       af.get("created",[]))
        _rename_tab()
        _simple_tab("Removed",       af.get("removed",[]))
        _simple_tab("Grok captures", af.get("grok_captures",[]))
        _simple_tab("Enriched",      af.get("enriched",[]), field_key="target")
        _ts_tab()

        total = sum(len(af.get(k,[])) for k in
                    ("created","renamed","removed","grok_captures","enriched","timestamp_fields"))
        bar = ttk.Frame(win)
        bar.grid(row=0, column=0, sticky="ew", padx=8, pady=(6,2))
        ttk.Label(bar, text=f"{total} distinct field operations across all pipelines",
                  font=("Segoe UI", 9), foreground="#555").pack(side="left")
        def _export():
            idx = nb.index(nb.select())
            if idx < len(tvs):
                lbl, tv = tvs[idx]
                _csv_export(win, tv, f"fields_{lbl.lower().replace(' ','_')}.csv")
        ttk.Button(bar, text="Export CSV →", command=_export).pack(side="right")


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def load_plan(path: Optional[Path]) -> Optional[Dict[str, Any]]:
    """Load the advisor plan JSON.  Returns None if not provided or unreadable."""
    if not path: return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Could not load plan file {path}: {e}", file=sys.stderr)
        return None


def main():
    ap = argparse.ArgumentParser(description="Logstash Pipeline Visualizer v4 — compare view + grok scoring + advisor tabs")
    ap.add_argument("analysis_json", help="JSON output from logstash_pipeline_analyzer_v12.py")
    ap.add_argument("--pipeline", help="Open this pipeline directly on launch")
    ap.add_argument("--plan",     help="Advisory plan JSON from logstash_migration_advisor.py "
                                       "(activates Pipeline / Blockers / Architecture / Patterns tabs)")
    args = ap.parse_args()

    data = load_json(Path(args.analysis_json))
    plan = load_plan(Path(args.plan) if args.plan else None)
    app  = PipelineVisualizer(data, plan=plan)
    if args.pipeline:
        row = get_pipeline(data, args.pipeline)
        if row: app.flow_canvas.load_pipeline(row)
    app.mainloop()

if __name__ == "__main__":
    main()

