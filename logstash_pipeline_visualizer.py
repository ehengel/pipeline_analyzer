#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logstash_pipeline_visualizer_v3.py
═══════════════════════════════════════════════════════════════════════════
Stage 4 — Kibana-style processor-level pipeline visualizer (v3).

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
# ProcessorDetailPanel  (v3)
# ─────────────────────────────────────────────────────────────

class ProcessorDetailPanel(ttk.Frame):
    """
    Three-tab detail panel shown when the user clicks a processor node.

      Tab 1 "Info"        — plugin name, ingest support, config summary,
                            grok performance score (grok nodes only)
      Tab 2 "Logstash"    — raw Logstash config text for this processor
      Tab 3 "Ingest JSON" — equivalent ES ingest processor JSON
                            (side-by-side Logstash ↔ Ingest view)
    """

    def __init__(self, parent):
        super().__init__(parent)
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
            ("grok_fast",   "#2ca25f", True),
            ("grok_mod",    "#b08800", True),
            ("grok_slow",   "#cb181d", True),
            ("grok_vslow",  "#8b0000", True),
            ("dim",         "#666666", False),
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

        # colour highlight tags for ingest JSON (simple keyword colouring)
        self.ingest_text.tag_configure("key",  foreground="#0000aa")
        self.ingest_text.tag_configure("str_val", foreground="#007700")
        self.ingest_text.tag_configure("comment", foreground="#888888", font=("Consolas", 9, "italic"))
        self.ingest_text.tag_configure("warn",    foreground="#bb6600", font=("Consolas", 9, "bold"))

    def _copy_ingest(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self.ingest_text.get("1.0", tk.END))
        except Exception:
            pass

    def show(self, payload: Dict[str, Any]):
        node_type = payload.get("node_type", "")
        self._populate_info(payload, node_type)
        self._populate_raw(payload, node_type)
        self._populate_ingest_json(payload, node_type)
        # Always bring Info tab to front so grok score / ingest note is immediately visible
        self._nb.select(0)

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
        label_cy = (y + (node.h - (10 if grok_perf else 0))) // 2
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

class PipelineVisualizer(tk.Tk):
    def __init__(self, data: Dict[str, Any]):
        super().__init__()
        self.data = data
        self.title("Logstash Pipeline Visualizer v3 — Processor-Level View")
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

        list_cols = ("pipeline", "class", "cov", "grok")
        self.pipeline_list = ttk.Treeview(list_frame, columns=list_cols, show="headings", height=30)
        self.pipeline_list.heading("pipeline", text="Pipeline",
                                   command=lambda: self._sort_list("pipeline"))
        self.pipeline_list.heading("class",    text="Class",
                                   command=lambda: self._sort_list("class"))
        self.pipeline_list.heading("cov",      text="Filt%",
                                   command=lambda: self._sort_list("cov"))
        self.pipeline_list.heading("grok",     text="Grok score",
                                   command=lambda: self._sort_list("grok"))
        self.pipeline_list.column("pipeline",  width=140)
        self.pipeline_list.column("class",     width=56)
        self.pipeline_list.column("cov",       width=46)
        self.pipeline_list.column("grok",      width=86)
        self.pipeline_list.tag_configure("Easy",      background="#e8ffe8")
        self.pipeline_list.tag_configure("Medium",    background="#fffbe6")
        self.pipeline_list.tag_configure("Hard",      background="#ffe6e6")
        self.pipeline_list.tag_configure("grok_fast", foreground="#2ca25f")
        self.pipeline_list.tag_configure("grok_mod",  foreground="#b08800")
        self.pipeline_list.tag_configure("grok_slow", foreground="#cb181d")
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
            mc           = r.get("migration_class","")
            fts          = r.get("filter_transform_score", r.get("migration_score", 0))
            grok_lbl, gt = self._row_grok_display(r)
            # Combine migration-class background tag with optional grok foreground tag
            tags = (mc, gt) if gt else (mc,)
            self.pipeline_list.insert("","end", iid=r["pipeline"],
                tags=tags, values=(r["pipeline"], mc, fts, grok_lbl))
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

        def sort_key(r):
            if col == "pipeline":  return r.get("pipeline","").lower()
            if col == "class":     return r.get("migration_class","")
            if col == "cov":       return int(r.get("filter_transform_score", r.get("migration_score",0)) or 0)
            if col == "grok":
                gs = pipeline_grok_score(r)
                return gs["total_score"] if gs else -1
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
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Logstash Pipeline Visualizer v3 — compare view + grok scoring")
    ap.add_argument("analysis_json", help="JSON output from logstash_pipeline_analyzer_v12.py")
    ap.add_argument("--pipeline", help="Open this pipeline directly on launch")
    args = ap.parse_args()

    data = load_json(Path(args.analysis_json))
    app = PipelineVisualizer(data)
    if args.pipeline:
        row = get_pipeline(data, args.pipeline)
        if row: app.flow_canvas.load_pipeline(row)
    app.mainloop()

if __name__ == "__main__":
    main()
