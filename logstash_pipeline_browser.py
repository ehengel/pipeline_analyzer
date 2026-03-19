#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
logstash_pipeline_browser_v3.py
═══════════════════════════════════════════════════════════════════════════
What's new vs v2
─────────────────
1.  Color-coded pipeline nodes  (canvas + table row tags)
      Green  (#c8f5c8 / #2ca25f) → Easy migration
      Yellow (#fff5b0 / #b08800) → Medium
      Red    (#ffd6d6 / #cb181d) → Hard

2.  Zoom + pan on the flow canvas
      Mouse wheel / +/- zoom; drag to pan; Home resets view.

3.  Pipeline label column  ("Simple ingest candidate", etc.)
      Also shown in the detail panel.

4.  Migration reasons panel  (bottom of detail pane, always visible)
      Plain-English bullet list, same as analyzer v10 output.

5.  Recommendations tab  (right panel has two tabs: Details / Config)
      Actionable migration recommendations listed clearly.

6.  Block-level highlighting in Config pane
      Now highlights entire plugin block + shows a tooltip explaining
      *why* it is flagged when you hover over a highlighted region.

7.  Filter-block extraction fix
      Uses balanced-brace scanner (not just string search) — no more
      "[No filter block found]" for valid pipelines.

8.  Reads v10 JSON  (backward-compatible with v9 JSON too).
═══════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations

import argparse
import json
import re
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# ─────────────────────────────────────────────────────────────
# Canvas layout constants
# ─────────────────────────────────────────────────────────────
BOX_W      = 290
BOX_H      = 140
COL_X      = [40, 400, 760]
V_SPACING  = 36
TOP_Y      = 70
CANVAS_W   = 1600
CANVAS_H   = 960

# ─────────────────────────────────────────────────────────────
# Plugin colour / tooltip catalogue (v3)
# ─────────────────────────────────────────────────────────────
PLUGIN_EXPLANATIONS: Dict[str, Tuple[str, str]] = {
    # (highlight_tier, tooltip_text)
    "ruby":           ("hard",   "ruby: Not supported in ingest pipelines. Replace with Painless script processor."),
    "aggregate":      ("hard",   "aggregate: Stateful — requires external coordination. Redesign required."),
    "elapsed":        ("hard",   "elapsed: Event-pair timing is stateful. Not ingest-compatible."),
    "clone":          ("hard",   "clone: Event cloning not natively supported in ingest."),
    "metrics":        ("hard",   "metrics: Aggregation state — use Elasticsearch aggregations instead."),
    "jdbc_streaming": ("hard",   "jdbc_streaming: External DB dependency. Pre-load to enrich policy."),
    "memcached":      ("hard",   "memcached: External state lookup. Replace with enrich policy."),
    "cipher":         ("hard",   "cipher: Security-critical custom code. Evaluate Painless or pre-process."),
    "http":           ("hard",   "http: Outbound HTTP not supported in ingest. Pre-enrich or trigger externally."),
    "elasticsearch":  ("hard",   "elasticsearch filter: Lookup — replace with enrich policy."),
    "translate":      ("medium", "translate: File-based dictionary. Replace with enrich policy."),
    "xml":            ("medium", "xml: Not natively supported in ingest. Use Painless script processor."),
    "dns":            ("medium", "dns: Network I/O not available in ingest. Pre-resolve DNS."),
    "useragent":      ("medium", "useragent: Use user_agent ingest processor (ES 7.11+)."),
    "geoip":          ("medium", "geoip: Use geoip ingest processor with maxmind DB."),
}

TIER_COLORS = {
    "hard":   {"bg": "#fff59d", "fg": "#8b0000", "outline": "#cc0000"},
    "medium": {"bg": "#fff9c4", "fg": "#5c4b00", "outline": "#c8a400"},
}

MIG_NODE_COLORS = {
    "Easy":   {"fill": "#c8f5c8", "outline": "#2ca25f", "text": "#004d00"},
    "Medium": {"fill": "#fff5b0", "outline": "#b08800", "text": "#5a3800"},
    "Hard":   {"fill": "#ffd6d6", "outline": "#cb181d", "text": "#5a0000"},
}

# ─────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────

def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def get_pipeline_rows(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return data.get("logical_pipelines", [])

def get_pipeline_row(data: Dict[str, Any], name: str) -> Optional[Dict[str, Any]]:
    for row in get_pipeline_rows(data):
        if row.get("pipeline") == name:
            return row
    return None

def short_text(s: str, n: int = 64) -> str:
    s = "" if s is None else str(s)
    return s if len(s) <= n else s[:n - 3] + "..."

def unique_preserve(items: List[str]) -> List[str]:
    seen = set(); out = []
    for item in items:
        if item not in seen: seen.add(item); out.append(item)
    return out

def read_file_text(path: str) -> str:
    p = Path(path)
    if not p.exists():
        return f"[File not found]\n{path}"
    for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try: return p.read_text(encoding=enc)
        except Exception: pass
    return p.read_text(errors="replace")

def display_input_label(label: str) -> str:
    raw = label[len("SOURCE:"):] if label.startswith("SOURCE:") else label
    return f"Input\n{short_text(raw, 110)}"

def display_output_label(label: str) -> str:
    if label.startswith("SINK:"): raw = label[len("SINK:"):]
    elif label.startswith("UNRESOLVED:"): raw = "UNRESOLVED\n" + label[len("UNRESOLVED:"):]
    else: raw = label
    return f"Output\n{short_text(raw, 110)}"

# ─────────────────────────────────────────────────────────────
# Migration score (v3: reads from v10 JSON; falls back to v2 calc)
# ─────────────────────────────────────────────────────────────

EASY_FRIENDLY = {"grok":6,"date":6,"json":5,"csv":4,"dissect":6,"kv":5,"mutate":5,"urldecode":4,"split":3}
MEDIUM_FRIENDLY = {"translate":-8,"geoip":-5,"useragent":-5,"fingerprint":-4,"xml":-8,"syslog_pri":-3,"dns":-6}
HARD_BLOCKERS = {"ruby":-30,"aggregate":-35,"elapsed":-25,"clone":-12,"metrics":-20,"http":-10,"elasticsearch":-10,"jdbc_streaming":-18,"memcached":-20,"cipher":-15}

def compute_migration_score_v2(row: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback migration scoring used when loading v9/v10 JSON (no 'migration' key)."""
    score = 100
    reasons: List[str] = []
    procs: Dict[str, int] = row.get("local_processors", {}) or {}
    for name, weight in EASY_FRIENDLY.items():
        if name in procs: score += min(8, weight + max(0, procs[name] // 50)); reasons.append(f"ingest-friendly: {name}")
    for name, penalty in MEDIUM_FRIENDLY.items():
        if name in procs: score += penalty; reasons.append(f"needs care: {name}")
    for name, penalty in HARD_BLOCKERS.items():
        if name in procs: score += penalty; reasons.append(f"hard blocker: {name}")
    score = max(0, min(100, score))
    migration_class = "Easy" if score >= 75 else "Medium" if score >= 45 else "Hard"
    return {
        "score": score,
        "full_replacement_score": score,
        "filter_transform_score": score,
        "migration_class": migration_class,
        "pipeline_label": migration_class,
        "reasons": reasons,
        "recommendations": [],
        "penalties": {},
        "input_blockers": [],
    }

def get_migration(row: Dict[str, Any]) -> Dict[str, Any]:
    """Return migration dict — prefers v11 embedded data, falls back to v2 calc."""
    if "migration" in row and isinstance(row["migration"], dict):
        m = dict(row["migration"])
        # Ensure both score fields exist (v10 JSON only has 'score')
        if "full_replacement_score" not in m:
            m["full_replacement_score"] = m.get("score", 0)
        if "filter_transform_score" not in m:
            m["filter_transform_score"] = m.get("score", 0)
        if "input_blockers" not in m:
            m["input_blockers"] = []
        return m
    return compute_migration_score_v2(row)

def enrich_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for row in rows:
        enriched = dict(row)
        mig = get_migration(row)
        enriched["_mig"] = mig
        enriched["migration_score"]        = mig.get("full_replacement_score", mig.get("score", row.get("migration_score", 0)))
        enriched["filter_transform_score"] = mig.get("filter_transform_score", mig.get("score", 0))
        enriched["full_replacement_score"] = mig.get("full_replacement_score", mig.get("score", 0))
        enriched["migration_class"]        = mig.get("migration_class", row.get("migration_class", ""))
        enriched["pipeline_label"]         = mig.get("pipeline_label", row.get("pipeline_label", ""))
        enriched["migration_reasons"]      = mig.get("reasons", row.get("migration_reasons", []))
        enriched["input_blockers"]         = mig.get("input_blockers", row.get("input_blockers", []))
        out.append(enriched)
    return out

# ─────────────────────────────────────────────────────────────
# Config text extraction (fixed brace-balanced scanner)
# ─────────────────────────────────────────────────────────────

def extract_named_blocks(text: str, block_name: str) -> List[str]:
    """
    Find all top-level occurrences of 'block_name { ... }' using a
    brace-balanced scanner that correctly handles nested blocks and strings.
    This replaces the v2 version which missed blocks in some files.
    """
    out: List[str] = []
    lower = block_name.lower()
    L = len(text)
    i = 0
    while i < L:
        idx = text.lower().find(lower, i)
        if idx == -1: break
        end_name = idx + len(lower)
        # Word boundary check
        before_ok = idx == 0 or not (text[idx-1].isalnum() or text[idx-1] == "_")
        after_ok  = end_name >= L or not (text[end_name].isalnum() or text[end_name] == "_")
        if not (before_ok and after_ok): i = idx + 1; continue

        # Skip whitespace to find opening brace
        j = end_name
        while j < L and text[j] in (" ", "\t", "\n", "\r"): j += 1
        if j >= L or text[j] != "{": i = idx + 1; continue

        # Brace-balanced scan
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
            out.append(text[idx:end].strip()); i = end
        else:
            i = idx + 1
    return out

def find_plugin_block_ranges(text: str, plugin_names: List[str]) -> List[Tuple[int, int, str]]:
    """Find (start, end, plugin_name) for each plugin block in text."""
    ranges: List[Tuple[int, int, str]] = []
    L = len(text)
    for plugin in plugin_names:
        patt = re.compile(rf'(?im)\b{re.escape(plugin)}\s*\{{')
        for m in patt.finditer(text):
            start = m.start()
            brace_pos = text.find("{", m.start())
            if brace_pos == -1: continue
            depth = 0; in_str = False; quote = ""; escaped = False; end = None
            for i in range(brace_pos, L):
                ch = text[i]
                if escaped: escaped = False; continue
                if ch == "\\": escaped = True; continue
                if in_str:
                    if ch == quote: in_str = False; quote = ""
                    continue
                if ch in ("'", '"'): in_str = True; quote = ch; continue
                if ch == "{": depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0: end = i + 1; break
            if end is not None: ranges.append((start, end, plugin))
    ranges.sort(key=lambda x: x[0])
    return ranges

def offset_to_tk_index(text: str, offset: int) -> str:
    before = text[:offset]
    line = before.count("\n") + 1
    last_nl = before.rfind("\n")
    col = offset if last_nl == -1 else offset - last_nl - 1
    return f"{line}.{col}"

# ─────────────────────────────────────────────────────────────
# Build pipeline node text
# ─────────────────────────────────────────────────────────────

def build_pipeline_node_text(row: Dict[str, Any]) -> str:
    pipeline = row.get("pipeline", "")
    procs = row.get("local_processors", {}) or {}
    proc_lines = sorted(f"{k}:{v}" for k, v in procs.items())
    if len(proc_lines) > 4: proc_lines = proc_lines[:4] + [f"(+{len(procs)-4} more)"]
    proc_text = "\n".join(proc_lines) if proc_lines else "-"
    mig = row.get("_mig") or get_migration(row)
    mig_class = mig.get("migration_class", "")
    full_score   = mig.get("full_replacement_score", mig.get("score", ""))
    filter_score = mig.get("filter_transform_score", mig.get("score", ""))
    label = mig.get("pipeline_label", "")
    # Show gap warning when filter is easy but full replacement is hard
    gap = int(filter_score or 0) - int(full_score or 0)
    score_line = f"full:{full_score} filt:{filter_score}"
    if gap >= 20:
        score_line += f" ⚠gap:{gap:+d}"
    return (
        f"{short_text(pipeline, 36)}\n{proc_text}\n"
        f"stmts:{row.get('total_statements',0)}  cmpx:{row.get('total_score',0)}\n"
        f"{mig_class}  {score_line}\n{short_text(label, 34)}"
    )

# ─────────────────────────────────────────────────────────────
# FlowViewer  (v3)
# ─────────────────────────────────────────────────────────────

class FlowViewer(tk.Toplevel):
    def __init__(self, master: tk.Tk, data: Dict[str, Any], pipeline_name: str):
        super().__init__(master)
        self.data = data
        self.pipeline_name = pipeline_name
        self.row = get_pipeline_row(data, pipeline_name)
        if not self.row: raise ValueError(f"Pipeline not found: {pipeline_name}")
        self.mig = get_migration(self.row)
        self._scale = 1.0
        self._pan_x = 0.0
        self._pan_y = 0.0
        self._drag_start: Optional[Tuple[int, int]] = None
        self._tooltip_window: Optional[tk.Toplevel] = None
        self._highlight_ranges: List[Tuple[int, int, str]] = []

        mc = self.mig.get("migration_class", "Easy")
        col = MIG_NODE_COLORS.get(mc, MIG_NODE_COLORS["Easy"])

        self.title(f"Logstash Flow Viewer — {pipeline_name}  [{mc}]")
        self.geometry("1620x950")
        self.configure(bg=col["fill"])

        # ── Top bar ─────────────────────────────────────
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=4)
        summary = (
            f"{pipeline_name}    stmts:{self.row.get('total_statements',0)}"
            f"    complexity:{self.row.get('total_score',0)}"
            f"    migration:{self.mig.get('score',0)} ({mc})"
        )
        ttk.Label(top, text=summary, font=("Segoe UI", 10, "bold")).pack(side="left")
        ttk.Button(top, text="⌂ Reset view", command=self._reset_view).pack(side="right", padx=4)
        ttk.Button(top, text="Redraw",        command=self.draw).pack(side="right", padx=4)

        # ── Body split ───────────────────────────────────
        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True)

        # Left: canvas
        left = ttk.Frame(body)
        body.add(left, weight=4)
        canvas_frame = ttk.Frame(left)
        canvas_frame.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(canvas_frame, bg="white", cursor="crosshair")
        hbar = ttk.Scrollbar(canvas_frame, orient="horizontal", command=self.canvas.xview)
        vbar = ttk.Scrollbar(canvas_frame, orient="vertical",   command=self.canvas.yview)
        self.canvas.configure(xscrollcommand=hbar.set, yscrollcommand=vbar.set)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vbar.grid(row=0, column=1, sticky="ns")
        hbar.grid(row=1, column=0, sticky="ew")
        canvas_frame.rowconfigure(0, weight=1); canvas_frame.columnconfigure(0, weight=1)
        # Zoom / pan bindings
        self.canvas.bind("<MouseWheel>",       self._on_mousewheel)
        self.canvas.bind("<Button-4>",         lambda e: self._zoom(1.1, e))
        self.canvas.bind("<Button-5>",         lambda e: self._zoom(0.9, e))
        self.canvas.bind("<ButtonPress-2>",    self._pan_start)
        self.canvas.bind("<B2-Motion>",        self._pan_move)
        self.canvas.bind("<ButtonPress-3>",    self._pan_start)
        self.canvas.bind("<B3-Motion>",        self._pan_move)
        self.bind("<Home>",                    lambda e: self._reset_view())
        self.bind("<plus>",  lambda e: self._zoom(1.15))
        self.bind("<minus>", lambda e: self._zoom(0.87))

        # Right: tabbed detail pane
        right = ttk.Frame(body, width=460)
        body.add(right, weight=2)

        ttk.Label(right, text="Node Details", font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=8, pady=(8,2))
        self.detail = tk.Text(right, wrap="word", height=14, font=("Consolas", 9))
        self.detail.pack(fill="x", padx=8, pady=(0,4))
        self.detail.configure(state="disabled")

        nb = ttk.Notebook(right)
        nb.pack(fill="both", expand=True, padx=8, pady=(0,8))

        config_frame = ttk.Frame(nb)
        rec_frame    = ttk.Frame(nb)
        nb.add(config_frame, text="Config")
        nb.add(rec_frame,    text="Recommendations")

        self.config_text = tk.Text(config_frame, wrap="none", font=("Consolas", 9))
        cscroll = ttk.Scrollbar(config_frame, orient="vertical", command=self.config_text.yview)
        self.config_text.configure(yscrollcommand=cscroll.set)
        self.config_text.pack(side="left", fill="both", expand=True)
        cscroll.pack(side="right", fill="y")
        self.config_text.tag_configure("hard_migration",   background=TIER_COLORS["hard"]["bg"],   foreground=TIER_COLORS["hard"]["fg"])
        self.config_text.tag_configure("medium_migration", background=TIER_COLORS["medium"]["bg"], foreground=TIER_COLORS["medium"]["fg"])
        self.config_text.bind("<Motion>",  self._on_config_hover)
        self.config_text.bind("<Leave>",   lambda e: self._hide_tooltip())
        self.config_text.configure(state="disabled")

        self.rec_text = tk.Text(rec_frame, wrap="word", font=("Segoe UI", 9))
        rscroll = ttk.Scrollbar(rec_frame, orient="vertical", command=self.rec_text.yview)
        self.rec_text.configure(yscrollcommand=rscroll.set)
        self.rec_text.pack(side="left", fill="both", expand=True)
        rscroll.pack(side="right", fill="y")
        self.rec_text.configure(state="disabled")

        self.draw()
        self._populate_recommendations()

    # ── Zoom / pan ─────────────────────────────────────────

    def _on_mousewheel(self, event):
        factor = 1.1 if event.delta > 0 else 0.9
        self._zoom(factor, event)

    def _zoom(self, factor: float, event=None):
        self._scale = max(0.2, min(4.0, self._scale * factor))
        cx = event.x if event else CANVAS_W // 2
        cy = event.y if event else CANVAS_H // 2
        self.canvas.scale("all", cx, cy, factor, factor)
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _pan_start(self, event):
        self._drag_start = (event.x, event.y)

    def _pan_move(self, event):
        if self._drag_start:
            dx = event.x - self._drag_start[0]
            dy = event.y - self._drag_start[1]
            self.canvas.move("all", dx, dy)
            self._drag_start = (event.x, event.y)
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _reset_view(self):
        self._scale = 1.0
        self.draw()

    # ── Tooltip ────────────────────────────────────────────

    def _on_config_hover(self, event):
        idx = self.config_text.index(f"@{event.x},{event.y}")
        for (start, end, plugin) in self._highlight_ranges:
            si = offset_to_tk_index(self._config_raw_text, start)
            ei = offset_to_tk_index(self._config_raw_text, end)
            if self.config_text.compare(idx, ">=", si) and self.config_text.compare(idx, "<", ei):
                tip = PLUGIN_EXPLANATIONS.get(plugin, (None, None))[1]
                if tip: self._show_tooltip(event, tip); return
        self._hide_tooltip()

    def _show_tooltip(self, event, text: str):
        self._hide_tooltip()
        win = tk.Toplevel(self)
        win.wm_overrideredirect(True)
        win.wm_geometry(f"+{event.x_root+12}+{event.y_root+12}")
        lbl = tk.Label(win, text=text, justify="left", relief="solid", borderwidth=1,
                       bg="#fffff0", font=("Segoe UI", 9), wraplength=380, padx=6, pady=4)
        lbl.pack()
        self._tooltip_window = win

    def _hide_tooltip(self):
        if self._tooltip_window:
            self._tooltip_window.destroy()
            self._tooltip_window = None

    # ── Config panel ───────────────────────────────────────

    def get_primary_file(self) -> Optional[str]:
        files = self.row.get("files", []) or []
        return files[0] if files else None

    def get_section_text(self, section: str) -> str:
        file_path = self.get_primary_file()
        if not file_path: return "[No source file path found in analyzer JSON]"
        text = read_file_text(file_path)
        blocks = extract_named_blocks(text, section)
        if not blocks:
            # Fallback: try the full file if no labelled section found
            if section == "filter":
                # Show full file with note
                return f"File: {file_path}\n[filter block not found — showing full file]\n\n{text}"
            return f"[No {section} block found]\n\nFile: {file_path}"
        header = f"File: {file_path}\nSection: {section}  ({len(blocks)} block(s) found)\n{'─'*60}\n\n"
        joined = ("\n\n" + "─"*60 + "\n\n").join(blocks)
        return header + joined

    def set_detail(self, title: str, payload: Dict[str, Any]):
        self.detail.configure(state="normal")
        self.detail.delete("1.0", tk.END)
        self.detail.insert(tk.END, f"{'─'*36}\n{title}\n{'─'*36}\n")
        skip = {"type", "node_name", "file"}
        for k, v in payload.items():
            if k in skip: continue
            self.detail.insert(tk.END, f"{k}: {v}\n")
        self.detail.configure(state="disabled")

    def set_config_text(self, text: str, section_type: str = ""):
        self._config_raw_text = text
        self._highlight_ranges = []
        self.config_text.configure(state="normal")
        self.config_text.delete("1.0", tk.END)
        self.config_text.insert(tk.END, text)
        self.config_text.tag_remove("hard_migration",   "1.0", tk.END)
        self.config_text.tag_remove("medium_migration", "1.0", tk.END)

        if section_type == "filter":
            procs = set((self.row.get("local_processors", {}) or {}).keys())
            hard_plugins   = [p for p in PLUGIN_EXPLANATIONS if PLUGIN_EXPLANATIONS[p][0] == "hard"   and p in procs]
            medium_plugins = [p for p in PLUGIN_EXPLANATIONS if PLUGIN_EXPLANATIONS[p][0] == "medium" and p in procs]
            all_flagged = hard_plugins + medium_plugins
            ranges = find_plugin_block_ranges(text, all_flagged)
            self._highlight_ranges = ranges
            for start, end, plugin in ranges:
                tier = PLUGIN_EXPLANATIONS.get(plugin, ("medium",))[0]
                tag = "hard_migration" if tier == "hard" else "medium_migration"
                self.config_text.tag_add(tag, offset_to_tk_index(text, start), offset_to_tk_index(text, end))

        self.config_text.configure(state="disabled")

    def on_box_click(self, node_name: str, payload: Dict[str, Any]):
        self.set_detail(node_name, payload)
        node_type = payload.get("type")
        if node_type == "input":
            self.set_config_text(self.get_section_text("input"), "input")
        elif node_type == "pipeline":
            self.set_config_text(self.get_section_text("filter"), "filter")
        elif node_type == "output":
            self.set_config_text(self.get_section_text("output"), "output")

    # ── Canvas drawing ─────────────────────────────────────

    def draw_box(self, x, y, display_text: str, fill: str, outline: str, text_color: str, payload: Dict[str, Any], bold: bool = False):
        font = ("Segoe UI", 10, "bold") if bold else ("Segoe UI", 10)
        x2, y2 = x + BOX_W, y + BOX_H
        rect = self.canvas.create_rectangle(x, y, x2, y2, fill=fill, outline=outline, width=2)
        txt  = self.canvas.create_text(x + BOX_W/2, y + BOX_H/2, text=display_text,
                                        width=BOX_W - 14, font=font, justify="center",
                                        fill=text_color)
        for tag in (rect, txt):
            self.canvas.tag_bind(tag, "<Button-1>",
                                 lambda e, p=payload: self.on_box_click(p.get("node_name",""), p))

    def draw_arrow(self, x1, y1, x2, y2):
        self.canvas.create_line(x1, y1, x2, y2, arrow=tk.LAST, width=2, smooth=False)

    def draw(self):
        self.canvas.delete("all")
        row = self.row
        pipeline_name = row.get("pipeline", "")
        mig = self._mig_col()

        input_sources = unique_preserve(row.get("input_sources", []) or [])
        flow_paths    = row.get("flow_chains", []) or []

        sinks = []
        for path in flow_paths:
            if path:
                last = path[-1]
                if last.startswith("SINK:") or last.startswith("UNRESOLVED:"): sinks.append(last)
        explicit_sinks = unique_preserve(row.get("terminal_sinks", []) or [])
        sinks = unique_preserve(explicit_sinks + sinks)

        if not input_sources:
            for path in flow_paths:
                if path and path[0].startswith("SOURCE:"): input_sources.append(path[0])
            input_sources = unique_preserve(input_sources)

        source_nodes = input_sources or ["SOURCE:?"]
        sink_nodes   = sinks or ["UNRESOLVED:?"]

        max_rows = max(len(source_nodes), len(sink_nodes), 1)
        total_h = TOP_Y + max_rows * (BOX_H + V_SPACING) + 80
        self.canvas.configure(scrollregion=(0, 0, CANVAS_W, max(total_h, CANVAS_H)))

        self.canvas.create_text(COL_X[0]+BOX_W/2, 30, text="Inputs",           font=("Segoe UI", 11, "bold"))
        self.canvas.create_text(COL_X[1]+BOX_W/2, 30, text="Pipeline / Filters",font=("Segoe UI", 11, "bold"))
        self.canvas.create_text(COL_X[2]+BOX_W/2, 30, text="Outputs",           font=("Segoe UI", 11, "bold"))

        source_positions = {}
        for idx, src in enumerate(source_nodes):
            y = TOP_Y + idx * (BOX_H + V_SPACING)
            source_positions[src] = (COL_X[0], y)
            payload = {"type": "input", "node_name": src, "input": src, "file": self.get_primary_file() or "-"}
            self.draw_box(COL_X[0], y, display_input_label(src),
                          "#dff3ff", "#2c7fb8", "#003050", payload)

        mid_y = TOP_Y + max(0, (max_rows-1) * (BOX_H + V_SPACING) / 2)
        pipeline_pos = (COL_X[1], int(mid_y))
        pipeline_payload = {
            "type": "pipeline", "node_name": pipeline_name,
            "migration_class":    mig["migration_class"],
            "migration_score":    mig["score"],
            "pipeline_label":     mig.get("pipeline_label", ""),
            "migration_reasons":  "; ".join(mig.get("reasons", [])),
            "total_statements":   row.get("total_statements", 0),
            "complexity_score":   row.get("total_score", 0),
            "local_processors":   str(sorted((row.get("local_processors",{}) or {}).keys())),
        }
        mc = mig.get("migration_class", "Easy")
        nc = MIG_NODE_COLORS.get(mc, MIG_NODE_COLORS["Easy"])
        self.draw_box(COL_X[1], pipeline_pos[1], build_pipeline_node_text(row),
                      nc["fill"], nc["outline"], nc["text"], pipeline_payload, bold=True)

        sink_positions = {}
        for idx, sink in enumerate(sink_nodes):
            y = TOP_Y + idx * (BOX_H + V_SPACING)
            sink_positions[sink] = (COL_X[2], y)
            if sink.startswith("UNRESOLVED:"):
                fill, outline, tc = "#ffe4e1", "#cb181d", "#5a0000"
            else:
                fill, outline, tc = "#e7f7df", "#2ca25f", "#004000"
            payload = {"type": "output", "node_name": sink, "output": sink, "file": self.get_primary_file() or "-"}
            self.draw_box(COL_X[2], y, display_output_label(sink), fill, outline, tc, payload)

        for src, (sx, sy) in source_positions.items():
            self.draw_arrow(sx+BOX_W, sy+BOX_H/2, pipeline_pos[0], pipeline_pos[1]+BOX_H/2)
        for sink, (tx, ty) in sink_positions.items():
            self.draw_arrow(pipeline_pos[0]+BOX_W, pipeline_pos[1]+BOX_H/2, tx, ty+BOX_H/2)

        # Show initial detail + filter config
        full_score   = mig.get("full_replacement_score", mig.get("score", ""))
        filter_score = mig.get("filter_transform_score", mig.get("score", ""))
        self.set_detail(pipeline_name, {
            "file":                   self.get_primary_file() or "-",
            "migration_class":        mc,
            "full_replacement_score": f"{full_score}/100  (end-to-end replacement ease)",
            "filter_transform_score": f"{filter_score}/100  (filter logic migration ease)",
            "pipeline_label":         mig.get("pipeline_label",""),
            "complexity":             row.get("total_score",0),
            "statements":             row.get("total_statements",0),
            "filter_reasons":         " | ".join(mig.get("reasons",[])[:3]) or "-",
            "input_blockers":         " | ".join(mig.get("input_blockers",[])[:2]) or "(none)",
        })
        self.set_config_text(self.get_section_text("filter"), "filter")

    def _mig_col(self) -> Dict[str, Any]:
        return self.mig

    # ── Recommendations panel ──────────────────────────────

    def _populate_recommendations(self):
        recs = self.mig.get("recommendations", [])
        self.rec_text.configure(state="normal")
        self.rec_text.delete("1.0", tk.END)
        mc = self.mig.get("migration_class", "Easy")
        full_score   = self.mig.get("full_replacement_score", self.mig.get("score", 0))
        filter_score = self.mig.get("filter_transform_score", self.mig.get("score", 0))
        gap = int(filter_score or 0) - int(full_score or 0)

        self.rec_text.insert(tk.END, f"Migration class: {mc}\n")
        self.rec_text.insert(tk.END, f"Filter transform ease:     {filter_score}/100\n")
        self.rec_text.insert(tk.END,  "  (Can the filter logic move to an ingest pipeline?)\n\n")
        self.rec_text.insert(tk.END, f"Full replacement ease:     {full_score}/100\n")
        self.rec_text.insert(tk.END,  "  (Can the entire pipeline be replaced by Elastic Agent + ingest?)\n\n")

        if gap >= 20:
            self.rec_text.insert(tk.END,
                f"⚠  Score gap: {gap:+d} points\n"
                "   The filter logic is easier to migrate than the pipeline as a whole.\n"
                "   The input source requires a separate replacement strategy.\n\n"
            )

        input_blockers = self.mig.get("input_blockers", [])
        if input_blockers:
            self.rec_text.insert(tk.END, "── Input / End-to-End Blockers ──\n\n")
            for b in input_blockers:
                self.rec_text.insert(tk.END, f"  ⛔ {b}\n\n")

        if recs:
            self.rec_text.insert(tk.END, "── Recommendations ──\n\n")
            for r in recs:
                self.rec_text.insert(tk.END, f"  • {r}\n\n")
        else:
            self.rec_text.insert(tk.END, "  ✓ No hard blockers — likely a good ingest candidate.\n")

        reasons = self.mig.get("reasons", [])
        if reasons:
            self.rec_text.insert(tk.END, "\n── Filter Analysis Notes ──\n\n")
            for r in reasons:
                self.rec_text.insert(tk.END, f"  – {r}\n")

        self.rec_text.configure(state="disabled")

# ─────────────────────────────────────────────────────────────
# PipelineBrowser  (v3)
# ─────────────────────────────────────────────────────────────

class PipelineBrowser(tk.Tk):
    def __init__(self, data: Dict[str, Any]):
        super().__init__()
        self.data  = data
        self.title("Logstash Pipeline Browser v4")
        self.geometry("1680x960")

        self.rows = enrich_rows(get_pipeline_rows(data))
        self.filtered_rows: List[Dict[str, Any]] = []

        # ── Filter bar ───────────────────────────────────
        top = ttk.Frame(self)
        top.pack(fill="x", padx=8, pady=6)

        self.search_var    = tk.StringVar()
        self.proc_var      = tk.StringVar()
        self.input_var     = tk.StringVar()
        self.output_var    = tk.StringVar()
        self.min_score_var = tk.StringVar(value="0")
        self.mig_class_var = tk.StringVar(value="All")
        self.label_var     = tk.StringVar(value="All")

        r1 = ttk.Frame(top); r1.pack(fill="x", pady=2)
        def lbl_entry(parent, label, var, width=18):
            ttk.Label(parent, text=label).pack(side="left")
            ttk.Entry(parent, textvariable=var, width=width).pack(side="left", padx=(4,12))
        lbl_entry(r1, "Search",    self.search_var, 28)
        lbl_entry(r1, "Processor", self.proc_var)
        lbl_entry(r1, "Input",     self.input_var)
        lbl_entry(r1, "Output",    self.output_var)
        ttk.Button(r1, text="Apply", command=self.refresh_table).pack(side="left", padx=(8,4))
        ttk.Button(r1, text="Reset", command=self.reset_filters).pack(side="left")

        r2 = ttk.Frame(top); r2.pack(fill="x", pady=2)
        ttk.Label(r2, text="Min Complexity").pack(side="left")
        ttk.Entry(r2, textvariable=self.min_score_var, width=8).pack(side="left", padx=(4,12))
        ttk.Label(r2, text="Migration Class").pack(side="left")
        ttk.Combobox(r2, textvariable=self.mig_class_var,
                     values=["All","Easy","Medium","Hard"], width=10, state="readonly").pack(side="left", padx=(4,12))
        ttk.Label(r2, text="Label").pack(side="left")
        label_options = ["All",
                         "Simple ingest candidate",
                         "Needs attention – medium blockers",
                         "Requires redesign – hard blockers",
                         "Multi-output complex pipeline",
                         "Heavy transformation pipeline",
                         "JDBC polling pipeline – requires alternative ingestion strategy",
                         "JDBC input – filter may migrate to ingest; input cannot",
                         "Input not replaceable by Elastic Agent – redesign data pipeline"]
        ttk.Combobox(r2, textvariable=self.label_var,
                     values=label_options, width=46, state="readonly").pack(side="left", padx=(4,12))
        ttk.Button(r2, text="Open Selected",   command=self.open_selected).pack(side="left", padx=(8,4))
        ttk.Button(r2, text="Open Top Result", command=self.open_top_result).pack(side="left")

        # ── Table + preview split ─────────────────────────
        main = ttk.Panedwindow(self, orient="vertical")
        main.pack(fill="both", expand=True)
        upper = ttk.Frame(main)
        lower = ttk.Frame(main)
        main.add(upper, weight=4)
        main.add(lower, weight=1)

        cols = ("pipeline","complexity","full_repl","filt_xfrm","mig_class","label","statements","inputs","processors")
        self.tree = ttk.Treeview(upper, columns=cols, show="headings")
        headings = {
            "pipeline":    "Pipeline",
            "complexity":  "Complexity",
            "full_repl":   "Full Repl",
            "filt_xfrm":   "Filt Xfrm",
            "mig_class":   "Class",
            "label":       "Label",
            "statements":  "Stmts",
            "inputs":      "Inputs",
            "processors":  "Processors",
        }
        widths = {
            "pipeline":    280,
            "complexity":  80,
            "full_repl":   70,
            "filt_xfrm":   70,
            "mig_class":   65,
            "label":       240,
            "statements":  55,
            "inputs":      170,
            "processors":  250,
        }
        for c in cols:
            self.tree.heading(c, text=headings[c], command=lambda cc=c: self.sort_by(cc, False))
            self.tree.column(c, width=widths[c], anchor="w")

        # Row tags for color coding
        self.tree.tag_configure("Easy",   background="#e8ffe8")
        self.tree.tag_configure("Medium", background="#fffbe6")
        self.tree.tag_configure("Hard",   background="#ffe6e6")
        # Special tag for JDBC gap pipelines — amber stripe
        self.tree.tag_configure("JDBCgap", background="#ffe8c0")

        yscroll = ttk.Scrollbar(upper, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>",          self.open_selected)
        self.tree.bind("<<TreeviewSelect>>",  self.show_preview)

        ttk.Label(lower, text="Preview", font=("Segoe UI",9,"bold")).pack(anchor="w", padx=8, pady=(8,4))
        self.preview = tk.Text(lower, wrap="word", height=12, font=("Segoe UI",9))
        self.preview.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.preview.configure(state="disabled")

        for var in (self.search_var, self.proc_var, self.input_var, self.output_var,
                    self.min_score_var, self.mig_class_var, self.label_var):
            var.trace_add("write", lambda *a: self.refresh_table())

        self.refresh_table()

    def reset_filters(self):
        self.search_var.set(""); self.proc_var.set(""); self.input_var.set("")
        self.output_var.set(""); self.min_score_var.set("0")
        self.mig_class_var.set("All"); self.label_var.set("All")

    def row_matches(self, row: Dict[str, Any]) -> bool:
        search = self.search_var.get().strip().lower()
        proc   = self.proc_var.get().strip().lower()
        inp    = self.input_var.get().strip().lower()
        outp   = self.output_var.get().strip().lower()
        mc     = self.mig_class_var.get().strip()
        lbl    = self.label_var.get().strip()
        try: min_score = int(self.min_score_var.get().strip() or "0")
        except ValueError: min_score = 0

        if int(row.get("total_score", 0) or 0) < min_score: return False
        if mc != "All" and row.get("migration_class") != mc: return False
        if lbl != "All" and row.get("pipeline_label", "") != lbl: return False

        proc_names = " ".join(sorted((row.get("local_processors",{}) or {}).keys())).lower()
        inputs  = " ".join(row.get("input_sources",[]) or []).lower()
        outputs = " ".join(row.get("terminal_sinks", []) or []).lower()
        blob = " | ".join([
            row.get("pipeline",""), proc_names, inputs, outputs,
            " ".join(row.get("files",[]) or []),
            " ".join(row.get("flags",[]) or []),
            row.get("migration_class",""), row.get("pipeline_label",""),
            " ".join(row.get("migration_reasons",[]) or []),
        ]).lower()

        if search and search not in blob: return False
        if proc   and proc   not in proc_names: return False
        if inp    and inp    not in inputs: return False
        if outp   and outp   not in outputs: return False
        return True

    def _insert_row(self, row: Dict[str, Any]):
        procs = sorted((row.get("local_processors",{}) or {}).keys())
        proc_text = ", ".join(procs[:5]) + (", ..." if len(procs)>5 else "")
        mc_tag = row.get("migration_class","")
        full_score   = int(row.get("full_replacement_score", row.get("migration_score", 0)) or 0)
        filter_score = int(row.get("filter_transform_score", full_score) or 0)
        gap = filter_score - full_score
        # Amber override: filter easy but full hard (JDBC gap)
        tag = "JDBCgap" if gap >= 20 else mc_tag
        self.tree.insert("","end", iid=row["pipeline"], tags=(tag,), values=(
            row["pipeline"],
            row.get("total_score",0),
            full_score,
            filter_score,
            row.get("migration_class",""),
            short_text(row.get("pipeline_label",""),50),
            row.get("total_statements",0),
            short_text(", ".join(row.get("input_sources",[]) or []),38),
            proc_text,
        ))

    def refresh_table(self):
        self.filtered_rows = [r for r in self.rows if self.row_matches(r)]
        for item in self.tree.get_children(): self.tree.delete(item)
        for row in self.filtered_rows:
            self._insert_row(row)
        if self.filtered_rows:
            first = self.filtered_rows[0]["pipeline"]
            self.tree.selection_set(first); self.tree.focus(first); self.show_preview()

    def sort_by(self, column: str, descending: bool):
        mapping = {
            "pipeline":   lambda r: r.get("pipeline",""),
            "complexity": lambda r: int(r.get("total_score",0) or 0),
            "full_repl":  lambda r: int(r.get("full_replacement_score", r.get("migration_score",0)) or 0),
            "filt_xfrm":  lambda r: int(r.get("filter_transform_score", 0) or 0),
            "mig_class":  lambda r: r.get("migration_class",""),
            "label":      lambda r: r.get("pipeline_label",""),
            "statements": lambda r: int(r.get("total_statements",0) or 0),
            "inputs":     lambda r: ",".join(r.get("input_sources",[]) or []),
            "processors": lambda r: ",".join(sorted((r.get("local_processors",{}) or {}).keys())),
        }
        self.filtered_rows.sort(key=mapping.get(column, lambda r: ""), reverse=descending)
        for item in self.tree.get_children(): self.tree.delete(item)
        for row in self.filtered_rows:
            self._insert_row(row)
        self.tree.heading(column, command=lambda: self.sort_by(column, not descending))

    def get_selected_row(self) -> Optional[Dict[str, Any]]:
        sel = self.tree.selection()
        if not sel: return None
        pipeline = sel[0]
        for row in self.filtered_rows:
            if row.get("pipeline") == pipeline: return row
        return None

    def show_preview(self, event=None):
        row = self.get_selected_row()
        self.preview.configure(state="normal")
        self.preview.delete("1.0", tk.END)
        if not row: self.preview.insert("1.0","No selection."); self.preview.configure(state="disabled"); return

        mig = row.get("_mig") or get_migration(row)
        full_score   = mig.get("full_replacement_score", mig.get("score", 0))
        filter_score = mig.get("filter_transform_score", mig.get("score", 0))
        gap = int(filter_score or 0) - int(full_score or 0)

        lines = [
            f"Pipeline:              {row.get('pipeline')}",
            f"Label:                 {row.get('pipeline_label','')}",
            f"Class:                 {row.get('migration_class','')}",
            f"Full replacement ease: {full_score}/100  ← end-to-end (Elastic Agent + ingest)",
            f"Filter transform ease: {filter_score}/100  ← filter logic only (ingest pipeline)",
        ]
        if gap >= 20:
            lines.append(f"⚠  Score gap {gap:+d}: filters are easier than the full pipeline suggests.")
            lines.append("   The input source cannot be replaced by an ingest pipeline alone.")

        lines += [
            f"Complexity:            {row.get('total_score',0)}",
            f"Statements:            {row.get('total_statements',0)}",
            f"Inputs:                {', '.join(row.get('input_sources',[]) or ['-'])}",
            f"Outputs:               {', '.join(row.get('terminal_sinks',[]) or ['-'])}",
            f"Flags:                 {', '.join(row.get('flags',[]) or ['-'])}",
            "",
            "Local processors:",
        ]
        lp = row.get("local_processors",{}) or {}
        lines += [f"  {k}: {lp[k]}" for k in sorted(lp)] if lp else ["  -"]

        input_blockers = mig.get("input_blockers",[]) or []
        if input_blockers:
            lines += ["", "Input / end-to-end blockers:"]
            lines += [f"  ⛔ {b[:90]}" for b in input_blockers[:3]]

        reasons = mig.get("reasons",[]) or []
        if reasons:
            lines += ["", "Filter migration notes:"]
            lines += [f"  – {r}" for r in reasons[:5]]

        recs = mig.get("recommendations",[]) or []
        if recs:
            lines += ["", "Recommendations:"]
            lines += [f"  • {r}" for r in recs[:4]]

        self.preview.insert("1.0", "\n".join(lines))
        self.preview.configure(state="disabled")

    def open_selected(self, event=None):
        row = self.get_selected_row()
        if not row: messagebox.showinfo("No selection","Please select a pipeline."); return
        FlowViewer(self, self.data, row["pipeline"])

    def open_top_result(self):
        if not self.filtered_rows: return
        FlowViewer(self, self.data, self.filtered_rows[0]["pipeline"])

# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Logstash Pipeline Browser v4 (dual-score JDBC-aware)")
    ap.add_argument("json_file", help="Path to analyzer JSON output (v9, v10, or v11)")
    args = ap.parse_args()
    data = load_json(Path(args.json_file))
    app = PipelineBrowser(data)
    app.mainloop()

if __name__ == "__main__":
    main()
