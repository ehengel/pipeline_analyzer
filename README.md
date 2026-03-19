# Logstash → Elasticsearch Ingest Migration Toolchain

A Python toolkit for analysing, planning, and executing the migration of Logstash pipelines to Elasticsearch ingest pipelines.


---

## Tools

### 1. `logstash_pipeline_analyzer.py` — Stage 1: Analysis

Parses all `.conf` files in a directory tree and produces a structured JSON report.

**What it does**

- Parses Logstash config files (handles multi-line, nested blocks, complex conditionals)
- Detects inputs, filters, outputs — and builds an **ordered filter tree** preserving execution order and branch structure
- Scores each pipeline with two independent scores:
  - `filter_transform_score` — how easily the filter logic migrates to ingest
  - `full_replacement_score` — how easily the entire pipeline can be replaced end-to-end (JDBC gets a hard ceiling of 30 regardless of filter simplicity)
- Classifies every processor as `supported` / `partial` / `unsupported` for ingest pipelines
- Detects `<base>_io.conf` + `<base>_filter.conf` sibling pairs and merges them as one logical pipeline
- Emits raw source text per block for downstream tools

```bash
python logstash_pipeline_analyzer.py /path/to/pipelines/ \
    --json-out analysis.json \
    --csv-out  analysis.csv
```

**Output:** `analysis.json` consumed by all other tools.

---

### 2. `logstash_ingest_transformer.py` — Stage 2+3: Transform & Plan

Converts Logstash filter sections to Elasticsearch ingest pipeline JSON, and generates a Markdown migration plan per pipeline.

**What it does**

- Translates each supported processor to its ES ingest equivalent:
  - `grok` → `grok`, `date` → `date`, `mutate` → `set/rename/remove/append` (split into sub-actions in Logstash execution order), `geoip` → `geoip`, `useragent` → `user_agent`, `kv` → `kv`, `dissect` → `dissect`, `fingerprint` → `fingerprint`, etc.
- Unsupported processors (`ruby`, `aggregate`, etc.) become valid Painless `script` stubs with TODO comments — the pipeline can be PUT to ES immediately
- Emits a **coverage score** (0–100%) and per-pipeline Markdown migration plan
- Identifies input blockers (JDBC, Kafka, etc.) and recommends replacement architectures

```bash
# Transform all pipelines
python logstash_ingest_transformer.py analysis.json --out-dir ./ingest_output/

# Preview a single pipeline
python logstash_ingest_transformer.py analysis.json --pipeline myapp --stdout

# Deploy generated pipeline
curl -X PUT 'https://elasticsearch:9200/_ingest/pipeline/myapp' \
     -H 'Content-Type: application/json' \
     -d @ingest_output/myapp.ingest.json
```

**Output per pipeline:** `<name>.ingest.json` + `<name>.plan.md` + `migration_summary.json`

---

### 3. `logstash_migration_advisor.py` — Decision support

Turns raw scores into an actionable migration plan for engineering leads and architects.

**What it does**

- **Wave assignment** — groups every pipeline into one of three waves:
  - Wave 1 (Quick wins): high filter ease, no hard blockers, low effort — migrate now
  - Wave 2 (Medium effort): partial blockers with workarounds available
  - Wave 3 (Keep/redesign): JDBC, ruby, aggregate, multi-output orchestration
- **Operational benefit score** (0–100) — weighs filter ease, complexity removed, output simplicity, pipeline centrality, and statement count to identify best ROI candidates, not just easiest migrations
- **Pattern clustering** — groups pipelines with identical processor fingerprints so a migration template solved once can be reused across a whole family
- **Structured blocker list** — classifies each blocker as `hard` / `workaround` / `decision` with specific recommendations
- **Field inventory** — extracts every field created, renamed, removed, grok-captured, and enriched across all pipelines
- **Cross-pipeline inventories** — all inputs, all outputs, and all fields used across the entire repository with per-wave counts

```bash
python logstash_migration_advisor.py analysis.json

# Filter to a specific wave
python logstash_migration_advisor.py analysis.json --wave 1

# Export full plan
python logstash_migration_advisor.py analysis.json \
    --json-out plan.json \
    --csv-out  plan.csv   # also writes plan_inputs.csv, plan_outputs.csv, plan_fields.csv
```

---

### 4. `logstash_pipeline_browser.py` — Pipeline browser (simple)

A Tkinter GUI for browsing pipelines from the analyzer JSON. Shows the pipeline flow graph, migration scores, processor details, and raw config with highlighted problem areas.

**What it does**

- Searchable, filterable pipeline list (by name, migration class)
- Flow graph canvas: boxes for each pipeline, colour-coded by migration class (green/amber/red)
- Detail panel: migration score, pipeline label, reasons, recommendations
- Config pane: raw filter block with plugin highlighting and hover tooltips explaining why each plugin is flagged
- Zoom + pan on the flow canvas

```bash
python logstash_pipeline_browser.py analysis.json
```

---

### 5. `logstash_pipeline_visualizer.py` — Processor-level visualizer (advanced)

A Kibana-style processor-level GUI that shows every filter processor as an individual node, with ingest compatibility colour-coding, side-by-side Logstash↔ingest comparison, and grok performance scoring.

**What it does**

- Shows the full processor chain — `Input → [Grok → Mutate → Date → if{ → Ruby }] → Output` — not just pipeline-level boxes
- **Horizontal and vertical layout** — toggle between left-to-right and top-to-bottom (Kibana style) with conditional branches rendering correctly in both modes
- **Colour coding on every node**: green = ingest-supported, amber = partial, red = unsupported
- **Grok performance scoring** — scores each grok block for runtime cost (pattern count × alternations × named captures × length) and displays the band (Fast / Moderate / Slow / Very Slow) directly on the canvas node as a coloured footer stripe
- **Grok score column** in the pipeline list — summed score across all groks per pipeline, sortable
- **Show Ingest JSON** — opens a side-by-side comparison window:
  - Full pipeline mode: raw Logstash source vs generated ES ingest pipeline JSON
  - Per-processor mode: individual processor raw config vs its ES equivalent
- **Three-tab detail panel** per processor: Info (with grok performance breakdown), Logstash (raw config), Ingest JSON (generated ES processor with copy button)
- Hover tooltips, zoom/pan, export to file

```bash
python logstash_pipeline_visualizer.py analysis.json

# Open directly to a specific pipeline
python logstash_pipeline_visualizer.py analysis.json --pipeline aixsyslogcef
```

> **Note:** The visualizer imports from `logstash_ingest_transformer.py` for live JSON generation. Place both files in the same directory.

---

## Workflow

```
.conf files
     │
     ▼
logstash_pipeline_analyzer.py  ──→  analysis.json
     │
     ├──→ logstash_ingest_transformer.py  ──→  <pipeline>.ingest.json
     │                                          <pipeline>.plan.md
     │
     ├──→ logstash_migration_advisor.py   ──→  plan.json / plan.csv
     │                                          plan_inputs.csv
     │                                          plan_outputs.csv
     │                                          plan_fields.csv
     │
     ├──→ logstash_pipeline_browser.py      (GUI — pipeline overview)
     │
     └──→ logstash_pipeline_visualizer.py   (GUI — processor detail)
```

---

## Requirements

```
Python 3.8+
tkinter  (stdlib, included in standard Python on Windows/macOS; on Linux: sudo apt install python3-tk)
```

No third-party packages required.

---

## Migration class definitions

| Class | Filter score | Full score | Meaning |
|---|---|---|---|
| Easy | ≥ 75 | ≥ 75 | Straightforward ingest migration |
| Medium | 45–74 | 45–74 | Some manual work or workarounds needed |
| Hard | < 45 | < 45 | Significant redesign required |

JDBC pipelines are always capped at a full replacement score of ≤ 30, regardless of how simple their filter logic is, because the input stage cannot be replaced by Elastic Agent.

---

## Ingest processor mapping

| Logstash | ES Ingest | Notes |
|---|---|---|
| `grok` | `grok` | Direct mapping |
| `dissect` | `dissect` | Direct mapping |
| `date` | `date` | Direct mapping |
| `mutate` | `set` / `rename` / `remove` / `append` / `convert` | Split into sub-actions |
| `geoip` | `geoip` | Needs MaxMind DB |
| `useragent` | `user_agent` | ES 7.11+ |
| `json` | `json` | Direct mapping |
| `kv` | `kv` | Direct mapping |
| `fingerprint` | `fingerprint` | Direct mapping |
| `urldecode` | `urldecode` | Direct mapping |
| `drop` | `drop` | Direct mapping |
| `translate` | `enrich` | Requires enrich policy setup |
| `ruby` | `script` (stub) | Manual Painless rewrite required |
| `aggregate` | — | No ingest equivalent |
| `jdbc` input | — | No Elastic Agent equivalent; use JDBC connector |