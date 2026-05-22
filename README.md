# segmentation-copilot

An AI Security Analyst agent that turns Cisco SD-Access SG-ACL hit logs into a TrustSec contract matrix proposal — designed to help networks switch the matrix default rule to `deny-ip` without breaking legitimate flows.

## What it does

1. Asks for a syslog source (local file or SSH to a syslog collector), an analysis window, and an SGT/DGT id→name dictionary.
2. Pulls and parses `%RBM-6-SGACLHIT` syslog entries from the configured source.
3. Aggregates the raw events into unique flow tuples (`sgt`, `dgt`, `protocol`, `src_port`, `dst_port`).
4. Uses Claude to classify each flow as **business_relevant**, **default**, **business_irrelevant**, or **harmful**.
5. Groups classified flows into one **contract** per (Source SGT, Destination SGT) pair, with one or more ACEs each.
6. Renders the matrix as a markdown table and persists runs to SQLite.

The matrix-wide default rule remains `deny-ip` — the agent emits only the explicit permits (and selective denies for visibility into Business Irrelevant / Harmful flows).

## Install

```bash
pip install -e ".[dev]"
```

## Run the Streamlit UI

```bash
export ANTHROPIC_API_KEY=sk-ant-...
streamlit run app.py
```

In the UI:
- Pick a log source (upload a local file, point at a directory, or configure SSH).
- Set the analysis window.
- Upload the SGT dictionary (JSON `{ "100": "Employees" }` or CSV with `id,name`).
- Click **Fetch and parse logs**, fill any missing SGT names in the *Missing SGTs* tab, then **Classify flows** and **Build matrix**.
- Download the result as `.md` or `.csv`.

## Run the tests

```bash
pytest
```

## Project layout

```
app.py                          # Streamlit entry point
src/segmentation_copilot/
    parser.py                   # %RBM-6-SGACLHIT regex parser
    aggregator.py               # Group events into unique flow tuples
    sgt.py                      # SGT dict load + lookup with missing-name registry
    classify.py                 # Claude-based flow categorisation
    contracts.py                # Build contracts + render markdown matrix
    db.py                       # SQLite persistence
    agent.py                    # Security Analyst system prompt + tool registry
    tools.py                    # Pure-Python tool implementations
    sources/
        base.py                 # LogSource abstract base
        local.py                # Local file backend
        ssh.py                  # Paramiko-based SSH backend
tests/                          # pytest suite + fixtures
data/                           # SQLite db + uploads (gitignored)
```
