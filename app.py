"""Segmentation Copilot — Streamlit UI.

Walks the operator through the workflow defined in the Security Analyst system
prompt:
  1. Configure log source (local file or SSH).
  2. Choose the time window.
  3. Upload (or paste) the SGT/DGT dictionary.
  4. Fetch + parse + classify + build matrix.
  5. Review the markdown matrix and download artefacts.
"""

from __future__ import annotations

import io
import os
from datetime import datetime, time, timedelta
from pathlib import Path

import streamlit as st

from segmentation_copilot import db, sgt, tools
from segmentation_copilot.sources import LogSourceConfig


DB_PATH = Path("data/segmentation.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
db.init_db(DB_PATH)


def _get_state() -> tools.AgentState:
    if "agent_state" not in st.session_state:
        st.session_state.agent_state = tools.AgentState(db_path=str(DB_PATH))
    return st.session_state.agent_state


def main() -> None:
    st.set_page_config(page_title="Segmentation Copilot", layout="wide")
    st.title("Segmentation Copilot")
    st.caption(
        "An AI Security Analyst that turns Cisco SG-ACL hit logs into a "
        "TrustSec contract matrix proposal."
    )

    state = _get_state()
    _sidebar(state)

    tab_run, tab_inputs, tab_matrix, tab_history = st.tabs(
        ["Run analysis", "Missing SGTs", "Matrix", "History"]
    )

    with tab_run:
        _run_panel(state)
    with tab_inputs:
        _missing_sgts_panel(state)
    with tab_matrix:
        _matrix_panel(state)
    with tab_history:
        _history_panel()


def _sidebar(state: tools.AgentState) -> None:
    with st.sidebar:
        st.header("Configuration")

        api_key = st.text_input(
            "Anthropic API key",
            value=os.environ.get("ANTHROPIC_API_KEY", ""),
            type="password",
        )
        if api_key:
            state.api_key = api_key

        st.subheader("Log source")
        kind = st.radio("Source type", ["local", "ssh"], horizontal=True)

        if kind == "local":
            uploaded = st.file_uploader(
                "Upload syslog file (or .log)", type=["log", "txt"], accept_multiple_files=False
            )
            path_text = st.text_input("…or absolute path to a file/directory on the server")
            if st.button("Use local source"):
                if uploaded is not None:
                    target = Path("data/uploads") / uploaded.name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(uploaded.getvalue())
                    state.source_config = LogSourceConfig(kind="local", options={"path": str(target)})
                    st.success(f"Using uploaded file: {target}")
                elif path_text:
                    state.source_config = LogSourceConfig(kind="local", options={"path": path_text})
                    st.success(f"Using path: {path_text}")
                else:
                    st.error("Provide either an upload or a path.")
        else:
            host = st.text_input("Host", placeholder="syslog.example.com")
            username = st.text_input("Username")
            password = st.text_input("Password (optional)", type="password")
            key_filename = st.text_input("SSH key path (optional)")
            log_path = st.text_input("Remote log path", value="/var/log/network/*.log")
            if st.button("Use SSH source"):
                state.source_config = LogSourceConfig(
                    kind="ssh",
                    options={
                        "host": host, "username": username, "password": password or None,
                        "key_filename": key_filename or None, "log_path": log_path,
                    },
                )
                st.success(f"Configured SSH source to {host}")

        st.subheader("Analysis window")
        default_end = datetime.utcnow()
        default_start = default_end - timedelta(days=1)
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start date", value=default_start.date())
            start_time = st.time_input("Start time", value=time(0, 0))
        with col2:
            end_date = st.date_input("End date", value=default_end.date())
            end_time = st.time_input("End time", value=time(23, 59))
        if st.button("Set window"):
            state.window_start = datetime.combine(start_date, start_time)
            state.window_end = datetime.combine(end_date, end_time)
            st.success(f"Window: {state.window_start} → {state.window_end}")

        st.subheader("SGT dictionary")
        dict_file = st.file_uploader("Upload SGT dict (JSON or CSV)", type=["json", "csv"])
        if dict_file is not None and st.button("Load dictionary"):
            text = dict_file.getvalue().decode("utf-8")
            if dict_file.name.lower().endswith(".json"):
                state.sgt_dict = sgt.load_from_json(text)
            else:
                state.sgt_dict = sgt.load_from_csv(text)
            st.success(f"Loaded {len(state.sgt_dict.names)} SGT entries.")


def _run_panel(state: tools.AgentState) -> None:
    st.markdown(
        "### Run pipeline\n"
        "Once the sidebar has a source, window, and SGT dictionary, run the steps "
        "below. The agent will surface SGT names it can't resolve in the **Missing "
        "SGTs** tab."
    )

    ready = all([state.source_config, state.window_start, state.window_end])
    if not ready:
        st.info("Configure source and time window in the sidebar first.")
        return

    if st.button("1. Fetch and parse logs", type="primary"):
        with st.spinner("Fetching and parsing…"):
            summary = tools.fetch_and_parse_logs(state)
        st.session_state.parse_summary = summary
    if "parse_summary" in st.session_state:
        st.json(st.session_state.parse_summary)

    if state.events and st.button("2. Classify flows", disabled=state.sgt_dict is None):
        with st.spinner("Asking Claude to classify flows…"):
            counts = tools.classify_flows(state)
        st.session_state.classify_counts = counts
    if "classify_counts" in st.session_state:
        st.write("**Classification counts**")
        st.json(st.session_state.classify_counts)

    if state.classified and st.button("3. Build matrix"):
        with st.spinner("Building contracts…"):
            tools.build_matrix(state)
        st.success("Matrix ready — see the **Matrix** tab.")


def _missing_sgts_panel(state: tools.AgentState) -> None:
    missing = tools.list_missing_sgt_names(state) if state.events else []
    if not missing:
        st.success("No missing SGTs.")
        return
    st.warning(
        f"{len(missing)} SGT/DGT IDs were observed in logs but are not in the "
        "dictionary. Provide names below before classifying."
    )
    for sgt_id in missing:
        name = st.text_input(f"Name for SGT {sgt_id}", key=f"sgt_name_{sgt_id}")
        if name and st.button(f"Register SGT {sgt_id}", key=f"sgt_btn_{sgt_id}"):
            tools.register_sgt_name(state, sgt_id, name)
            st.experimental_rerun()


def _matrix_panel(state: tools.AgentState) -> None:
    if not state.matrix_markdown:
        st.info("Run the pipeline to generate a matrix.")
        return
    st.markdown(state.matrix_markdown)
    st.download_button(
        "Download matrix (.md)",
        data=state.matrix_markdown.encode("utf-8"),
        file_name="trustsec_matrix.md",
        mime="text/markdown",
    )
    csv_buf = io.StringIO()
    csv_buf.write("Source SGT,Destination SGT,Contract Name,Protocol,Source Port,Destination Port,Action\n")
    for c in state.contracts:
        for ace in c["aces"]:
            csv_buf.write(
                f"{c['src_sgt_name']},{c['dst_sgt_name']},{c['name']},"
                f"{ace['protocol']},{ace['src_port']},{ace['dst_port']},{ace['action']}\n"
            )
    st.download_button(
        "Download matrix (.csv)",
        data=csv_buf.getvalue().encode("utf-8"),
        file_name="trustsec_matrix.csv",
        mime="text/csv",
    )


def _history_panel() -> None:
    runs = db.list_runs(DB_PATH)
    if not runs:
        st.info("No prior runs.")
        return
    st.dataframe(runs, use_container_width=True)
    run_ids = [r["id"] for r in runs]
    selected = st.selectbox("Inspect run", run_ids)
    if selected:
        contracts = db.load_contracts(DB_PATH, selected)
        st.write(f"**{len(contracts)} contracts**")
        st.json(contracts)


if __name__ == "__main__":
    main()
