"""Segmentation Copilot — Streamlit UI (Phase 2: pure HTTP client of the API).

Every action goes through the FastAPI service at `SCOPILOT_API_BASE`. No
direct imports of `segmentation_copilot.tools`, `segmentation_copilot.core`,
or the database — this file is now interchangeable with the CLI client
and any other UI.

The Phase-2 plan calls out a CI grep test
(`tests/test_no_core_in_app.py`) that fails if any of those imports come
back; do not bring them back without removing the test.

Run with:

    uvicorn services.api.main:app &     # in another terminal
    streamlit run app.py
"""

from __future__ import annotations

import io
import json
import os
from datetime import datetime, time, timedelta
from typing import Any

import httpx
import streamlit as st

DEFAULT_API_BASE = os.environ.get("SCOPILOT_API_BASE", "http://localhost:8000")


# ---------------------------------------------------------------------------
# Thin HTTP wrapper around the REST API
# ---------------------------------------------------------------------------


class ApiError(RuntimeError):
    pass


def _client() -> httpx.Client:
    base = st.session_state.get("api_base", DEFAULT_API_BASE)
    token = st.session_state.get("api_token", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.Client(base_url=base, headers=headers, timeout=120.0)


def _call(method: str, path: str, **kwargs: Any) -> Any:
    with _client() as c:
        resp = c.request(method, path, **kwargs)
    if not resp.is_success:
        raise ApiError(f"HTTP {resp.status_code}: {resp.text}")
    if resp.headers.get("content-type", "").startswith("application/json"):
        return resp.json()
    return resp.text


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------


def main() -> None:
    st.set_page_config(page_title="Segmentation Copilot", layout="wide")
    st.title("Segmentation Copilot")
    st.caption(
        "AI Security Analyst that turns Cisco SG-ACL hit logs into a "
        "TrustSec contract matrix proposal. Backed by the segmentation-copilot API."
    )

    _sidebar()
    tab_run, tab_inputs, tab_matrix, tab_history, tab_proposals = st.tabs(
        ["Run analysis", "Missing SGTs", "Matrix", "History", "Proposals"]
    )
    with tab_run:
        _run_panel()
    with tab_inputs:
        _missing_sgts_panel()
    with tab_matrix:
        _matrix_panel()
    with tab_history:
        _history_panel()
    with tab_proposals:
        _proposals_panel()


def _sidebar() -> None:
    with st.sidebar:
        st.header("API")
        st.session_state.setdefault("api_base", DEFAULT_API_BASE)
        st.session_state.setdefault("api_token", "")
        st.session_state["api_base"] = st.text_input(
            "API base URL", value=st.session_state["api_base"]
        )
        st.session_state["api_token"] = st.text_input(
            "API bearer token (optional)",
            value=st.session_state["api_token"],
            type="password",
        )
        if st.button("Test connection"):
            try:
                _call("GET", "/readyz")
                st.success("API reachable")
            except ApiError as exc:
                st.error(str(exc))

        st.divider()
        st.header("New run")
        uploaded = st.file_uploader(
            "Upload a syslog file", type=["log", "txt"], accept_multiple_files=False
        )

        st.subheader("Analysis window (metadata)")
        default_end = datetime.utcnow()
        default_start = default_end - timedelta(days=1)
        col1, col2 = st.columns(2)
        with col1:
            start_date = st.date_input("Start date", value=default_start.date())
            start_time = st.time_input("Start time", value=time(0, 0))
        with col2:
            end_date = st.date_input("End date", value=default_end.date())
            end_time = st.time_input("End time", value=time(23, 59))

        if st.button("Create run and ingest", type="primary", disabled=uploaded is None):
            try:
                run_resp = _call(
                    "POST", "/v1/runs",
                    json={
                        "source_type": "upload",
                        "window_start": datetime.combine(start_date, start_time).isoformat(),
                        "window_end": datetime.combine(end_date, end_time).isoformat(),
                    },
                )
                run_id = run_resp["run"]["id"]
                lines = uploaded.getvalue().decode("utf-8", errors="replace").splitlines()
                summary = _call(
                    "POST", f"/v1/runs/{run_id}/ingest", json={"lines": lines}
                )
                st.session_state["active_run_id"] = run_id
                st.session_state["ingest_summary"] = summary
                st.success(f"Run {run_id} created and ingested.")
            except ApiError as exc:
                st.error(str(exc))

        st.divider()
        st.header("SGT dictionary")
        dict_file = st.file_uploader("Upload SGT dict (JSON)", type=["json"])
        if dict_file is not None and st.button("Load dictionary"):
            try:
                data = json.loads(dict_file.getvalue().decode("utf-8"))
                _call("POST", "/v1/sgt/bulk",
                      json={"entries": {str(k): str(v) for k, v in data.items()}})
                st.success(f"Loaded {len(data)} entries.")
            except ApiError as exc:
                st.error(str(exc))


def _active_run_id() -> int | None:
    return st.session_state.get("active_run_id")


def _run_panel() -> None:
    run_id = _active_run_id()
    if run_id is None:
        st.info("Upload a log file in the sidebar to start a run.")
        return

    summary = st.session_state.get("ingest_summary")
    if summary:
        st.subheader("Ingest summary")
        st.json(summary)

    if st.button("Classify flows", type="primary"):
        try:
            result = _call("POST", f"/v1/runs/{run_id}/classify")
            st.session_state["classify_counts"] = result["counts"]
            st.success("Classification complete.")
        except ApiError as exc:
            st.error(str(exc))

    if "classify_counts" in st.session_state:
        st.subheader("Classification counts")
        st.json(st.session_state["classify_counts"])

    if st.button("Build matrix"):
        try:
            matrix = _call("POST", f"/v1/runs/{run_id}/matrix")
            st.session_state["matrix"] = matrix
            st.success("Matrix built — see the Matrix tab.")
        except ApiError as exc:
            st.error(str(exc))


def _missing_sgts_panel() -> None:
    run_id = _active_run_id()
    if run_id is None:
        st.info("No active run.")
        return
    try:
        data = _call("GET", f"/v1/runs/{run_id}/missing-sgts")
    except ApiError as exc:
        st.error(str(exc))
        return
    missing = data["missing"]
    if not missing:
        st.success("No missing SGTs.")
        return
    st.warning(f"{len(missing)} SGT/DGT IDs are missing from the dictionary.")
    for sgt_id in missing:
        name = st.text_input(f"Name for SGT {sgt_id}", key=f"sgt_name_{sgt_id}")
        if name and st.button(f"Register SGT {sgt_id}", key=f"sgt_btn_{sgt_id}"):
            try:
                _call("POST", "/v1/sgt", json={"sgt_id": sgt_id, "name": name})
                st.success(f"Registered {sgt_id} → {name}")
            except ApiError as exc:
                st.error(str(exc))


def _matrix_panel() -> None:
    matrix = st.session_state.get("matrix")
    if not matrix:
        st.info("Build the matrix from the Run tab.")
        return
    st.markdown(matrix["markdown"])
    st.download_button(
        "Download matrix (.md)",
        data=matrix["markdown"].encode("utf-8"),
        file_name="trustsec_matrix.md",
        mime="text/markdown",
    )
    csv_buf = io.StringIO()
    csv_buf.write("Source SGT,Destination SGT,Contract Name,Protocol,"
                  "Source Port,Destination Port,Action\n")
    for c in matrix["contracts"]:
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
    try:
        runs = _call("GET", "/v1/runs")["runs"]
    except ApiError as exc:
        st.error(str(exc))
        return
    if not runs:
        st.info("No prior runs.")
        return
    st.dataframe(runs, use_container_width=True)


def _proposals_panel() -> None:
    try:
        data = _call("GET", "/v1/proposals")
    except ApiError as exc:
        st.error(str(exc))
        return
    proposals = data["proposals"]
    if not proposals:
        st.info("No proposals.")
        return
    for p in proposals:
        with st.expander(
            f"[{p['status']}] {p['src_sgt']} → {p['dst_sgt']} — {p['trigger']}"
        ):
            st.markdown(f"**Rationale:** {p['rationale']}")
            st.json(p["proposed_aces"])
            if p["status"] in ("pending", "notified"):
                col_a, col_r = st.columns(2)
                if col_a.button("Approve", key=f"approve_{p['id']}"):
                    try:
                        _call("POST", f"/v1/proposals/{p['id']}/decision",
                              json={"decision": "approved"})
                        st.success("Approved.")
                    except ApiError as exc:
                        st.error(str(exc))
                if col_r.button("Reject", key=f"reject_{p['id']}"):
                    try:
                        _call("POST", f"/v1/proposals/{p['id']}/decision",
                              json={"decision": "rejected"})
                        st.success("Rejected.")
                    except ApiError as exc:
                        st.error(str(exc))


if __name__ == "__main__":
    main()
