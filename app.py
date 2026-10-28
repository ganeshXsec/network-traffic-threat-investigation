from pathlib import Path
import sys

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from analyzer import analyze_flows, load_flows  # noqa: E402

st.set_page_config(page_title="Network Threat Investigation", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Traffic Threat Investigation")
st.caption("Rule-based network-flow triage • Educational demo • Alerts require analyst validation")

uploaded = st.file_uploader("Upload network-flow CSV", type=["csv"])
use_sample = st.checkbox("Use bundled synthetic sample data", value=uploaded is None)

try:
    if uploaded is not None:
        flows = load_flows(uploaded)
    elif use_sample:
        flows = load_flows(ROOT / "data" / "sample_traffic.csv")
    else:
        st.info("Upload a CSV or select the sample data option.")
        st.stop()

    st.sidebar.header("Detection thresholds")
    failed_threshold = st.sidebar.slider("Failed connections per source", 3, 20, 5)
    port_scan_threshold = st.sidebar.slider("Distinct ports for possible scan", 4, 30, 8)
    large_mb = st.sidebar.slider("Large transfer threshold (MB)", 1, 100, 5)
    watchlist_text = st.sidebar.text_input("Watchlist destination ports", "23,2323,4444,5555,6667,31337")
    try:
        watchlist = {int(x.strip()) for x in watchlist_text.split(",") if x.strip()}
    except ValueError:
        st.sidebar.error("Ports must be comma-separated integers.")
        st.stop()

    alerts = analyze_flows(
        flows,
        failed_threshold=failed_threshold,
        port_scan_threshold=port_scan_threshold,
        large_transfer_bytes=large_mb * 1024 * 1024,
        watchlist_ports=watchlist,
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Flows analyzed", f"{len(flows):,}")
    c2.metric("Alerts", f"{len(alerts):,}")
    c3.metric("High severity", int((alerts["severity"] == "HIGH").sum()) if not alerts.empty else 0)
    c4.metric("Unique source IPs", flows["src_ip"].nunique())

    st.subheader("Traffic overview")
    left, right = st.columns(2)
    with left:
        st.write("**Flows by protocol**")
        st.bar_chart(flows["protocol"].value_counts())
    with right:
        st.write("**Top destination ports**")
        st.bar_chart(flows["dst_port"].value_counts().head(10))

    st.subheader("Investigation alerts")
    if alerts.empty:
        st.success("No alerts matched the selected rules. This does not prove the traffic is benign.")
    else:
        severity = st.multiselect("Filter severity", ["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"])
        visible = alerts[alerts["severity"].isin(severity)]
        st.dataframe(visible, use_container_width=True, hide_index=True)
        st.download_button(
            "Download alert report (CSV)",
            data=visible.to_csv(index=False).encode("utf-8"),
            file_name="network_threat_alerts.csv",
            mime="text/csv",
        )

    with st.expander("View raw flow records"):
        st.dataframe(flows, use_container_width=True, hide_index=True)

except (ValueError, pd.errors.ParserError) as exc:
    st.error(f"Could not load or analyze the file: {exc}")
