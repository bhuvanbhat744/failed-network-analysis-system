import streamlit as st
import pandas as pd
import sqlite3
import os

DB = "/tmp/netra_events.db"

st.set_page_config(
    page_title="NETRA",
    page_icon="🛡️",
    layout="wide"
)

@st.fragment(run_every=2)
def live_dashboard():

    st.title("🛡️ NETRA")
    st.subheader("Network Intelligence & Threat Detection")
    st.caption("Live Network Monitoring System")

    if not os.path.exists(DB):
        st.warning("Waiting for monitoring engine...")
        return

    conn = sqlite3.connect(DB)

    events = pd.read_sql_query(
        "SELECT * FROM events ORDER BY id DESC LIMIT 100",
        conn
    )

    alerts = pd.read_sql_query(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 100",
        conn
    )

    conn.close()

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Events", len(events))
    c2.metric("Security Alerts", len(alerts))
    c3.metric("Port Scan Alerts",
              len(alerts[alerts.alert_type == "PORT SCAN"])
              if not alerts.empty else 0)
    c4.metric("Host Discovery Alerts",
              len(alerts[alerts.alert_type == "HOST DISCOVERY"])
              if not alerts.empty else 0)

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("🚨 Security Alerts")
        if alerts.empty:
            st.info("No suspicious activity detected yet.")
        else:
            st.dataframe(alerts, use_container_width=True)

    with right:
        st.subheader("📡 Network Activity")
        if events.empty:
            st.info("Waiting for network traffic...")
        else:
            st.dataframe(events, use_container_width=True)

    st.caption("NETRA | Refreshes automatically every 2 seconds")

live_dashboard()
