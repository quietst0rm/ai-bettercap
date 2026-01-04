import streamlit as st
import pandas as pd
import time
import os

st.set_page_config(page_title="Sentinel Dashboard", layout="wide")

st.title("🛡️ Sentinel: AI Network Defense")

# Auto-refresh logic
if 'last_update' not in st.session_state:
    st.session_state.last_update = time.time()

def load_data():
    if os.path.exists('data/traffic_log.csv'):
        # Read only last 1000 rows for performance
        return pd.read_csv('data/traffic_log.csv').tail(1000)
    return pd.DataFrame(columns=['size', 'dst_port', 'score', 'is_anomaly', 'timestamp'])

df = load_data()

# Metrics Row
col1, col2, col3 = st.columns(3)
col1.metric("Total Packets Scanned", len(df))
anomalies_count = len(df[df['is_anomaly'] == 1])
col2.metric("Anomalies Detected", anomalies_count)
col3.metric("Current Threat Level", "HIGH" if anomalies_count > 5 else "LOW")

# Charts
st.subheader("Anomaly Score Timeline")
if not df.empty:
    st.line_chart(df[['score']].reset_index(drop=True))

    st.subheader("Traffic Distribution (Top destination ports by count)")
    ports = df.groupby('dst_port').size().sort_values(ascending=False).head(50)
    st.bar_chart(ports)

st.subheader("Recent Alerts")
if not df.empty:
    anomalies = df[df['is_anomaly'] == 1].tail(10)
    st.dataframe(anomalies, width='stretch')

# Manual refresh button
if st.button("Refresh"):
    st.write("Refreshed")