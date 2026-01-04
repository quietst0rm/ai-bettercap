# ai-bettercap — Sentinel pack

This repository contains a small demo stack that ingests Bettercap network sniffer
events, runs a lightweight anomaly detector, logs traffic features to CSV and
exposes a Streamlit dashboard.

**Quick Start**

1. Build and start services (Bettercap sensor + AI engine):

```bash
docker compose up --build
```

2. Open the Streamlit dashboard at `http://localhost:8501` and monitor `data/traffic_log.csv`.

**Services**
- `sensor` — Bettercap instance running the caplet in `caplets/listener.cap`.
- `ai_engine` — Python app that connects to Bettercap WebSocket, detects anomalies and
  serves the Streamlit UI (source under `src/`).

**Key files & folders**
- `docker-compose.yml` — compose services for `sensor` and `ai_engine`.
- `Dockerfile.ai` — Dockerfile used to build the AI engine image.
- `caplets/listener.cap` — Bettercap caplet configuring sniffing and API.
- `src/` — application source code:
  - `src/main.py` — entrypoint; starts connector and detector.
  - `src/core/connector.py` — Bettercap websocket connector.
  - `src/analysis/model.py` — streaming `AnomalyDetector` (feature extraction + buffered CSV writer).
  - `src/core/responder.py` — REST helper for mitigation commands.
  - `src/ui/app.py` — Streamlit dashboard UI.
- `data/` — runtime data files written by the app:
  - `data/traffic_log.csv` — appended feature records used by the UI.
  - `data/sample_event.json`, `data/sample_tcp.json` — sample events captured for debugging.

**Behavior & notes**
- The connector uses `aiohttp` to consume Bettercap WebSocket events and enqueues
  `net.sniff.*` events (both raw `packet` payloads and summarized `data` objects).
- `AnomalyDetector` performs a small z-score based detector and buffers CSV writes
  in memory, flushing every second or when the buffer reaches 100 records.
- The app includes a `Responder` stub which can be extended to issue Bettercap
  REST commands for mitigation.

**Development tips**
- To view logs while developing, run:

```bash
docker compose logs --follow ai_engine
```

- If Bettercap fails to bind to `127.0.0.1:8081`, stop any local Bettercap or processes
  using that port.

**Next improvements**
- Batch flush durability (rotate/atomic writes), threshold tuning, and extracting
  source IPs consistently for responder actions.

License: none — demo code. Use responsibly.
