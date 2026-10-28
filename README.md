# Network Traffic Threat Investigation

A beginner-friendly cybersecurity project for investigating network flow logs and flagging potentially suspicious activity. It includes a command-line analyzer, a Streamlit dashboard, synthetic sample data, and unit tests.

> **Important:** This is a defensive, educational triage tool. It uses transparent heuristics, not a production-grade IDS. Alerts are leads for investigation, not proof of compromise.

## Features

- Load network-flow CSV files
- Flag connections to uncommon/high-risk ports
- Identify repeated failed connections
- Detect possible port-scanning behavior
- Highlight unusually large outbound transfers
- Flag DNS traffic to unusually long domains
- Produce a prioritized alert report as CSV
- Explore traffic and alerts in a local Streamlit dashboard
- Run unit tests with `pytest`

## Project structure

```text
network-traffic-threat-investigation/
├── app.py
├── requirements.txt
├── README.md
├── data/
│   └── sample_traffic.csv
├── reports/
│   └── .gitkeep
├── src/
│   └── analyzer.py
└── tests/
    └── test_analyzer.py
```

## Quick start

Requires Python 3.10 or newer.

### 1. Create and activate a virtual environment

**Windows (PowerShell):**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

**macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the command-line investigation

```bash
python src/analyzer.py --input data/sample_traffic.csv --output reports/alerts.csv
```

The tool prints a summary and saves alerts to `reports/alerts.csv`.

### 4. Launch the dashboard

```bash
streamlit run app.py
```

Open the local URL shown in your terminal. Upload a CSV with the schema below or use the included sample.

### 5. Run tests

```bash
pytest -q
```

## Input CSV schema

Required columns:

| Column | Meaning |
|---|---|
| `timestamp` | Time of observed flow, parseable by pandas |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `protocol` | Protocol, e.g. TCP, UDP, ICMP |
| `bytes_sent` | Bytes sent from source to destination |
| `bytes_received` | Bytes received by source |
| `connection_state` | Connection outcome, e.g. `SUCCESS` or `FAILED` |
| `dns_query` | Queried domain, blank if not DNS |

The sample data is synthetic and does not represent real people, devices, or incidents.

## Detection logic

| Detection | Heuristic | Suggested next step |
|---|---|---|
| Unusual destination port | Destination port in a configurable watchlist | Check asset role, process, and business justification |
| Repeated failures | At least 5 failed connections from one source IP | Review authentication/service logs and source reputation |
| Possible port scan | One source contacts at least 8 distinct destination ports | Correlate with firewall and endpoint telemetry |
| Large outbound transfer | At least 5 MB sent in a single flow | Verify destination, user, process, and data sensitivity |
| Long DNS query | DNS query label length above 50 characters | Check resolver logs and endpoint process; long labels can be legitimate |

These are simple, explainable rules. Tune thresholds for your environment to reduce false positives. The tool does not block traffic, perform packet capture, or contact external systems.

## Example investigation workflow

1. Load a flow-log export from an environment you are authorized to investigate.
2. Run the analyzer and sort alerts by severity.
3. Validate the source and destination asset owners.
4. Correlate timestamps with endpoint, identity, DNS, and firewall logs.
5. Record evidence and disposition; do not treat a heuristic alert alone as confirmation.

## Push to GitHub

Create a new empty repository on GitHub, then from this project folder run:

```bash
git init
git add .
git commit -m "Initial network traffic threat investigation project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/network-traffic-threat-investigation.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. Do not commit real network logs, credentials, private IP inventories, or other sensitive data without authorization.

## Future improvements

- Add configurable thresholds in a YAML file
- Enrich IPs using an approved internal threat-intelligence source
- Add MITRE ATT&CK technique mapping where evidence supports it
- Add a timeline and downloadable investigation summary
- Evaluate detections against a labeled dataset and measure precision/recall
