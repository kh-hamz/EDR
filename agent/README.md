# edr_agent

Endpoint sensor: tails Falco and osquery output, normalizes events to the
shared schema, buffers them on disk, and ships them to the backend ingest
gateway over HTTP.

## Install (on the victim host)

The agent imports the normalized event models from `edr-schema` (single
source of truth for the schema, shared with the backend), so both the
`shared` and `agent` packages get installed:

```bash
git clone <repo> edr && cd edr
python3 -m venv .venv && source .venv/bin/activate
pip install -e ./shared -e ./agent
```

Sensors themselves are installed separately: `sudo bash lab/provision/install_sensors.sh`.

## Configure

Environment variables (prefix `EDR_AGENT_`):

| Variable | Default | Purpose |
|---|---|---|
| `EDR_AGENT_BACKEND_URL` | `http://localhost:8000` | Ingest gateway base URL |
| `EDR_AGENT_API_TOKEN` | (required) | Bearer token, must match backend `EDR_API_TOKEN` |
| `EDR_AGENT_FALCO_LOG` | `/var/log/falco/events.json` | Falco JSON output to tail |
| `EDR_AGENT_OSQUERY_LOG` | `/var/log/osquery/osqueryd.results.log` | osquery results log to tail |
| `EDR_AGENT_DATA_DIR` | `/var/lib/edr-agent` | Spool (disk buffer) + enrollment state |
| `EDR_AGENT_BATCH_SIZE` | `200` | Max events per POST |
| `EDR_AGENT_FLUSH_INTERVAL` | `2.0` | Seconds between ship attempts when idle |

## Run

```bash
sudo -E .venv/bin/python -m edr_agent
```

Root is needed to read the Falco/osquery logs and (from Phase 5) to execute
response actions. First run enrolls with the backend and stores the assigned
`agent_id` in `$EDR_AGENT_DATA_DIR/state.json`.
