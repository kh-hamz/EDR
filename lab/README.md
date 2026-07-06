# EDR Lab Setup

## Topology

Two roles, per the roadmap (Windows victim is deferred):

| Role | Machine | Runs |
|---|---|---|
| Backend box | This host (Debian desktop) | Docker Compose stack: OpenSearch, OpenSearch Dashboards, Postgres, Redis. Later: FastAPI backend, React console. |
| Victim host | Ubuntu VM (VirtualBox/libvirt), or this same host during early dev | osquery + Falco sensors, later the `edr_agent`. |

Using the backend host as its own victim is fine for Phase 0/1 development, the
agent just ships to `localhost`. A separate VM makes the demo more honest
(real network hop, host isolation is actually visible) and is the target for
Phase 5 response testing. Do not test `isolate_host` on your own desktop.

## Backend box setup

1. Install Docker (see `docs/commands.md` for the exact commands used).
2. OpenSearch needs a larger mmap limit than the Linux default:
   `sudo sysctl -w vm.max_map_count=262144` (persist in `/etc/sysctl.d/99-opensearch.conf`).
3. Copy `.env.example` to `.env`, set a real `POSTGRES_PASSWORD`.
4. `docker compose up -d` from the repo root.
5. Verify: OpenSearch at http://localhost:9200, Dashboards at http://localhost:5601.

## Victim host setup

Run `lab/provision/install_sensors.sh` on the victim (Ubuntu 22.04/24.04 or
Debian 12+). It installs osquery and Falco from their official apt
repositories, applies our configs, and enables both services.

Verify sensors after install:

```bash
# Falco should log a JSON event when you spawn a shell from an odd parent
sudo tail -f /var/log/falco/events.json

# osquery scheduled results
sudo tail -f /var/log/osquery/osqueryd.results.log
```
