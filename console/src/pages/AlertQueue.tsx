import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import { AlertCard } from "../components/AlertCard";
import { formatTime, severityRank } from "../format";

const STATUS_FILTERS = ["all", "open", "acknowledged", "dismissed", "closed"];
const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"];

export function AlertQueue() {
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("all");

  const incidents = useApi(() => api.incidents({ status: "open" }));
  const alerts = useApi(
    () =>
      api.alerts({
        status: status === "all" ? undefined : status,
        severity: severity === "all" ? undefined : severity,
      }),
    [status, severity],
  );

  const triage = (id: number, next: string) => {
    api.updateAlertStatus(id, next).then(() => {
      alerts.reload();
      incidents.reload(); // closing the last open alert may change incident rollups
    });
  };

  const sorted = (alerts.data ?? [])
    .slice()
    .sort(
      (a, b) =>
        severityRank(a.severity) - severityRank(b.severity) ||
        b.created_at.localeCompare(a.created_at),
    );

  return (
    <div>
      <section>
        <h2>Open incidents</h2>
        {incidents.error && <p className="error">{incidents.error}</p>}
        {incidents.data && incidents.data.length === 0 && (
          <p className="muted">no open incidents</p>
        )}
        {incidents.data && incidents.data.length > 0 && (
          <table>
            <thead>
              <tr>
                <th>id</th>
                <th>severity</th>
                <th>title</th>
                <th>host</th>
                <th>alerts</th>
                <th>first alert</th>
                <th>last alert</th>
              </tr>
            </thead>
            <tbody>
              {incidents.data.map((inc) => (
                <tr key={inc.id}>
                  <td>
                    <Link to={`/incidents/${inc.id}`}>#{inc.id}</Link>
                  </td>
                  <td>
                    <span className={`badge severity-${inc.severity}`}>{inc.severity}</span>
                  </td>
                  <td>
                    <Link to={`/incidents/${inc.id}`}>{inc.title}</Link>
                  </td>
                  <td>{inc.hostname}</td>
                  <td>{inc.alert_count}</td>
                  <td>{formatTime(inc.first_alert_at)}</td>
                  <td>{formatTime(inc.last_alert_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section>
        <h2>Alert queue</h2>
        <div className="filters">
          <label>
            status
            <select value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUS_FILTERS.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <label>
            severity
            <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
              {SEVERITY_FILTERS.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
        </div>
        {alerts.loading && <p className="muted">loading...</p>}
        {alerts.error && <p className="error">{alerts.error}</p>}
        {alerts.data && sorted.length === 0 && <p className="muted">no alerts match</p>}
        {sorted.map((alert) => (
          <AlertCard key={alert.id} alert={alert} onStatusChange={triage} />
        ))}
      </section>
    </div>
  );
}
