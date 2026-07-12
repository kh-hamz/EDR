import { useParams } from "react-router-dom";
import { api } from "../api/client";
import { useApi } from "../api/useApi";
import { AICopilotPanel } from "../components/AICopilotPanel";
import { AlertCard } from "../components/AlertCard";
import { ProcessTree } from "../components/ProcessTree";
import { Timeline } from "../components/Timeline";
import { formatTime } from "../format";

export function IncidentDetail() {
  const { id } = useParams();
  const incidentId = Number(id);
  const { data, error, loading, reload } = useApi(() => api.incident(incidentId), [incidentId]);

  if (loading) return <p className="muted">loading...</p>;
  if (error) return <p className="error">{error}</p>;
  if (!data) return null;

  const toggleStatus = () => {
    api
      .updateIncidentStatus(incidentId, data.status === "open" ? "closed" : "open")
      .then(reload);
  };

  const triageAlert = (alertId: number, next: string) => {
    api.updateAlertStatus(alertId, next).then(reload);
  };

  const alertedEventIds = new Set(data.alerts.map((a) => a.event_id));
  const techniques = [
    ...new Set(data.alerts.map((a) => a.technique_id).filter((t): t is string => t !== null)),
  ];

  return (
    <div className="incident-layout">
      <div className="incident-main">
        <header className="incident-header">
          <h2>
            #{data.id} {data.title}
          </h2>
          <span className={`badge severity-${data.severity}`}>{data.severity}</span>
          <span className={`badge status-${data.status}`}>{data.status}</span>
          <button onClick={toggleStatus}>
            {data.status === "open" ? "close incident" : "reopen incident"}
          </button>
        </header>
        <p className="muted">
          {data.hostname} | {formatTime(data.first_alert_at)} to {formatTime(data.last_alert_at)}
        </p>

        <section>
          <h3>Alerts ({data.alerts.length})</h3>
          {data.alerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onStatusChange={triageAlert}
              showIncidentLink={false}
            />
          ))}
        </section>

        <section>
          <h3>Timeline</h3>
          <Timeline entries={data.timeline} />
        </section>

        <section>
          <h3>Process tree</h3>
          <ProcessTree roots={data.process_tree} alerted={alertedEventIds} />
        </section>
      </div>

      <aside>
        <AICopilotPanel incidentId={incidentId} techniques={techniques} />
      </aside>
    </div>
  );
}
