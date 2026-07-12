import { Link } from "react-router-dom";
import type { Alert } from "../api/types";
import { formatTime } from "../format";

// Triage transitions offered per current status. Closed/dismissed alerts can
// be reopened; open alerts get the three-way triage choice.
const NEXT_STATUSES: Record<string, string[]> = {
  open: ["acknowledged", "dismissed", "closed"],
  acknowledged: ["closed", "dismissed"],
  dismissed: ["open"],
  closed: ["open"],
};

interface Props {
  alert: Alert;
  onStatusChange?: (id: number, status: string) => void;
  showIncidentLink?: boolean;
}

export function AlertCard({ alert, onStatusChange, showIncidentLink = true }: Props) {
  return (
    <div className={`alert-card severity-border-${alert.severity}`}>
      <div className="alert-card-main">
        <span className={`badge severity-${alert.severity}`}>{alert.severity}</span>
        <span className="alert-title">{alert.title}</span>
        {alert.technique_id && <span className="badge technique">{alert.technique_id}</span>}
        <span className={`badge status-${alert.status}`}>{alert.status}</span>
      </div>
      <div className="alert-card-meta">
        <span>{alert.hostname}</span>
        <span>{formatTime(alert.created_at)}</span>
        {alert.tactic && <span>{alert.tactic}</span>}
        {showIncidentLink && alert.incident_id != null && (
          <Link to={`/incidents/${alert.incident_id}`}>incident #{alert.incident_id}</Link>
        )}
      </div>
      {onStatusChange && (
        <div className="alert-card-actions">
          {(NEXT_STATUSES[alert.status] ?? []).map((next) => (
            <button key={next} onClick={() => onStatusChange(alert.id, next)}>
              {next === "open" ? "reopen" : next.replace("acknowledged", "acknowledge").replace("dismissed", "dismiss").replace("closed", "close")}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
