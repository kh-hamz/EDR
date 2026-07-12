import type { TimelineEntry } from "../api/types";
import { formatTime } from "../format";

// Ordered list of the incident's events; entries that fired rules carry
// severity-colored chips naming the rule(s).
export function Timeline({ entries }: { entries: TimelineEntry[] }) {
  if (entries.length === 0) {
    return <p className="muted">no events on this incident's alerts</p>;
  }
  return (
    <ol className="timeline">
      {entries.map((entry) => (
        <li key={entry.event_id} className="timeline-entry">
          <span className="timeline-time">{formatTime(entry.time)}</span>
          <span className="badge event-type">{entry.event_type}</span>
          <code className="timeline-summary">{entry.summary}</code>
          <span className="timeline-alerts">
            {entry.alerts.map((a) => (
              <span key={a.rule_id} className={`badge severity-${a.severity}`}>
                {a.title}
              </span>
            ))}
          </span>
        </li>
      ))}
    </ol>
  );
}
