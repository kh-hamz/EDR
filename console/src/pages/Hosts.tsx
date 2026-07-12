import { api } from "../api/client";
import { useApi } from "../api/useApi";
import { formatTime, timeAgo } from "../format";

// An agent that has not checked in for this long is likely down.
const STALE_AFTER_MS = 10 * 60 * 1000;

export function Hosts() {
  const { data, error, loading } = useApi(() => api.hosts());

  if (loading) return <p className="muted">loading...</p>;
  if (error) return <p className="error">{error}</p>;

  return (
    <div>
      <h2>Hosts</h2>
      {data && data.length === 0 && <p className="muted">no enrolled agents</p>}
      {data && data.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>hostname</th>
              <th>os</th>
              <th>ip</th>
              <th>agent id</th>
              <th>enrolled</th>
              <th>last seen</th>
            </tr>
          </thead>
          <tbody>
            {data.map((host) => {
              const stale =
                !host.last_seen ||
                Date.now() - new Date(host.last_seen).getTime() > STALE_AFTER_MS;
              return (
                <tr key={host.agent_id} className={stale ? "stale" : ""}>
                  <td>{host.hostname}</td>
                  <td>{host.os}</td>
                  <td>{host.ip ?? "-"}</td>
                  <td>
                    <code>{host.agent_id.slice(0, 8)}</code>
                  </td>
                  <td>{formatTime(host.enrolled_at)}</td>
                  <td>{timeAgo(host.last_seen)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}
