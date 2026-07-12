import { useState } from "react";
import { api } from "../api/client";
import type { HuntResponse } from "../api/types";
import { formatTime, summarizeEvent } from "../format";

// NL hunt: the backend translates the sentence to filters via the LLM, runs
// the search, and returns both, so the analyst can see how the question was
// interpreted next to the results.
export function Hunt() {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<HuntResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const run = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    api
      .hunt(query)
      .then(setResult)
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false));
  };

  return (
    <div>
      <h2>Hunt</h2>
      <form onSubmit={run} className="hunt-form">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder='e.g. "outbound connections from www-data in the last 24h"'
        />
        <button type="submit" disabled={loading}>
          {loading ? "hunting..." : "Hunt"}
        </button>
      </form>

      {error && <p className="error">{error}</p>}

      {result && (
        <>
          <div className="filters">
            <span className="muted">interpreted as:</span>
            {Object.entries(result.filters)
              .filter(([, v]) => v)
              .map(([k, v]) => (
                <span key={k} className="chip">
                  {k}={String(v)}
                </span>
              ))}
            <span className="muted">{result.total} event(s)</span>
          </div>
          {result.events.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>time</th>
                  <th>host</th>
                  <th>type</th>
                  <th>summary</th>
                </tr>
              </thead>
              <tbody>
                {result.events.map((event) => (
                  <tr key={event.event_id}>
                    <td>{formatTime(event.time)}</td>
                    <td>{event.host.hostname}</td>
                    <td>
                      <span className="badge event-type">{event.event_type}</span>
                    </td>
                    <td>
                      <code>{summarizeEvent(event)}</code>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </div>
  );
}
