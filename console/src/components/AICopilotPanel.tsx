import { useState } from "react";
import { api } from "../api/client";

// The two copilot features that live on the incident page: LLM summary of
// this incident, and "explain this technique" grounded in the local corpus.
// A 503 means LLM_API_KEY is unset on the backend; surface it as-is.
interface Props {
  incidentId: number;
  techniques: string[];
}

export function AICopilotPanel({ incidentId, techniques }: Props) {
  const [summary, setSummary] = useState<string | null>(null);
  const [summaryError, setSummaryError] = useState<string | null>(null);
  const [summarizing, setSummarizing] = useState(false);

  const [explainQuery, setExplainQuery] = useState("");
  const [answer, setAnswer] = useState<string | null>(null);
  const [sources, setSources] = useState<string[]>([]);
  const [explainError, setExplainError] = useState<string | null>(null);
  const [explaining, setExplaining] = useState(false);

  const summarize = () => {
    setSummarizing(true);
    setSummaryError(null);
    api
      .summarize(incidentId)
      .then((res) => setSummary(res.summary))
      .catch((e: Error) => setSummaryError(e.message))
      .finally(() => setSummarizing(false));
  };

  const explain = (query: string) => {
    if (!query.trim()) return;
    setExplainQuery(query);
    setExplaining(true);
    setExplainError(null);
    api
      .explain(query)
      .then((res) => {
        setAnswer(res.answer);
        setSources(res.sources);
      })
      .catch((e: Error) => setExplainError(e.message))
      .finally(() => setExplaining(false));
  };

  return (
    <div className="copilot">
      <h3>AI copilot</h3>

      <section>
        <button onClick={summarize} disabled={summarizing}>
          {summarizing ? "summarizing..." : "Summarize incident"}
        </button>
        {summaryError && <p className="error">{summaryError}</p>}
        {summary && <p className="copilot-answer">{summary}</p>}
      </section>

      <section>
        <h4>Explain technique</h4>
        <div className="technique-chips">
          {techniques.map((t) => (
            <button key={t} className="chip" onClick={() => explain(t)}>
              {t}
            </button>
          ))}
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            explain(explainQuery);
          }}
        >
          <input
            value={explainQuery}
            onChange={(e) => setExplainQuery(e.target.value)}
            placeholder="technique id or question"
          />
          <button type="submit" disabled={explaining}>
            {explaining ? "..." : "Explain"}
          </button>
        </form>
        {explainError && <p className="error">{explainError}</p>}
        {answer && (
          <div>
            <p className="copilot-answer">{answer}</p>
            {sources.length > 0 && (
              <p className="muted">sources: {sources.join(", ")}</p>
            )}
          </div>
        )}
      </section>
    </div>
  );
}
