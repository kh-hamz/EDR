// Mirrors of the backend response models (api/hosts.py, api/alerts.py,
// api/incidents.py, api/ai.py, api/hunt.py). Datetimes arrive as ISO strings.

export interface Host {
  agent_id: string;
  hostname: string;
  os: string;
  ip: string | null;
  enrolled_at: string;
  last_seen: string | null;
}

export interface Alert {
  id: number;
  event_id: string;
  rule_id: string;
  title: string;
  severity: string;
  tactic: string | null;
  technique_id: string | null;
  hostname: string;
  created_at: string;
  status: string;
  incident_id: number | null;
}

export interface IncidentSummary {
  id: number;
  hostname: string;
  title: string;
  severity: string;
  status: string;
  first_alert_at: string;
  last_alert_at: string;
  alert_count: number;
}

// correlation/timeline.py entry shape
export interface TimelineAlertRef {
  rule_id: string;
  title: string;
  severity: string;
}

export interface TimelineEntry {
  time: string;
  event_id: string;
  event_type: string;
  summary: string;
  alerts: TimelineAlertRef[];
}

// correlation/process_tree.py node; event_id === null marks a synthetic
// parent that had no create event inside the window.
export interface ProcessNode {
  pid: number;
  name: string | null;
  cmdline: string | null;
  user: string | null;
  time: string | null;
  event_id: string | null;
  children: ProcessNode[];
}

export interface IncidentDetail extends Omit<IncidentSummary, "alert_count"> {
  alerts: Alert[];
  timeline: TimelineEntry[];
  process_tree: ProcessNode[];
}

// NormalizedEvent, loosely typed: the console only reads a few fields and
// the full schema lives in shared/edr_schema.
export interface EDREvent {
  event_id: string;
  time: string;
  event_type: string;
  host: { hostname: string; [k: string]: unknown };
  process?: {
    pid?: number;
    name?: string;
    cmdline?: string;
    user?: { name?: string };
  } | null;
  file?: { action?: string; path?: string } | null;
  network?: { process_name?: string; dst_ip?: string; dst_port?: number } | null;
  auth?: { action?: string; user?: string; result?: string } | null;
  inventory?: { query_name?: string; action?: string } | null;
}

export interface HuntFilters {
  hostname: string | null;
  event_type: string | null;
  process_name: string | null;
}

export interface HuntResponse {
  filters: HuntFilters;
  total: number;
  events: EDREvent[];
}

export interface SummarizeResponse {
  incident_id: number;
  summary: string;
}

export interface ExplainResponse {
  answer: string;
  sources: string[];
}
