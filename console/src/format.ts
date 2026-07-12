import type { EDREvent } from "./api/types";

export function formatTime(iso: string | null): string {
  if (!iso) return "-";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export function timeAgo(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "never";
  const seconds = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export function severityRank(severity: string): number {
  const i = SEVERITY_ORDER.indexOf(severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

// One-line description of an event for the hunt results table. Mirrors the
// backend's correlation/timeline.py _summarize so both views read the same.
export function summarizeEvent(e: EDREvent): string {
  if (e.event_type === "process_create" || e.event_type === "process_terminate") {
    const p = e.process ?? {};
    return p.cmdline ?? p.name ?? `pid ${p.pid}`;
  }
  if (e.event_type === "file_event") {
    const f = e.file ?? {};
    return `${f.action ?? "?"} ${f.path ?? "?"}`;
  }
  if (e.event_type === "network_connection") {
    const n = e.network ?? {};
    return `${n.process_name ?? "?"} -> ${n.dst_ip}:${n.dst_port}`;
  }
  if (e.event_type === "auth_event") {
    const a = e.auth ?? {};
    return `${a.action} user=${a.user} result=${a.result}`;
  }
  if (e.event_type === "inventory") {
    const inv = e.inventory ?? {};
    return `${inv.query_name} (${inv.action})`;
  }
  return e.event_type;
}
