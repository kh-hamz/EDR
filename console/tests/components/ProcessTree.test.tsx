import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import type { ProcessNode } from "../../src/api/types";
import { ProcessTree } from "../../src/components/ProcessTree";

function node(pid: number, name: string, extra: Partial<ProcessNode> = {}): ProcessNode {
  return {
    pid,
    name,
    cmdline: null,
    user: null,
    time: "2026-07-11T10:00:00Z",
    event_id: `ev-${pid}`,
    children: [],
    ...extra,
  };
}

it("renders nested children under their parent", () => {
  const roots = [node(100, "sshd", { children: [node(200, "bash", { children: [node(300, "nc")] })] })];
  render(<ProcessTree roots={roots} />);
  expect(screen.getByText("sshd")).toBeTruthy();
  expect(screen.getByText("bash")).toBeTruthy();
  expect(screen.getByText("nc")).toBeTruthy();
});

it("highlights nodes whose event fired an alert", () => {
  const roots = [node(100, "bash", { children: [node(200, "nc")] })];
  render(<ProcessTree roots={roots} alerted={new Set(["ev-200"])} />);
  expect(screen.getByText("nc").closest(".pnode")!.className).toContain("alerted");
  expect(screen.getByText("bash").closest(".pnode")!.className).not.toContain("alerted");
});

it("dims synthetic parents that had no create event", () => {
  const roots = [node(100, "sshd", { event_id: null, children: [node(200, "bash")] })];
  render(<ProcessTree roots={roots} />);
  expect(screen.getByText("sshd").closest(".pnode")!.className).toContain("synthetic");
});

it("shows a placeholder for an empty tree", () => {
  render(<ProcessTree roots={[]} />);
  expect(screen.getByText(/no process events/)).toBeTruthy();
});
