import type { ProcessNode } from "../api/types";

// Recursive indented tree. Nodes whose event triggered an alert are
// highlighted via the `alerted` set of event ids; synthetic parents (no
// create event inside the window, event_id null) render dimmed.
interface Props {
  roots: ProcessNode[];
  alerted?: Set<string>;
}

function TreeNode({ node, alerted }: { node: ProcessNode; alerted?: Set<string> }) {
  const hit = node.event_id !== null && alerted?.has(node.event_id);
  return (
    <li>
      <div className={`pnode${hit ? " alerted" : ""}${node.event_id === null ? " synthetic" : ""}`}>
        <span className="pid">{node.pid}</span>
        <span className="pname">{node.name ?? "?"}</span>
        {node.user && <span className="puser">{node.user}</span>}
        {node.cmdline && <code className="pcmd">{node.cmdline}</code>}
      </div>
      {node.children.length > 0 && (
        <ul>
          {node.children.map((child) => (
            <TreeNode key={child.pid} node={child} alerted={alerted} />
          ))}
        </ul>
      )}
    </li>
  );
}

export function ProcessTree({ roots, alerted }: Props) {
  if (roots.length === 0) {
    return <p className="muted">no process events in the incident window</p>;
  }
  return (
    <ul className="ptree">
      {roots.map((root) => (
        <TreeNode key={root.pid} node={root} alerted={alerted} />
      ))}
    </ul>
  );
}
