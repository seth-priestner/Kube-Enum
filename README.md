# kube-enum.py

Read-only Kubernetes reconnaissance and hardening aide.

`kube-enum.py` collects Kubernetes cluster metadata — communication topology, RBAC bindings, NetworkPolicy coverage, ServiceAccount configuration, and potential lateral-movement or container-escape risks.  
It outputs **JSON**, **Graphviz DOT**, **HTML**, and optionally **PNG** visualizations.

---

## Features

### Inventory
- Namespaces and Pods (labels, owner refs, images, node, ServiceAccount).

### RBAC
- Lists all `RoleBinding` and `ClusterRoleBinding` visible to the current identity.
- Flags over-privilege (e.g., `cluster-admin`, wildcard verbs/resources, sensitive verbs).

### NetworkPolicy
- **Effective isolation analysis**:
  - Per-pod ingress/egress isolation (`no-isolation`, `deny-all`, `allow-some`).
  - Resolves `podSelector` / `namespaceSelector` / `ipBlock` peers.
  - Aggregates ports (protocol, port, endPort).
- **Topology aide**: summarized selector view for graphing.

### Service Accounts
- Pod → SA mapping.
- **Static** rules per SA (aggregated from RoleBindings / ClusterRoleBindings).
- **Optional impersonation mode** (`--impersonate-sa`) to probe as each SA.
- **Local SA enumeration** (`--local-sa-enum`) to show current in-pod identity and `/var/run/secrets` metadata.

### Lateral Movement & Escape Heuristics
- Detects:
  - `privileged: true`, `allowPrivilegeEscalation: true`, running as root.
  - Dangerous capabilities (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, etc.).
  - `hostNetwork`, `hostPID`, `hostIPC`, `shareProcessNamespace`.
  - Sensitive `hostPath` mounts, runtime sockets, writable system paths.
- All findings mapped to indicative MITRE ATT&CK tactics.

### Visibility Warnings
- Collects API exceptions and missing permissions in `results.json["warnings"]` and the HTML report.

---

## Outputs

| File | Description |
|------|--------------|
| `results.json` | Full machine-readable results |
| `graph.dot` | Graphviz DOT graph (namespaces, pods, peers) |
| `graph.png` | Optional PNG rendering (`--render-dot` if `dot` present) |
| `report.html` | Self-contained interactive report |

Render manually:
```bash
dot -Tpng graph.dot -o graph.png
```

---

## Requirements

- Python **3.9+**
- Packages:
  ```bash
  pip install kubernetes==29.0.0
  ```
- To render PNG/SVG graphs: install **Graphviz** CLI (`dot`).

---

## Usage

```bash
python kube-enum.py [--context NAME] [--kubeconfig PATH] [--namespace NS]   [--outdir DIR]   [--per-sa-static]   [--impersonate-sa] [--sa-namespace NS] [--sa-name NAME]   [--local-sa-enum]   [--render-dot]
```

### Examples

| Command | Description |
|----------|--------------|
| `python kube-enum.py` | Sweep all namespaces |
| `python kube-enum.py --namespace prod` | Limit to one namespace |
| `python kube-enum.py --per-sa-static --local-sa-enum` | Include static SA analysis + local mount data |
| `python kube-enum.py --impersonate-sa` | Impersonate all SAs (requires `impersonate`) |
| `python kube-enum.py --render-dot` | Generate `graph.png` using Graphviz |

---

## NetworkPolicy Semantics

| Term | Meaning |
|------|----------|
| `no-isolation` | No policy of that type selects the pod (default allow) |
| `deny-all` | Policy selects pod but defines no rules (default deny) |
| `allow-some` | Policy selects pod and has rules |

- Resolves peers by **live namespace and pod labels**.
- Records CIDRs and ports per rule.
- Ports aggregated as sets of `(protocol, port[, endPort])`.

> This is a correlation and isolation signal — not a full CNI-level policy solver.

---

## Data Model (Highlights)

```json
"netpol_effective": {
  "ns": {
    "pod": {
      "ingress": {
        "effective": "allow-some",
        "aggregate": {"peer_pod_count":3,"peer_namespace_count":2,"cidr_count":1,"ports":["TCP/80"]}
      },
      "egress": { ... }
    }
  }
}
```

Also included:
- `rbac.bindings` with over-privilege reasons.
- `api_probes` with SSAR checks and read attempt results.
- `service_accounts` sections (static rules, impersonated probes, pod usage).
- `lateral_movement_hints` with per-container findings.
- `warnings` for visibility gaps.

---

## Permissions

| Capability | Needed for |
|-------------|-------------|
| `list` on `namespaces`, `pods`, `configmaps`, `secrets`, `nodes` | Core discovery |
| `list` on `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings` | RBAC mapping |
| `list` on `networkpolicies` | NetworkPolicy analysis |
| `create` on `selfsubjectaccessreviews.authorization.k8s.io` | SSAR probes |
| `impersonate` on SAs | Optional impersonated probes |

Everything else is **read-only**.

---

## Hardening Tips

- Remove `privileged` and `allowPrivilegeEscalation`.
- Drop dangerous capabilities; avoid `ALL`, `SYS_ADMIN`, `NET_ADMIN`.
- Remove mounts to runtime sockets (`docker.sock`, `containerd.sock`, `crio.sock`).
- Disallow `hostPath` to `/`, `/etc`, `/root`, `/var/lib`, `/proc`, `/sys`, `/dev`.
- Enforce `runAsNonRoot`, non-zero `runAsUser`.
- Default deny network policies; allow by exception.
- Scope SAs tightly; avoid cluster-wide roles.

---

## Troubleshooting

| Symptom | Explanation |
|----------|--------------|
| `failed to configure kube client` | Bad/missing kubeconfig/context |
| `SSAR error: 403 Forbidden` | Identity lacks `create` on SSAR |
| `impersonation failed` | Missing `impersonate` RBAC rule |
| `graph.png` missing | Run with `--render-dot` and ensure `dot` is installed |
| Missing report sections | Check the **Warnings** section in HTML |

---

## Limitations

- No CNI-specific logic or actual packet testing.
- Named ports not resolved across Services.
- Static SA aggregation is heuristic, not full effective permissions.
- Impersonation may be audited or blocked by policy.

---

## License

**Apache License 2.0**

```text
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

SPDX-Identifier: `Apache-2.0`

---

## About

Created for authorized Kubernetes assessments and cluster hardening.
