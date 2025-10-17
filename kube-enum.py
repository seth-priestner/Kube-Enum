#!/usr/bin/env python3
 # kube-enum.py — Kubernetes comms, RBAC/NetPol, SA enum, and lateral-movement/escape heuristics
 #
 # Outputs (in --outdir):
 # - results.json
 # - graph.dot
 # - report.html
 # - graph.png (optional, if --render-dot and Graphviz 'dot' found)
 #
 # Requires:
 # pip install kubernetes==29.0.0
 #
 # Usage:
 # python kube-enum.py [--context NAME] [--kubeconfig PATH] [--namespace NS] [--outdir DIR]
 # [--per-sa-static] [--impersonate-sa] [--sa-namespace NS] [--sa-name NAME]
 # [--local-sa-enum] [--render-dot]
 import argparse
 import json
 import os
 import sys
 import socket
 import pathlib
 import hashlib
 import shutil
 import subprocess
 from datetime import datetime, timezone
 from collections import defaultdict
 from typing import Dict, List, Tuple, Any, Set
 
 from kubernetes import client, config
 from kubernetes.client import ApiException
 
 
 # ----------------------------- Helpers -----------------------------
 def ts():
 return datetime.now(timezone.utc).isoformat()
 
 
 def safe_mkdir(p):
 os.makedirs(p, exist_ok=True)
 
 
 def to_str(o):
 try:
 return json.dumps(o, sort_keys=True)
 except Exception:
 return str(o)
 
 
 def owner_string(owners):
 if not owners:
 return None
 parts = []
 for o in owners:
 parts.append(f"{o.kind}/{o.name}")
 return ", ".join(parts) if parts else None
 
 
 # ----------------------------- Authorization (SSAR) -----------------------------
 def can_i(authz_api, verb, resource, group="", namespace=None, name=None, subresource=None):
 spec = client.V1SelfSubjectAccessReviewSpec(
 resource_attributes=client.V1ResourceAttributes(
 verb=verb,
 resource=resource,
 group=group or "",
 namespace=namespace,
 name=name,
 subresource=subresource,
 )
 )
 body = client.V1SelfSubjectAccessReview(spec=spec)
 try:
 resp = authz_api.create_self_subject_access_review(body=body)
 allowed = bool(resp.status.allowed)
 reason = resp.status.reason or ""
 return allowed, reason
 except ApiException as e:
 return False, f"SSAR error: {e.status} {e.reason}"
 
 
 def try_read(list_fn, *args, **kwargs):
 try:
 objs = list_fn(*args, **kwargs)
 return {"ok": True, "count": len(objs.items or []), "error": None}
 except ApiException as e:
 return {"ok": False, "count": 0, "error": f"{e.status} {e.reason}"}
 except Exception as e:
 return {"ok": False, "count": 0, "error": str(e)}
 
 
 # ----------------------------- Detection Heuristics -----------------------------
 SENSITIVE_VERBS = {"create", "update", "patch", "delete", "deletecollection", "escalate", "bind", "impersonate"}
 SENSITIVE_RESOURCES = {
 ("", "secrets"),
 ("", "configmaps"),
 ("", "serviceaccounts"),
 ("rbac.authorization.k8s.io", "rolebindings"),
 ("rbac.authorization.k8s.io", "clusterrolebindings"),
 ("rbac.authorization.k8s.io", "roles"),
 ("rbac.authorization.k8s.io", "clusterroles"),
 ("", "nodes"),
 }
 
 
 def is_overprivileged_role_rules(rules):
 reasons = []
 for r in rules or []:
 verbs = set((r.verbs or []))
 res = set((r.resources or []))
 api_groups = set((r.api_groups or []))
 if "*" in verbs:
 reasons.append("wildcard verbs (*)")
 if "*" in res:
 reasons.append("wildcard resources (*)")
 if verbs & SENSITIVE_VERBS:
 reasons.append(f"sensitive verbs: {', '.join(sorted(verbs & SENSITIVE_VERBS))}")
 for grp in (api_groups or {""}):
 for rs in (res or []):
 if (grp, rs) in SENSITIVE_RESOURCES:
 reasons.append(f"access to sensitive resource {grp or 'core'}/{rs}")
 return list(sorted(set(reasons)))
 
 
 def binding_subjects(sbj_list):
 out = []
 for s in sbj_list or []:
 out.append({"kind": s.kind, "name": s.name, "namespace": s.namespace})
 return out
 
 
 # ----------------------------- Label/Selector Matching -----------------------------
 def match_label_selector(labels: dict, selector) -> bool:
 if selector is None:
 return True
 if selector.match_labels:
 for k, v in selector.match_labels.items():
 if labels.get(k) != v:
 return False
 for expr in selector.match_expressions or []:
 key = expr.key
 op = expr.operator
 vals = set(expr.values or [])
 lv = labels.get(key)
 if op == "In":
 if lv not in vals:
 return False
 elif op == "NotIn":
 if lv in vals:
 return False
 elif op == "Exists":
 if key not in labels:
 return False
 elif op == "DoesNotExist":
 if key in labels:
 return False
 else:
 return False
 return True
 
 
 # ----------------------------- NetworkPolicy Mapping (topology aide) -----------------------------
 def compute_netpol_effects(pods_by_ns, netpols_by_ns):
 """
 Topology aide (legacy). For each pod, list policies applied and summarize peer selectors.
 """
 results = defaultdict(dict)
 for ns, pods in pods_by_ns.items():
 npols = netpols_by_ns.get(ns, [])
 for p in pods:
 p_labels = p.metadata.labels or {}
 p_name = p.metadata.name
 applied = {"ingress": [], "egress": [], "policies_applied": []}
 
 for np in npols:
 spec = np.spec
 if spec is None:
 continue
 if not match_label_selector(p_labels, spec.pod_selector):
 continue
 applied["policies_applied"].append(np.metadata.name)
 
 # Ingress
 for ing in spec.ingress or []:
 for frm in ing._from or []: # reserved keyword exposed as _from
 if frm.pod_selector is not None:
 applied["ingress"].append(
 {"type": "podSelector", "ns": ns, "selector": to_str(frm.pod_selector.to_dict())}
 )
 if frm.namespace_selector is not None:
 applied["ingress"].append(
 {"type": "nsSelector", "selector": to_str(frm.namespace_selector.to_dict())}
 )
 if frm.ip_block is not None:
 applied["ingress"].append(
 {"type": "ipBlock", "cidr": frm.ip_block.cidr, "except": frm.ip_block._except or []}
 )
 
 # Egress
 for eg in spec.egress or []:
 for to in eg.to or []:
 if to.pod_selector is not None:
 applied["egress"].append(
 {"type": "podSelector", "ns": ns, "selector": to_str(to.pod_selector.to_dict())}
 )
 if to.namespace_selector is not None:
 applied["egress"].append(
 {"type": "nsSelector", "selector": to_str(to.namespace_selector.to_dict())}
 )
 if to.ip_block is not None:
 applied["egress"].append(
 {"type": "ipBlock", "cidr": to.ip_block.cidr, "except": to.ip_block._except or []}
 )
 
 results[ns][p_name] = applied
 return results
 
 
 # ----------------------------- NetworkPolicy Effective Analysis -----------------------------
 def _policy_types(spec: client.V1NetworkPolicySpec) -> Set[str]:
 """
 Per spec:
 - If policyTypes set, use it.
 - Else infer: include Ingress if ingress rules present; include Egress if egress rules present; if none present, default ["Ingress"].
 """
 if spec.policy_types:
 return set([t for t in spec.policy_types])
 types = set()
 if spec.ingress:
 types.add("Ingress")
 if spec.egress:
 types.add("Egress")
 if not types:
 types = {"Ingress"}
 return types
 
 
 def analyze_network_policies(
 namespaces: List[str],
 ns_labels: Dict[str, Dict[str, str]],
 pods_by_ns: Dict[str, List[client.V1Pod]],
 netpols_by_ns: Dict[str, List[client.V1NetworkPolicy]],
 ):
 """
 For each pod: isolation booleans, effective status (no-isolation | deny-all | allow-some),
 resolved peers (pods/namespaces) and ports per rule.
 """
 # indexes to resolve selectors
 pod_labels_index: Dict[str, Dict[str, Dict[str, str]]] = {}
 for ns, pods in pods_by_ns.items():
 pod_labels_index[ns] = {p.metadata.name: (p.metadata.labels or {}) for p in pods}
 
 def resolve_peer(peer, policy_ns: str):
 res = {"pods": [], "namespaces": [], "cidrs": []}
 # ipBlock
 if peer.ip_block is not None:
 res["cidrs"].append({"cidr": peer.ip_block.cidr, "except": peer.ip_block._except or []})
 return res
 
 # Determine namespace set
 if peer.namespace_selector is not None:
 ns_set = [n for n in namespaces if match_label_selector(ns_labels.get(n, {}), peer.namespace_selector)]
 else:
 ns_set = [policy_ns]
 
 # Determine pod set
 if peer.pod_selector is not None:
 for ns in ns_set:
 for pod_name, labels in pod_labels_index.get(ns, {}).items():
 if match_label_selector(labels, peer.pod_selector):
 res["pods"].append(f"{ns}/{pod_name}")
 res["namespaces"].extend(sorted(set(ns_set)))
 else:
 # namespace-only selector: all pods in those namespaces
 for ns in ns_set:
 for pod_name in pod_labels_index.get(ns, {}):
 res["pods"].append(f"{ns}/{pod_name}")
 res["namespaces"].extend(sorted(set(ns_set)))
 
 # de-dup pods
 res["pods"] = sorted(set(res["pods"]))
 return res
 
 def ports_list(rule_ports: List[client.V1NetworkPolicyPort]):
 out = []
 for prt in rule_ports or []:
 proto = (prt.protocol or "TCP")
 # port can be int-or-string; end_port is optional
 port_val = getattr(prt, "port", None)
 end_port = getattr(prt, "end_port", None)
 # normalize to string for JSON friendliness
 if port_val is None:
 pv = None
 elif hasattr(port_val, "to_dict"): # unlikely, but safe
 pv = to_str(port_val.to_dict())
 else:
 pv = str(port_val)
 out.append({"protocol": proto, "port": pv, "end_port": end_port})
 return out
 
 per_pod = defaultdict(dict)
 
 for ns, pods in pods_by_ns.items():
 npols = netpols_by_ns.get(ns, [])
 for p in pods:
 p_name = p.metadata.name
 p_labels = p.metadata.labels or {}
 
 selecting = []
 for np in npols:
 if np.spec and match_label_selector(p_labels, np.spec.pod_selector):
 selecting.append(np)
 
 # policy types selecting this pod
 types = set()
 for np in selecting:
 types |= _policy_types(np.spec)
 
 # isolation booleans
 ingress_iso = "Ingress" in types
 egress_iso = "Egress" in types
 
 # accumulate rules
 ingress_rules = []
 egress_rules = []
 
 for np in selecting:
 spec = np.spec
 ptypes = _policy_types(spec)
 if "Ingress" in ptypes:
 for ing in spec.ingress or []:
 peers = {"pods": [], "namespaces": [], "cidrs": []}
 for frm in ing._from or []:
 r = resolve_peer(frm, ns)
 peers["pods"].extend(r["pods"])
 peers["namespaces"].extend(r["namespaces"])
 peers["cidrs"].extend(r["cidrs"])
 ingress_rules.append({"policy": np.metadata.name, "peers": _dedup_peers(peers), "ports": ports_list(ing.ports)})
 if "Egress" in ptypes:
 for eg in spec.egress or []:
 peers = {"pods": [], "namespaces": [], "cidrs": []}
 for to in eg.to or []:
 r = resolve_peer(to, ns)
 peers["pods"].extend(r["pods"])
 peers["namespaces"].extend(r["namespaces"])
 peers["cidrs"].extend(r["cidrs"])
 egress_rules.append({"policy": np.metadata.name, "peers": _dedup_peers(peers), "ports": ports_list(eg.ports)})
 
 # effective status per direction
 ingress_effective = (
 "no-isolation" if not ingress_iso else ("deny-all" if len(ingress_rules) == 0 else "allow-some")
 )
 egress_effective = (
 "no-isolation" if not egress_iso else ("deny-all" if len(egress_rules) == 0 else "allow-some")
 )
 
 per_pod[ns][p_name] = {
 "policies_applied": [{"name": np.metadata.name, "types": sorted(list(_policy_types(np.spec)))} for np in selecting],
 "ingress": {
 "isolated": ingress_iso,
 "effective": ingress_effective,
 "rules": ingress_rules,
 "aggregate": _aggregate_rules(ingress_rules),
 },
 "egress": {
 "isolated": egress_iso,
 "effective": egress_effective,
 "rules": egress_rules,
 "aggregate": _aggregate_rules(egress_rules),
 },
 }
 
 return per_pod
 
 
 def _dedup_peers(peers: Dict[str, List[Any]]) -> Dict[str, Any]:
 return {
 "pods": sorted(set(peers.get("pods", []))),
 "namespaces": sorted(set(peers.get("namespaces", []))),
 "cidrs": peers.get("cidrs", []), # ipBlocks may duplicate; keep as-listed
 }
 
 
 def _aggregate_rules(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
 pods = set()
 nss = set()
 cidrs = []
 ports = set()
 named_ports = set()
 for r in rules:
 pods |= set(r["peers"].get("pods", []))
 nss |= set(r["peers"].get("namespaces", []))
 cidrs.extend(r["peers"].get("cidrs", []))
 for pr in r.get("ports", []):
 pv = pr.get("port")
 proto = pr.get("protocol", "TCP")
 if pv is None:
 ports.add(f"{proto}/ALL")
 else:
 # Distinguish named ports
 if pv.isdigit():
 if pr.get("end_port"):
 ports.add(f"{proto}/{pv}-{pr['end_port']}")
 else:
 ports.add(f"{proto}/{pv}")
 else:
 named_ports.add(f"{proto}/{pv}")
 return {
 "peer_pod_count": len(pods),
 "peer_namespace_count": len(nss),
 "cidr_count": len(cidrs),
 "ports": sorted(list(ports)),
 "named_ports": sorted(list(named_ports)),
 }
 
 
 # ----------------------------- DOT Graph -----------------------------
 def build_dot(namespaces, pods_by_ns, netpol_effects):
 lines = []
 lines.append("digraph k8s {")
 lines.append(' graph [rankdir="LR"];')
 lines.append(' node [shape=box, style=rounded];')
 
 for ns in namespaces:
 lines.append(f' subgraph "cluster_{ns}" {{')
 lines.append(f' label="ns/{ns}";')
 for p in pods_by_ns.get(ns, []):
 pid = f"{ns}__{p.metadata.name}"
 img_list = sorted({c.image for c in (p.spec.containers or [])})
 img_txt = "\\n".join(img_list[:2]) + ("\\n..." if len(img_list) > 2 else "")
 lbl = f"{p.metadata.name}\\n{img_txt}"
 lines.append(f' "{pid}" [label="{lbl}"];')
 lines.append(" }")
 
 anon_idx = 0
 
 def anon(label):
 nonlocal anon_idx
 anon_idx += 1
 nid = f"anon_{anon_idx}"
 lines.append(f' "{nid}" [label="{label}", shape=note, style="dashed"];')
 return nid
 
 for ns, pods in netpol_effects.items():
 for pod_name, effects in pods.items():
 pid = f"{ns}__{pod_name}"
 for peer in effects.get("ingress", []):
 if peer["type"] == "ipBlock":
 nid = anon(f'ingress ipBlock\\n{peer["cidr"]}')
 else:
 nid = anon(f'ingress {peer["type"]}\\n{peer.get("selector","")}')
 lines.append(f' "{nid}" -> "{pid}";')
 
 for peer in effects.get("egress", []):
 if peer["type"] == "ipBlock":
 nid = anon(f'egress ipBlock\\n{peer["cidr"]}')
 else:
 nid = anon(f'egress {peer["type"]}\\n{peer.get("selector","")}')
 lines.append(f' "{pid}" -> "{nid}";')
 
 lines.append("}")
 return "\n".join(lines)
 
 
 def maybe_render_dot(dot_path: str, out_png: str) -> Tuple[bool, str]:
 dot_bin = shutil.which("dot")
 if not dot_bin:
 return False, "Graphviz 'dot' not found on PATH"
 try:
 subprocess.run([dot_bin, "-Tpng", dot_path, "-o", out_png], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
 return True, ""
 except subprocess.CalledProcessError as e:
 return False, f"dot render failed: {e}"
 
 
 # ----------------------------- HTML Report -----------------------------
 def build_html(data):
 generated = ts()
 title = "K8s Communication, RBAC/NetPol, SA & Lateral Movement Report"
 
 def esc(s):
 return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
 
 op_bindings = [b for b in data["rbac"]["bindings"] if b.get("overprivileged_reasons")]
 netpol_ns = len([n for n, arr in data["network_policies"].items() if arr])
 api_denied = [p for p in data["api_probes"] if not p["ssar_allowed"]]
 lm = data.get("lateral_movement_hints", {})
 lm_count = sum(len(v) for v in lm.values())
 warnings = data.get("warnings", [])
 
 mitre_tags = set()
 if op_bindings:
 mitre_tags.update({"Privilege Escalation", "Defense Evasion"})
 if netpol_ns == 0:
 mitre_tags.add("Lateral Movement")
 if api_denied:
 mitre_tags.add("Discovery")
 if lm_count:
 mitre_tags.update({"Lateral Movement", "Privilege Escalation", "Credential Access"})
 
 # Build API probes rows safely
 probe_rows = []
 for p in data["api_probes"]:
 res_name = f'{p["group"]+"/"+p["resource"]}' if p["group"] else p["resource"]
 attempted = "yes" if p["attempted"] else "no"
 result_text = p.get("attempt_error") if p.get("attempt_error") else f"ok:{p.get('attempt_count',0)}"
 probe_rows.append(
 f'<tr><td>{esc(res_name)}</td><td>{esc(p.get("namespace") or "-")}</td>'
 f'<td>{"✅" if p["ssar_allowed"] else "❌"}</td><td>{esc(p.get("ssar_reason") or "")}</td>'
 f"<td>{esc(attempted)}</td><td>{esc(result_text)}</td></tr>"
 )
 
 # Netpol effective rows (show only interesting)
 np_eff = data.get("netpol_effective", {})
 eff_rows = []
 for ns, pods in np_eff.items():
 for pod, det in pods.items():
 ing = det["ingress"]["effective"]
 eg = det["egress"]["effective"]
 if ing != "no-isolation" or eg != "no-isolation":
 eff_rows.append(
 f"<tr><td>{esc(ns)}</td><td>{esc(pod)}</td>"
 f"<td>{esc(ing)}</td><td>{esc(det['ingress']['aggregate']['peer_pod_count'])}/ns:{esc(det['ingress']['aggregate']['peer_namespace_count'])}/cidr:{esc(det['ingress']['aggregate']['cidr_count'])}</td>"
 f"<td>{esc(eg)}</td><td>{esc(det['egress']['aggregate']['peer_pod_count'])}/ns:{esc(det['egress']['aggregate']['peer_namespace_count'])}/cidr:{esc(det['egress']['aggregate']['cidr_count'])}</td></tr>"
 )
 
 html = f"""<!doctype html>
 <html>
 <head>
 <meta charset="utf-8"/>
 <title>{esc(title)}</title>
 <style>
 body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
 h1,h2,h3 {{ margin: 0.6em 0; }}
 code, pre {{ background:#f6f8fa; padding: 8px; border-radius:6px; overflow:auto; display:block; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ border:1px solid #ddd; padding:6px 8px; text-align:left; vertical-align: top; }}
 .badge {{ display:inline-block; background:#eef; color:#223; padding:2px 8px; border-radius:12px; margin-right:6px; font-size:12px; }}
 .warn {{ color:#a33; font-weight:600; }}
 .ok {{ color:#2a6; font-weight:600; }}
 small {{ color:#666; }}
 ul {{ margin: 4px 0 4px 18px; }}
 </style>
 </head>
 <body>
 <h1>{esc(title)}</h1>
 <small>Generated: {esc(generated)}</small>
 
 <h2>At-a-Glance</h2>
 <p>
 <span class="badge">Namespaces: {len(data["namespaces"])}</span>
 <span class="badge">Pods: {sum(len(v) for v in data["pods"].values())}</span>
 <span class="badge">NetworkPolicies: {sum(len(v) for v in data["network_policies"].values())}</span>
 <span class="badge">RoleBindings/ClusterRoleBindings: {len(data["rbac"]["bindings"])}</span>
 <span class="badge">Lateral Movement/HCE Hints: {lm_count}</span>
 </p>
 <p>
 <span class="badge">Over-Privileged Bindings: {len(op_bindings)}</span>
 <span class="badge">Namespaces with NetPols: {netpol_ns}</span>
 <span class="badge">API Probes Denied: {len(api_denied)}</span>
 </p>
 <h3>MITRE ATT&CK Tactics (indicative)</h3>
 <p>{" ".join(f'<span class="badge">{esc(t)}</span>' for t in sorted(mitre_tags)) or "<small>No clear signals.</small>"}</p>
 
 <h2>Warnings</h2>
 {("<ul>" + "".join(f"<li>{esc(w.get('where','?'))}: {esc(w.get('error',''))}</li>" for w in warnings) + "</ul>") if warnings else "<small>None recorded.</small>"}
 
 <h2>NetworkPolicy Effective Status (per pod)</h2>
 <table>
 <thead><tr><th>Namespace</th><th>Pod</th><th>Ingress</th><th>Ingress peers (pods/ns/cidrs)</th><th>Egress</th><th>Egress peers (pods/ns/cidrs)</th></tr></thead>
 <tbody>
 {''.join(eff_rows) if eff_rows else '<tr><td colspan="6"><small>No pods under isolation or policy effects detected (or no visibility).</small></td></tr>'}
 </tbody>
 </table>
 
 <h2>Potential Lateral Movement & Host-Container Escape Risks</h2>
 <table>
 <thead><tr><th>Namespace</th><th>Pod</th><th>Container</th><th>Findings</th></tr></thead>
 <tbody>
 """
 # LM table
 for ns in sorted(lm.keys()):
 for item in lm[ns]:
 pod = esc(item["pod"])
 for c in item["containers"]:
 cname = esc(c["name"])
 findings = "<ul>" + "".join(f"<li>{esc(f)}</li>" for f in c["findings"]) + "</ul>"
 html += f"<tr><td>{esc(ns)}</td><td>{pod}</td><td>{cname}</td><td>{findings}</td></tr>\n"
 if lm_count == 0:
 html += '<tr><td colspan="4"><small>No obvious host-escape/lateral-movement risk flags found by heuristics.</small></td></tr>\n'
 html += "</tbody></table>\n"
 
 html += """
 <h2>Over-Privileged RBAC Bindings</h2>
 <table>
 <thead><tr><th>Scope</th><th>Name</th><th>RoleRef</th><th>Subjects</th><th class="warn">Reasons</th></tr></thead>
 <tbody>
 """
 for b in op_bindings:
 scope = "Cluster" if b["kind"] == "ClusterRoleBinding" else f'ns/{b.get("namespace","")}'
 subs = ", ".join(
 f'{s["kind"]}:{s["name"]}' + (f'({s["namespace"]})' if s.get("namespace") else "") for s in b["subjects"]
 )
 reasons = "; ".join(b["overprivileged_reasons"])
 html += f'<tr><td>{esc(scope)}</td><td>{esc(b["name"])}</td><td>{esc(b["roleRef"])}</td><td>{esc(subs)}</td><td class="warn">{esc(reasons)}</td></tr>\n'
 if not op_bindings:
 html += '<tr><td colspan="5"><small>No obvious over-privileged bindings detected by heuristics.</small></td></tr>\n'
 html += "</tbody></table>\n"
 
 html += """
 <h2>API Access Probes (read-only)</h2>
 <table>
 <thead><tr><th>Resource</th><th>Namespace</th><th>SSAR Allowed</th><th>SSAR Reason</th><th>Attempted</th><th>Result</th></tr></thead>
 <tbody>
 """
 html += "\n".join(probe_rows)
 html += "</tbody></table>\n"
 
 # ServiceAccount summary (if present)
 sa = data.get("service_accounts", {})
 sa_static = sa.get("static_rules", {})
 sa_pod_usage = sa.get("pod_usage", {})
 any_sa = bool(sa_static or sa_pod_usage or sa.get("impersonated_probes"))
 
 if any_sa:
 html += """
 <h2>Service Accounts Overview</h2>
 <table>
 <thead><tr><th>Namespace</th><th>ServiceAccount</th><th>Pods Using</th><th>Over-Priv Reasons</th></tr></thead>
 <tbody>
 """
 for ns in sorted(sa_pod_usage.keys() | sa_static.keys()):
 sa_names = set(sa_pod_usage.get(ns, {}).keys()) | set(sa_static.get(ns, {}).keys())
 for name in sorted(sa_names):
 pods = sa_pod_usage.get(ns, {}).get(name, [])
 reasons = (sa_static.get(ns, {}).get(name, {}) or {}).get("overprivileged_reasons", [])
 html += f"<tr><td>{esc(ns)}</td><td>{esc(name)}</td><td>{len(pods)}</td><td>{esc('; '.join(reasons))}</td></tr>\n"
 html += "</tbody></table>\n"
 
 html += f"""
 <h2>Local ServiceAccount (if --local-sa-enum)</h2>
 <pre><code>{esc(json.dumps(data.get("local_service_account", {}), indent=2, sort_keys=True))}</code></pre>
 
 <h2>Raw Data (JSON)</h2>
 <pre><code>{esc(json.dumps(data, indent=2, sort_keys=True))}</code></pre>
 
 <hr/>
 <small>Policy math here is best-effort. It's a correlation + isolation signal, not a full enforcement engine.</small>
 </body>
 </html>
 """
 return html
 
 
 # ----------------------------- ServiceAccount (cluster-wide) -----------------------------
 def list_service_accounts(core: client.CoreV1Api, namespaces: List[str], limit_ns=None, limit_name=None, warnings=None):
 sa_index = defaultdict(list)
 for ns in namespaces:
 if limit_ns and ns != limit_ns:
 continue
 try:
 res = core.list_namespaced_service_account(ns)
 for sa in res.items or []:
 if limit_name and sa.metadata.name != limit_name:
 continue
 sa_index[ns].append(sa)
 except ApiException as e:
 msg = f"list serviceaccounts in ns/{ns}: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 if warnings is not None:
 warnings.append({"where": f"ns/{ns} serviceaccounts", "error": msg})
 return sa_index
 
 
 def pods_by_service_account(pods_by_ns: Dict[str, List[client.V1Pod]]):
 mapping = defaultdict(lambda: defaultdict(list))
 for ns, pods in pods_by_ns.items():
 for p in pods:
 sa = getattr(p.spec, "service_account_name", "default") or "default"
 mapping[ns][sa].append(p.metadata.name)
 return mapping
 
 
 def aggregate_rules_for_role_ref(role_ref_kind: str, role_ref_name: str, ns: str, roles_by_key: Dict[Tuple[str, str], List]):
 if role_ref_kind == "ClusterRole":
 return roles_by_key.get(("cluster", role_ref_name), []) or []
 else:
 return roles_by_key.get((ns, role_ref_name), []) or []
 
 
 def aggregate_rules_for_sa(ns: str, sa_name: str, rbacapi: client.RbacAuthorizationV1Api, roles_by_key: Dict[Tuple[str, str], List], warnings=None):
 rules = []
 try:
 rbs = rbacapi.list_namespaced_role_binding(ns).items or []
 except ApiException as e:
 msg = f"list rolebindings in ns/{ns}: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 if warnings is not None:
 warnings.append({"where": f"ns/{ns} rolebindings", "error": msg})
 rbs = []
 for b in rbs:
 for s in b.subjects or []:
 if s.kind == "ServiceAccount" and s.name == sa_name and (s.namespace or ns) == ns:
 rules += aggregate_rules_for_role_ref(b.role_ref.kind, b.role_ref.name, ns, roles_by_key)
 try:
 crbs = rbacapi.list_cluster_role_binding().items or []
 except ApiException as e:
 msg = f"list clusterrolebindings: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 if warnings is not None:
 warnings.append({"where": "cluster clusterrolebindings", "error": msg})
 crbs = []
 for b in crbs:
 for s in b.subjects or []:
 if s.kind == "ServiceAccount" and s.name == sa_name and (s.namespace or ns) == ns:
 rules += aggregate_rules_for_role_ref("ClusterRole", b.role_ref.name, ns, roles_by_key)
 return rules
 
 
 def build_impersonated_client(base_client: client.ApiClient, ns: str, sa_name: str):
 cfg = client.Configuration()
 base_cfg = base_client.configuration
 for attr in dir(base_cfg):
 if attr.startswith("_"):
 continue
 try:
 setattr(cfg, attr, getattr(base_cfg, attr))
 except Exception:
 pass
 imp = client.ApiClient(cfg)
 user = f"system:serviceaccount:{ns}:{sa_name}"
 imp.default_headers.update({"Impersonate-User": user})
 return imp
 
 
 def run_probes_with_client(api_client: client.ApiClient, namespaces: List[str]):
 core_i = client.CoreV1Api(api_client=api_client)
 authz_i = client.AuthorizationV1Api(api_client=api_client)
 probes = []
 for t in [{"group": "", "resource": "nodes"}, {"group": "", "resource": "namespaces"}]:
 allowed, reason = can_i(authz_i, "list", t["resource"], group=t["group"])
 if allowed:
 attempt = try_read(core_i.list_node if t["resource"] == "nodes" else core_i.list_namespace)
 else:
 attempt = {"ok": False, "count": 0, "error": "not attempted (denied by SSAR)"}
 probes.append(
 {
 "group": t["group"],
 "resource": t["resource"],
 "namespace": None,
 "ssar_allowed": allowed,
 "ssar_reason": reason,
 "attempted": allowed,
 "attempt_error": attempt["error"],
 "attempt_count": attempt["count"],
 }
 )
 for ns in namespaces:
 for res in ["secrets", "configmaps", "pods"]:
 allowed, reason = can_i(authz_i, "list", res, namespace=ns)
 if allowed:
 if res == "secrets":
 attempt = try_read(core_i.list_namespaced_secret, ns)
 elif res == "configmaps":
 attempt = try_read(core_i.list_namespaced_config_map, ns)
 else:
 attempt = try_read(core_i.list_namespaced_pod, ns)
 else:
 attempt = {"ok": False, "count": 0, "error": "not attempted (denied by SSAR)"}
 probes.append(
 {
 "group": "",
 "resource": res,
 "namespace": ns,
 "ssar_allowed": allowed,
 "ssar_reason": reason,
 "attempted": allowed,
 "attempt_error": attempt["error"],
 "attempt_count": attempt["count"],
 }
 )
 return probes
 
 
 # ----------------------------- Local SA enumeration (in-pod) -----------------------------
 def sha256_file(path: str, chunk=65536):
 h = hashlib.sha256()
 with open(path, "rb") as f:
 while True:
 b = f.read(chunk)
 if not b:
 break
 h.update(b)
 return h.hexdigest()
 
 
 def enum_local_sa_mounts(root="/var/run/secrets"):
 out = {
 "root": root,
 "exists": os.path.isdir(root),
 "serviceaccount_path": None,
 "namespace": None,
 "token_len": None,
 "token_sha256": None,
 "ca_crt_sha256": None,
 "files": [],
 }
 if not out["exists"]:
 return out
 
 sa_path = os.path.join(root, "kubernetes.io", "serviceaccount")
 if os.path.isdir(sa_path):
 out["serviceaccount_path"] = sa_path
 ns_file = os.path.join(sa_path, "namespace")
 tok_file = os.path.join(sa_path, "token")
 ca_file = os.path.join(sa_path, "ca.crt")
 if os.path.isfile(ns_file):
 try:
 with open(ns_file, "r", encoding="utf-8", errors="ignore") as f:
 out["namespace"] = f.read().strip()
 except Exception:
 pass
 if os.path.isfile(tok_file):
 try:
 sz = os.path.getsize(tok_file)
 out["token_len"] = int(sz)
 out["token_sha256"] = sha256_file(tok_file)
 except Exception:
 pass
 if os.path.isfile(ca_file):
 try:
 out["ca_crt_sha256"] = sha256_file(ca_file)
 except Exception:
 pass
 
 for p in pathlib.Path(root).rglob("*"):
 try:
 if p.is_file():
 out["files"].append(
 {
 "path": str(p),
 "size": int(p.stat().st_size),
 "mode": oct(p.stat().st_mode & 0o777),
 "sha256": sha256_file(str(p))
 if p.name in ("token", "ca.crt") or p.suffix == ".token"
 else None,
 }
 )
 except Exception:
 continue
 return out
 
 
 def get_current_identity(authn_api: client.AuthenticationV1Api):
 body = client.V1SelfSubjectReview(spec=client.V1SelfSubjectReviewSpec())
 try:
 resp = authn_api.create_self_subject_review(body=body)
 ui = resp.status.user_info if resp and resp.status else None
 username = getattr(ui, "username", None)
 groups = getattr(ui, "groups", None) or []
 extra = getattr(ui, "extra", None)
 sa_ns = sa_name = None
 if username and username.startswith("system:serviceaccount:"):
 parts = username.split(":")
 if len(parts) >= 4:
 sa_ns, sa_name = parts[2], parts[3]
 return {
 "username": username,
 "groups": groups,
 "extra": extra.to_dict() if hasattr(extra, "to_dict") else extra,
 "parsed_serviceaccount": {"namespace": sa_ns, "name": sa_name},
 }
 except ApiException as e:
 return {"error": f"{e.status} {e.reason}"}
 except Exception as e:
 return {"error": str(e)}
 
 
 # ----------------------------- Lateral Movement / Host Escape Heuristics -----------------------------
 DANGEROUS_CAPS = {
 "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "NET_ADMIN", "DAC_READ_SEARCH", "DAC_OVERRIDE",
 "SYS_RAWIO", "BPF", "SYS_TIME", "SYSLOG", "SYS_CHROOT", "MKNOD"
 }
 RUNTIME_SOCKETS = {
 "/var/run/docker.sock",
 "/run/docker.sock",
 "/run/containerd/containerd.sock",
 "/var/run/containerd/containerd.sock",
 "/var/run/crio/crio.sock",
 "/var/run/crio.sock",
 }
 SENSITIVE_HOSTPATH_PREFIXES = [
 "/", "/root", "/etc", "/proc", "/sys", "/dev", "/var/lib/kubelet", "/var/lib/docker", "/var/run", "/run"
 ]
 
 def _caps(sc: client.V1SecurityContext) -> Dict[str, List[str]]:
 if not sc or not sc.capabilities:
 return {"add": [], "drop": []}
 return {
 "add": [c.upper() for c in (sc.capabilities.add or [])],
 "drop": [c.upper() for c in (sc.capabilities.drop or [])],
 }
 
 def _mk_finding(msg: str, tactic: str, severity: str = "high") -> str:
 return f"[{severity.upper()} | {tactic}] {msg}"
 
 def analyze_pod_escape_surface(pod: client.V1Pod, volumes_index: Dict[str, Any]) -> Dict[str, Any]:
 findings_per_container = []
 
 pod_sc = getattr(pod.spec, "security_context", None)
 pod_flags = []
 if getattr(pod.spec, "host_network", False):
 pod_flags.append(_mk_finding("hostNetwork enabled", "Lateral Movement", "medium"))
 if getattr(pod.spec, "host_pid", False):
 pod_flags.append(_mk_finding("hostPID enabled (can inspect host processes)", "Discovery", "high"))
 if getattr(pod.spec, "host_ipc", False):
 pod_flags.append(_mk_finding("hostIPC enabled", "Privilege Escalation", "high"))
 if getattr(pod.spec, "share_process_namespace", False):
 pod_flags.append(_mk_finding("shareProcessNamespace enabled", "Privilege Escalation", "medium"))
 
 if getattr(pod.spec, "automount_service_account_token", None) is True:
 pod_flags.append(_mk_finding("automountServiceAccountToken=true", "Credential Access", "medium"))
 
 def resolve_mount_source(vol_name: str):
 v = volumes_index.get(vol_name)
 if not v:
 return None
 if v.host_path:
 return ("hostPath", v.host_path.path, getattr(v.host_path, "type", None))
 if v.projected:
 return ("projected", "projected", None)
 if v.empty_dir:
 return ("emptyDir", None, None)
 if v.secret:
 return ("secret", v.secret.secret_name, None)
 if v.config_map:
 return ("configMap", v.config_map.name, None)
 if v.persistent_volume_claim:
 return ("pvc", v.persistent_volume_claim.claim_name, None)
 return (type(v).__name__, None, None)
 
 def scan_container(name: str, sc: client.V1SecurityContext, mounts: List[client.V1VolumeMount]):
 c_findings = list(pod_flags)
 if sc:
 if getattr(sc, "privileged", False):
 c_findings.append(_mk_finding("Privileged=true", "Privilege Escalation", "critical"))
 if getattr(sc, "allow_privilege_escalation", None) is True:
 c_findings.append(_mk_finding("allowPrivilegeEscalation=true", "Privilege Escalation", "high"))
 if getattr(sc, "run_as_user", None) == 0 or getattr(sc, "run_as_non_root", None) is False:
 c_findings.append(_mk_finding("Runs as root (runAsUser=0 / runAsNonRoot=false)", "Privilege Escalation", "medium"))
 
 caps = _caps(sc)
 added = set(caps["add"])
 bad_caps = sorted(added & DANGEROUS_CAPS)
 if bad_caps:
 c_findings.append(_mk_finding(f"Powerful Linux capabilities added: {', '.join(bad_caps)}", "Privilege Escalation", "high"))
 if "ALL" in added:
 c_findings.append(_mk_finding("ALL capabilities granted", "Privilege Escalation", "critical"))
 
 for m in mounts or []:
 src = resolve_mount_source(m.name)
 if not src:
 continue
 kind, path_or_name, _ = src
 
 if kind == "hostPath":
 hp = path_or_name or ""
 if any(hp == p or hp.startswith(p + "/") for p in SENSITIVE_HOSTPATH_PREFIXES):
 c_findings.append(_mk_finding(f"hostPath mount to '{hp}'", "Privilege Escalation", "high"))
 if hp in ("/",):
 c_findings.append(_mk_finding("hostPath '/' root-mount", "Privilege Escalation", "critical"))
 if any(hp.endswith(s) or m.mount_path.endswith(s) for s in ["/docker.sock", "/containerd.sock", "/crio.sock"]):
 c_findings.append(_mk_finding(f"hostPath likely runtime socket: {hp}", "Lateral Movement", "high"))
 
 mp = m.mount_path or ""
 if mp in RUNTIME_SOCKETS:
 c_findings.append(_mk_finding(f"Runtime socket mounted in container: {mp}", "Lateral Movement", "high"))
 
 if getattr(m, "read_only", False) is False:
 if any(mp == p or mp.startswith(p + "/") for p in ["/etc", "/root", "/var/lib", "/proc", "/sys", "/dev"]):
 c_findings.append(_mk_finding(f"Writable mount on sensitive path: {mp}", "Privilege Escalation", "high"))
 
 return {"name": name, "findings": sorted(set(c_findings))}
 
 containers = []
 for c in pod.spec.containers or []:
 containers.append(
 scan_container(
 name=c.name,
 sc=c.security_context,
 mounts=c.volume_mounts or [],
 )
 )
 for ic in pod.spec.init_containers or []:
 res = scan_container(name=f"(init){ic.name}", sc=ic.security_context, mounts=ic.volume_mounts or [])
 containers.append(res)
 
 return {"pod": pod.metadata.name, "containers": containers}
 
 
 def lateral_movement_sweep(pods_by_ns: Dict[str, List[client.V1Pod]]) -> Dict[str, List[Dict[str, Any]]]:
 out = defaultdict(list)
 for ns, pods in pods_by_ns.items():
 for p in pods:
 vols = {v.name: v for v in (p.spec.volumes or [])}
 res = analyze_pod_escape_surface(p, vols)
 if any(c["findings"] for c in res["containers"]):
 out[ns].append(res)
 return out
 
 
 # ----------------------------- Main -----------------------------
 def main():
 ap = argparse.ArgumentParser()
 ap.add_argument("--context", help="kubeconfig context name")
 ap.add_argument("--kubeconfig", help="path to kubeconfig")
 ap.add_argument("--namespace", help="limit to a single namespace")
 ap.add_argument("--outdir", default="k8s_commcheck_out", help="output directory")
 
 # SA-related
 ap.add_argument("--per-sa-static", action="store_true", help="Aggregate static RBAC rules per ServiceAccount")
 ap.add_argument("--impersonate-sa", action="store_true", help="Impersonate each ServiceAccount and run probes")
 ap.add_argument("--sa-namespace", help="Limit SA evaluation to this namespace")
 ap.add_argument("--sa-name", help="Limit SA evaluation to a single ServiceAccount (requires --sa-namespace)")
 ap.add_argument("--local-sa-enum", action="store_true", help="Enumerate current identity and /var/run/secrets")
 
 # Graph rendering
 ap.add_argument("--render-dot", action="store_true", help="If 'dot' is available, render graph.png alongside graph.dot")
 
 args = ap.parse_args()
 
 warnings: List[Dict[str, str]] = []
 
 # Load config
 try:
 if args.kubeconfig or args.context:
 config.load_kube_config(config_file=args.kubeconfig, context=args.context)
 else:
 try:
 config.load_kube_config()
 except Exception:
 config.load_incluster_config()
 except Exception as e:
 print(f"[fatal] failed to configure kube client: {e}", file=sys.stderr)
 sys.exit(2)
 
 # Clients
 core = client.CoreV1Api()
 netv1 = client.NetworkingV1Api()
 rbac = client.RbacAuthorizationV1Api()
 authz = client.AuthorizationV1Api()
 authn = client.AuthenticationV1Api()
 
 safe_mkdir(args.outdir)
 
 # Namespaces
 ns_list = []
 try:
 if args.namespace:
 ns_list = [client.V1Namespace(metadata=client.V1ObjectMeta(name=args.namespace))]
 else:
 ns_resp = core.list_namespace()
 ns_list = ns_resp.items or []
 except ApiException as e:
 msg = f"listing namespaces: {e.status} {e.reason}"
 print(f"[error] {msg}", file=sys.stderr)
 warnings.append({"where": "cluster namespaces", "error": msg})
 ns_list = []
 
 namespaces = sorted([n.metadata.name for n in ns_list])
 ns_labels = {n.metadata.name: (n.metadata.labels or {}) for n in ns_list}
 
 # Pods
 pods_by_ns: Dict[str, List[client.V1Pod]] = defaultdict(list)
 for ns in namespaces:
 try:
 pl = core.list_namespaced_pod(ns)
 for p in pl.items or []:
 pods_by_ns[ns].append(p)
 except ApiException as e:
 msg = f"list pods in ns/{ns}: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 warnings.append({"where": f"ns/{ns} pods", "error": msg})
 
 # Pod inventory
 pod_inventory = defaultdict(list)
 for ns, pods in pods_by_ns.items():
 for p in pods:
 labels = p.metadata.labels or {}
 owner = owner_string(p.metadata.owner_references)
 images = sorted({c.image for c in (p.spec.containers or [])})
 pod_inventory[ns].append(
 {
 "name": p.metadata.name,
 "labels": labels,
 "owner": owner,
 "image_list": images,
 "node": p.spec.node_name,
 "service_account": getattr(p.spec, "service_account_name", None),
 }
 )
 
 # NetworkPolicies
 netpols_by_ns: Dict[str, List[client.V1NetworkPolicy]] = defaultdict(list)
 for ns in namespaces:
 try:
 npl = netv1.list_namespaced_network_policy(ns)
 netpols_by_ns[ns] = npl.items or []
 except ApiException as e:
 msg = f"list netpols in ns/{ns}: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 warnings.append({"where": f"ns/{ns} networkpolicies", "error": msg})
 
 netpol_serialized = {ns: [np.to_dict() for np in arr] for ns, arr in netpols_by_ns.items()}
 netpol_effects = compute_netpol_effects(pods_by_ns, netpols_by_ns) # topology aide
 netpol_effective = analyze_network_policies(namespaces, ns_labels, pods_by_ns, netpols_by_ns) # isolation + resolved peers
 
 # RBAC: roles map
 roles_by_key: Dict[Tuple[str, str], List] = {}
 try:
 crs = rbac.list_cluster_role().items or []
 except ApiException as e:
 msg = f"list clusterroles: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 warnings.append({"where": "cluster clusterroles", "error": msg})
 crs = []
 for cr in crs:
 roles_by_key[("cluster", cr.metadata.name)] = cr.rules or []
 
 for ns in namespaces:
 try:
 rs = rbac.list_namespaced_role(ns).items or []
 except ApiException as e:
 msg = f"list roles in ns/{ns}: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 warnings.append({"where": f"ns/{ns} roles", "error": msg})
 rs = []
 for r in rs:
 roles_by_key[(ns, r.metadata.name)] = r.rules or []
 
 # Bindings
 all_bindings = []
 try:
 crbs = rbac.list_cluster_role_binding().items or []
 except ApiException as e:
 msg = f"list clusterrolebindings: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 warnings.append({"where": "cluster clusterrolebindings", "error": msg})
 crbs = []
 for b in crbs:
 reasons = []
 role_ref = f"{b.role_ref.kind}:{b.role_ref.name}"
 if b.role_ref.name == "cluster-admin":
 reasons.append("cluster-admin")
 rules = roles_by_key.get(("cluster", b.role_ref.name), [])
 reasons += is_overprivileged_role_rules(rules)
 all_bindings.append(
 {
 "kind": "ClusterRoleBinding",
 "name": b.metadata.name,
 "namespace": None,
 "roleRef": role_ref,
 "subjects": binding_subjects(b.subjects),
 "overprivileged_reasons": sorted(set(reasons)),
 }
 )
 
 for ns in namespaces:
 try:
 rbs = rbac.list_namespaced_role_binding(ns).items or []
 except ApiException as e:
 msg = f"list rolebindings in ns/{ns}: {e.status} {e.reason}"
 print(f"[warn] {msg}", file=sys.stderr)
 warnings.append({"where": f"ns/{ns} rolebindings", "error": msg})
 rbs = []
 for b in rbs:
 reasons = []
 role_ref = f"{b.role_ref.kind}:{b.role_ref.name}"
 if b.role_ref.kind == "ClusterRole":
 rules = roles_by_key.get(("cluster", b.role_ref.name), [])
 else:
 rules = roles_by_key.get((ns, b.role_ref.name), [])
 reasons += is_overprivileged_role_rules(rules)
 if b.role_ref.name == "cluster-admin":
 reasons.append("cluster-admin")
 all_bindings.append(
 {
 "kind": "RoleBinding",
 "name": b.metadata.name,
 "namespace": ns,
 "roleRef": role_ref,
 "subjects": binding_subjects(b.subjects),
 "overprivileged_reasons": sorted(set(reasons)),
 }
 )
 
 # API Probes (current identity)
 probes = []
 cluster_targets = [
 {"group": "", "resource": "nodes", "namespace": None},
 {"group": "", "resource": "namespaces", "namespace": None},
 ]
 ns_targets = [
 {"group": "", "resource": "secrets"},
 {"group": "", "resource": "configmaps"},
 {"group": "", "resource": "pods"},
 ]
 
 for t in cluster_targets:
 allowed, reason = can_i(authz, "list", t["resource"], group=t["group"], namespace=None)
 if allowed:
 attempt = try_read(core.list_node if t["resource"] == "nodes" else core.list_namespace)
 else:
 attempt = {"ok": False, "count": 0, "error": "not attempted (denied by SSAR)"}
 probes.append(
 {
 "group": t["group"],
 "resource": t["resource"],
 "namespace": None,
 "ssar_allowed": allowed,
 "ssar_reason": reason,
 "attempted": allowed,
 "attempt_error": attempt["error"],
 "attempt_count": attempt["count"],
 }
 )
 
 for ns in namespaces:
 for t in ns_targets:
 allowed, reason = can_i(authz, "list", t["resource"], group=t.get("group", ""), namespace=ns)
 if allowed:
 if t["resource"] == "secrets":
 attempt = try_read(core.list_namespaced_secret, ns)
 elif t["resource"] == "configmaps":
 attempt = try_read(core.list_namespaced_config_map, ns)
 else:
 attempt = try_read(core.list_namespaced_pod, ns)
 else:
 attempt = {"ok": False, "count": 0, "error": "not attempted (denied by SSAR)"}
 probes.append(
 {
 "group": t.get("group", ""),
 "resource": t["resource"],
 "namespace": ns,
 "ssar_allowed": allowed,
 "ssar_reason": reason,
 "attempted": allowed,
 "attempt_error": attempt["error"],
 "attempt_count": attempt["count"],
 }
 )
 
 # SA features
 sa_static = {}
 sa_imp_probes = {}
 sa_pod_usage = pods_by_service_account(pods_by_ns)
 
 if args.per_sa_static or args.impersonate_sa:
 sa_index = list_service_accounts(core, namespaces, args.sa_namespace, args.sa_name, warnings)
 
 if args.per_sa_static:
 for ns, sas in sa_index.items():
 for sa in sas:
 rules = aggregate_rules_for_sa(ns, sa.metadata.name, rbac, roles_by_key, warnings)
 reasons = is_overprivileged_role_rules(rules)
 sa_static.setdefault(ns, {})[sa.metadata.name] = {
 "rules": [r.to_dict() for r in rules],
 "overprivileged_reasons": reasons,
 "pods_using": sa_pod_usage.get(ns, {}).get(sa.metadata.name, []),
 }
 
 if args.impersonate_sa:
 base_client = core.api_client
 ns_scope = namespaces if not args.sa_namespace else [args.sa_namespace]
 for ns, sas in sa_index.items():
 for sa in sas:
 try:
 imp_client = build_impersonated_client(base_client, ns, sa.metadata.name)
 sa_imp_probes.setdefault(ns, {})[sa.metadata.name] = run_probes_with_client(imp_client, ns_scope)
 except ApiException as e:
 msg = f"impersonation for {ns}/{sa.metadata.name} failed: {e.status} {e.reason}"
 sa_imp_probes.setdefault(ns, {})[sa.metadata.name] = [{"error": msg}]
 warnings.append({"where": f"impersonate {ns}/{sa.metadata.name}", "error": msg})
 except Exception as e:
 msg = f"impersonation for {ns}/{sa.metadata.name} failed: {str(e)}"
 sa_imp_probes.setdefault(ns, {})[sa.metadata.name] = [{"error": msg}]
 warnings.append({"where": f"impersonate {ns}/{sa.metadata.name}", "error": msg})
 
 # Local SA enum
 local_sa = {}
 if args.local_sa_enum:
 local_sa["identity"] = get_current_identity(authn)
 local_sa["mounted_secrets"] = enum_local_sa_mounts("/var/run/secrets")
 
 # Lateral movement / host-escape sweep
 lm_hints = lateral_movement_sweep(pods_by_ns)
 
 # Assemble results
 results = {
 "generated_at": ts(),
 "node": socket.gethostname(),
 "namespaces": namespaces,
 "pods": dict(pod_inventory),
 "network_policies": {k: v for k, v in netpol_serialized.items()},
 "netpol_effects": netpol_effects, # topology aide (selectors summarized)
 "netpol_effective": netpol_effective, # isolation + resolved peers + ports
 "rbac": {"bindings": all_bindings},
 "api_probes": probes,
 "service_accounts": {
 "static_rules": sa_static,
 "impersonated_probes": sa_imp_probes,
 "pod_usage": sa_pod_usage,
 },
 "local_service_account": local_sa,
 "lateral_movement_hints": lm_hints,
 "warnings": warnings,
 "mitre_attck_tactics_hint": [],
 }
 
 if any(b["overprivileged_reasons"] for b in all_bindings):
 results["mitre_attck_tactics_hint"].append("Privilege Escalation")
 if all(len(v) == 0 for v in netpol_serialized.values()):
 results["mitre_attck_tactics_hint"].append("Lateral Movement")
 if any(not p["ssar_allowed"] for p in probes):
 results["mitre_attck_tactics_hint"].append("Discovery")
 if any(results["lateral_movement_hints"].values()):
 results["mitre_attck_tactics_hint"].extend(["Privilege Escalation", "Lateral Movement", "Credential Access"])
 
 # Write files
 json_path = os.path.join(args.outdir, "results.json")
 with open(json_path, "w", encoding="utf-8") as f:
 json.dump(results, f, indent=2, sort_keys=True)
 
 dot_text = build_dot(namespaces, pods_by_ns, netpol_effects)
 dot_path = os.path.join(args.outdir, "graph.dot")
 with open(dot_path, "w", encoding="utf-8") as f:
 f.write(dot_text)
 
 # optional render
 if args.render_dot:
 png_path = os.path.join(args.outdir, "graph.png")
 ok, err = maybe_render_dot(dot_path, png_path)
 if not ok:
 warnings.append({"where": "graphviz", "error": err})
 
 html = build_html(results)
 html_path = os.path.join(args.outdir, "report.html")
 with open(html_path, "w", encoding="utf-8") as f:
 f.write(html)
 
 print(f"[ok] wrote {json_path}")
 print(f"[ok] wrote {dot_path}")
 if args.render_dot:
 if any(w for w in warnings if w.get("where") == "graphviz"):
 print("[warn] graph.png not generated (see warnings in report.html)")
 else:
 print(f"[ok] wrote {os.path.join(args.outdir, 'graph.png')}")
 print(f"[ok] wrote {html_path}")
 
 
 if __name__ == "__main__":
 main()