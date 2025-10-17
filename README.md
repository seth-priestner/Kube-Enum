# Kube-Enum
Enumerating Kubernetes via Python
Read-only Kubernetes reconnaissance: communication topology, RBAC and NetworkPolicy analysis, ServiceAccount enumeration, and lateral‑movement/escape heuristics. Exports JSON, Graphviz DOT, a self-contained HTML report, and (optionally) a rendered PNG graph.

**What it does**

**Inventory**
Namespaces and Pods (labels, owner refs, images, node, ServiceAccount).
**RBAC**
Lists RoleBinding / ClusterRoleBinding.
Flags over‑privilege (e.g., cluster-admin, wildcard verbs/resources, sensitive verbs on sensitive resources).
**NetworkPolicy**
**  Effective view (new):**
    Computes per‑pod isolation and status per direction:
    no-isolation = no policy of that type selects the pod (K8s default allow).
    deny-all = pod is isolated for the direction but no rules exist (default‑deny).
    allow-some = isolated + at least one rule.
**  Resolves peers:**
    podSelector → actual pods (same ns unless combined with namespaceSelector).
    namespaceSelector → actual namespaces by live namespace labels.
    podSelector + namespaceSelector → pods in matching namespaces.
    ipBlock (with _except) → CIDRs recorded.
  Captures rule ports (protocol, port, endPort) and aggregates counts/sets.
  Topology aide: selector summaries per pod for quick graphing.
**Service accounts**
  Pod → ServiceAccount usage mapping.
  Static effective rules per SA from Role/ClusterRole bindings.
  Impersonation mode (optional) to re-run probes as each SA (requires impersonate).
  Local SA enumeration (optional): current identity via SelfSubjectReview and /var/run/secrets metadata (size + SHA‑256 only; no content).
**Lateral movement / host‑container escape heuristics**
  Per container flags: privileged, allowPrivilegeEscalation, runs as root, added capabilities (CAP_SYS_ADMIN, CAP_NET_ADMIN, ALL, etc).
  hostNetwork/hostPID/hostIPC/shareProcessNamespace.
  hostPath mounts to sensitive prefixes, runtime sockets (docker.sock/containerd.sock/crio.sock), writable mounts into /etc, /root, /var/lib, /proc, /sys, /dev.
**MITRE ATT&CK hints**
  Tags tactics (Privilege Escalation, Lateral Movement, Discovery, Credential Access) based on findings.
**Warnings surfaced (new)**
  Collects API errors and blind spots in results.json["warnings"] and shows them in the HTML.

**Outputs**
**Written to --outdir (default k8s_commcheck_out):**
  results.json — full machine‑readable output.
  graph.dot — Graphviz DOT graph (namespaces, pods, summarized ingress/egress peers).
  report.html — human report with tables + raw JSON.
  graph.png — optional (--render-dot if Graphviz dot is present).
**Render the DOT yourself (if you didn’t use --render-dot):**
  dot -Tpng graph.dot -o graph.png

**Install**
  Python 3.9+
  Packages:
   ** pip install kubernetes==29.0.0**
  To render PNG/SVG graphs: install Graphviz CLI (dot) via your OS package manager.

**Usage**
  python kube-enum.py [--context NAME] [--kubeconfig PATH] [--namespace NS] \
  [--outdir DIR] \
  [--per-sa-static] \
  [--impersonate-sa] [--sa-namespace NS] [--sa-name NAME] \
  [--local-sa-enum] \
  [--render-dot]
**Examples**
Sweep everything with effective NetPolicy math:
  python kube-enum.py --render-dot
Limit to a single namespace:
  python kube-enum.py --namespace prod
ServiceAccount static rules + local SA info:
  python kube-enum.py --per-sa-static --local-sa-enum
Impersonate all SAs (you must have impersonate on them):
  python kube-enum.py --impersonate-sa
Impersonate one SA:
  python kube-enum.py --impersonate-sa --sa-namespace app --sa-name web-sa
Custom output dir:
  python kube-enum.py --outdir ./out/k8s-audit-$(date +%F)

**How NetworkPolicy analysis works (and where it stops)**
**  policyTypes: uses spec.policyTypes if set; else infers:**
    include Ingress if spec.ingress present,
    include Egress if spec.egress present,
    if neither set, default to Ingress (per spec).
  **Isolation (per pod/direction):**
    If no policy of that type selects the pod → no-isolation.
    If at least one policy of that type selects the pod but there are zero rules → deny-all.
    If there’s at least one rule → allow-some.
**  Peers:**
    Resolves podSelector and namespaceSelector against current pod and namespace labels.
    Records ipBlock CIDRs and _except.
  Ports: collects each rule’s (protocol, port, endPort) and aggregates; named ports listed separately.
This is not a full policy solver. It won’t replicate CNI behavior, handle named-port resolution across pods/services, or compute transitive reachability. It’s a fast, accurate isolation signal with real peer resolution and port visibility.

**Data model (selected keys)**
  results.json (top-level):
    namespaces — list of ns names.
    pods — { ns: [ {name, labels, owner, image_list, node, service_account} ] }.
    network_policies — raw policies per ns (as dicts).
    netpol_effects — topology aide: per pod, selectors summarized.
    netpol_effective — effective analysis:
                "netpol_effective": {
              "ns": {
                "pod": {
                  "policies_applied": [ {"name": "...", "types": ["Ingress","Egress"]} ],
                  "ingress": {
                    "isolated": true,
                    "effective": "allow-some|deny-all|no-isolation",
                    "rules": [
                      {
                        "policy": "np-name",
                        "peers": {"pods": ["ns/pod"...], "namespaces": ["ns"...], "cidrs": [{"cidr":"1.2.3.0/24","except":["..."]}]},
                        "ports": [{"protocol":"TCP","port":"80","end_port":null}]
                      }
                    ],
                    "aggregate": {"peer_pod_count": 3, "peer_namespace_count": 2, "cidr_count": 1, "ports": ["TCP/80"], "named_ports": []}
                  },
                  "egress": { "...same shape..." }
                }
              }
            }
**rbac.bindings** — list with over‑privilege reasons.
**api_probes** — SSAR decision + attempted read results.
**service_accounts.static_rules** — per ns/SA: rules + over‑priv reasons + pods using it.
**service_accounts.impersonated_probes** — per ns/SA: probe results (if enabled).
**service_accounts.pod_usage** — ns → sa → [pods].
**local_service_account** — identity + /var/run/secrets file metadata (if enabled).
**lateral_movement_hints** — ns → [{pod, containers:[{name, findings[]}]}].
**warnings** — list of {where, error} messages.
**mitre_attck_tactics_hint** — coarse tags based on findings.

**Permissions**
**  Read-only.** The tool never writes to cluster resources.
  Useful rights for broad coverage:
    list: namespaces, pods, configmaps, secrets (namespaced), nodes (cluster).
    RBAC: list on roles, clusterroles, rolebindings, clusterrolebindings.
    Network policy: list on networkpolicies.
    SSAR: create on selfsubjectaccessreviews.authorization.k8s.io (usually allowed for all authenticated users).
    Optional: impersonate for system:serviceaccount:<ns>:<name> to run impersonated probes.
  If you lack permissions, you’ll see warnings and reduced visibility.

**Troubleshooting**
  
  [fatal] failed to configure kube client
  Bad or missing kubeconfig/context. Check --kubeconfig/--context, or run in‑cluster.
  
  Missing sections in HTML
  Check the Warnings section; you likely lack list on that resource/namespace.
  
  SSAR error: 403 Forbidden
  Your identity can’t create SelfSubjectAccessReview. Probes won’t run.
  
  impersonation failed: 403 Forbidden
  You don’t have impersonate on that ServiceAccount. Use --per-sa-static.
  
  graph.png not generated
  Use --render-dot and ensure dot is on PATH. Otherwise you still get graph.dot.  

**License & usage**
For authorized assessment and hardening of environments you’re allowed to inspect. No warranty. Use at your own risk.
