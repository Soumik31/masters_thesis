# Topic 1 — Comparison (Sebastian vs Fabian vs Original)

<aside>
<img src="https://www.notion.soi" alt="https://www.notion.soi" width="40px" />

This page compares: (1) what you initially proposed for Topic 1, and (2) what you were suggested by Sebastian (8 May) vs Fabian (21 May). Use it to decide final scope + case study.

</aside>

## TL;DR decision guide

- If you want a **clear, implementable thesis with measurable results in 3–4 months**: pick **one concrete workload** (WordPress or Article Generator), model 2–3 realistic compromise scenarios, and implement **least-privilege network + identity controls** + monitoring.
- If you want a **bigger org-wide platform/tooling outcome**: focus on **account-to-account governance + monitoring** (default-deny between accounts + dashboard + PR workflow). This is more “tool building” and may become broader than a thesis if not tightly scoped.

---

## 1) Your original Topic 1 proposal (baseline)

### Your framing

- “Inside the VPC = trusted” is the current implicit model; a compromise of one service can laterally move to many others.
- Goal: **Zero Trust** via **micro-segmentation** so each service can only talk to direct dependencies (e.g., Media Processing → S3/SQS only).
- Use of **VPC endpoints** to remove the need for internet egress (reduce exfil path).
- Quantify impact with **blast radius reduction** (before/after reachability).

### What this implies as thesis work

- Choose a target environment/workload
- Map communication dependencies
- Define “allowed graph” (service-to-service, service-to-AWS-service)
- Implement controls (SGs, NACLs where appropriate, endpoints, IAM boundaries, etc.)
- Validate by testing lateral movement paths + measure blast radius

---

## 2) Sebastian (meeting 8 May) — what you were suggested

### Sebastian’s core concern / angle

- The urgent gap is not only “service-to-service inside one VPC”, but **account-to-account lateral movement**: with many production accounts connected, compromise of one account may enable reach into others.
- There is limited **observability of traffic flows** between accounts (who is talking to whom, and how much).

### Suggested direction (concept)

- Move toward **default-deny between accounts**, then explicitly allow only required account-to-account flows.
- Add a **dashboard / admin portal** that:
    - Shows which accounts can communicate with which other accounts (current state)
    - Adds monitoring/metrics (e.g., GB transferred per account pair)
    - Enables controlled changes via **PR-driven IaC** (UI triggers a pull request that updates allowlists)

### What Sebastian is effectively recommending

- A thesis angle around **governance + monitoring + controlled network permissions** across accounts (Transit Gateway + security boundaries + workflow)

### Risks / tradeoffs

- Can become a **platform/tooling project** (bigger scope, product-y)
- Requires clarity on what is technically enforceable via TGW routing, SG patterns, NACLs, prefix lists, firewall, endpoints, etc.
- Might overlap with ongoing TGW work unless you clearly position your part as **policy + monitoring + workflow** rather than routing implementation

---

## 3) Fabian (meeting 21 May) — what you were suggested

### Fabian’s core concern / angle

- Your topic is strong and important, but it should avoid duplicating the “between-account routing/isolation” work already happening.
- Focus on **blast radius reduction inside an account and within a workload**:
    - If an attacker gets code execution on **one compute unit** (EC2/Lambda/container), it should not automatically lead to access to other resources like DynamoDB.

### Suggested direction (case-study driven)

- Pick a **real production workload** (not only sandbox) to make it meaningful.
- Two concrete candidate case studies:
    - **WordPress** (public viewing + admin access, EC2/ECS + DB patterns)
    - **Article Generator** (more modern stack; easier to demonstrate fine-grained permissions; good internal expertise to review weaknesses)

### Suggested output beyond the single case study (org-wide reuse)

- Artifacts that generalize:
    - Documentation and patterns other teams can follow
    - Security checklists for building services
    - “Guardrails” such as SCPs (e.g., disallow overly broad SG rules / wildcards)
    - Monitoring for blocked attempts (prevent + detect)

### Risks / tradeoffs

- Needs careful selection of one workload where you can implement changes without disrupting ongoing work
- You must define a small number of scenarios and controls so it stays within thesis time

---

## 4) Direct comparison (side-by-side)

| Dimension | Your original idea | Sebastian (8 May) | Fabian (21 May) |
| --- | --- | --- | --- |
| Primary focus | Intra-VPC / service-to-service Zero Trust + endpoints | Inter-account lateral movement + visibility + governance workflow | Within-account, within-workload blast radius (service/resource level) |
| “Unit of control” | Service / subnet / SG / endpoints | AWS accounts + approved account-to-account flows | Workload (WordPress or Article Generator) + resources (EC2/Lambda/DB) |
| Overlap risk | Low–medium (depends on chosen target) | Medium (could overlap with TGW routing project) | Low (explicitly tries to avoid TGW overlap) |
| Best “thesis narrative” | Micro-segmentation reduces blast radius; endpoints reduce egress/exfil | Governed connectivity: default-deny between accounts + monitored allowlists | Case-study hardening: realistic attack scenarios + least privilege + reusable guardrails |
| Implementation scope tendency | Medium (clear boundaries if workload is fixed) | High (can balloon into a tooling platform) | Medium–low (can be tightly scoped to 1 workload) |
| Suggested case study | Not fixed (needs selection) | Account connectivity model / monitoring portal | WordPress or Article Generator |
| What you measure | Blast radius (reachability graph before/after), blocked paths, egress removal | Account-to-account allowed graph, traffic volume per pair, attempted violations | Scenario outcomes (what a compromised node can/can’t reach), policy violations, control coverage |

---

## 5) A practical “decision” framing

### Option A — Governance/monitoring between accounts (Sebastian-leaning)

Choose this if your thesis should deliver:

- A controlled model of **which accounts may talk**
- A workflow for requesting/approving connectivity
- Monitoring/reporting on cross-account communication

Keep it bounded by:

- Defining 1–2 account-pair use cases (not “all accounts”)
- Defining only the minimum viable portal/reporting (don’t build a full product)

### Option B — Workload hardening + reusable patterns (Fabian-leaning)

Choose this if your thesis should deliver:

- A deep, defensible “before/after” story on one real system
- Concrete improvements + evidence (tests/validation)
- Reusable guardrails (docs, checklists, SCP ideas)

Keep it bounded by:

- Picking 1 workload
- Picking 2–3 attack scenarios
- Delivering a small set of controls that clearly map to those scenarios

---

## 6) What you need to decide next (fill-in)

- Target workload: **WordPress** vs **Article Generator**
- Target environment: dev/staging vs prod-like
- Main attacker model:
    - (a) compromise of compute (EC2/Lambda/container)
    - (b) compromise of one account (cross-account reach)
- Success metrics you will report:
    - (a) blast radius graph reduction
    - (b) number of blocked lateral paths
    - (c) removed internet egress paths
    - (d) policy/guardrail coverage (SCPs, least privilege)