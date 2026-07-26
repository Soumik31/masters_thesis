# Sebastian's Suggestion — Cross-Account Security Governance & Monitoring

---

## The Problem Sebastian Sees

Dyn Media has many AWS accounts — probably organized like this:

```
Dyn Media AWS Organization
├── Production Account (live streaming, user-facing)
├── Staging Account (pre-production testing)
├── Dev Account (development environments)
├── Media Processing Account (transcoding, packaging)
├── Data/Analytics Account (user analytics, reporting)
├── Shared Services Account (CI/CD, monitoring, logging)
├── Security Account (GuardDuty, Config, audit logs)
└── ... possibly more
```

These accounts are connected through a **Transit Gateway** — a central hub that routes traffic between accounts. The problem: **who controls which accounts can talk to which?**

Right now, the situation is probably:
- Most accounts can reach most other accounts through the Transit Gateway
- There's no clear visibility into what traffic is flowing between accounts
- There's no formal process for approving new connections
- If one account is compromised, the attacker can potentially reach other accounts

**Sebastian's concern in one sentence:** "We have 10-20 AWS accounts connected together, and we don't know who's talking to whom, or how to stop an attacker from jumping between accounts."

---

## What Sebastian Wants You to Build

### 1. Default-Deny Between Accounts

**Current state:** Accounts are connected and can mostly reach each other.

**Target state:** No account can talk to any other account UNLESS explicitly approved.

```
BEFORE (implicit allow):
  Account A ←→ Account B ←→ Account C ←→ Account D
  (everything can reach everything)

AFTER (default-deny + explicit allow):
  Account A ──→ Account B (approved: CI/CD deploys to staging)
  Account C ──→ Account D (approved: media processing sends to CDN origin)
  Account A ✗ Account C (no approved connection)
  Account B ✗ Account D (no approved connection)
```

**How this works technically:**
- Transit Gateway route tables control which accounts can route traffic to which
- Security groups and NACLs at account boundaries enforce the rules
- VPC endpoint policies restrict which accounts can access shared services
- Resource policies on S3 buckets, SQS queues, etc. restrict cross-account access

### 2. Visibility Dashboard

A dashboard that answers these questions at a glance:

| Question | What You See |
|---|---|
| Which accounts can talk to which? | Visual graph showing approved connections |
| How much traffic is flowing between accounts? | GB transferred per account pair, per day/week |
| Are there any unauthorized connection attempts? | Blocked traffic logs from Transit Gateway |
| Has anything changed recently? | Audit trail of connection approvals/removals |
| Which connections are unused? | Account pairs with approved connections but zero traffic in 90 days |

### 3. PR-Driven Approval Workflow

When a team needs a new connection between accounts:

```
Step 1: Developer opens a Pull Request
        "I need Account A (CI/CD) to reach Account B (Staging) on port 443"

Step 2: Security team reviews the PR
        - Is this connection necessary?
        - Is it scoped correctly (specific ports, not all traffic)?
        - Is there a time limit?

Step 3: PR is approved and merged
        - IaC (Terraform/CloudFormation) automatically updates Transit Gateway routes
        - Dashboard updates to show the new connection
        - Monitoring starts tracking traffic on this connection

Step 4: Ongoing monitoring
        - If the connection is unused for 90 days → alert to review/remove
        - If traffic volume is abnormal → alert for investigation
```

---

## What This Looks Like as a Thesis

### Research Questions
1. What is the current cross-account connectivity model at Dyn Media? (Which accounts can reach which?)
2. Can default-deny between accounts be implemented without breaking existing workflows?
3. How quickly can unauthorized cross-account access attempts be detected?
4. Does a PR-driven governance workflow reduce unauthorized connectivity changes?

### Phase A (Weeks 1-8): Assessment
- Map all current cross-account connections (Transit Gateway routes, VPC peering, resource policies)
- Analyze Transit Gateway flow logs to see actual traffic between accounts
- Identify connections that exist but are never used
- Identify connections that are too broad (all ports, all protocols)
- Document the current "who can reach whom" graph

### Phase B (Weeks 9-16): Implementation
- Implement default-deny routing (restrict Transit Gateway route tables)
- Build monitoring dashboard (CloudWatch + custom metrics)
- Build PR-driven approval workflow (GitHub/GitLab + Terraform)
- Test: verify that unauthorized cross-account access is blocked
- Measure: detection time for unauthorized attempts, traffic visibility improvement

### Deliverables
- Cross-account connectivity map (before/after)
- Governance dashboard
- PR-based approval workflow
- Monitoring and alerting for unauthorized access
- Documentation for teams on how to request new connections

---

## Pros and Cons

### Pros
- **High organizational impact** — affects all accounts, all teams
- **Sebastian clearly cares about this** — your leader wants it
- **Real visibility gap** — nobody currently knows the full picture of cross-account traffic
- **Governance is valuable** — PR-based workflow creates audit trail and accountability

### Cons
- **Scope creep risk is HIGH** — building a dashboard + workflow + monitoring can easily become a 6-12 month product, not a 3-4 month thesis
- **Overlaps with Transit Gateway work** — if someone is already working on TGW routing, your thesis might conflict
- **More "tooling" than "research"** — a thesis advisor might say "where's the research question?" Building a dashboard is engineering, not academic research
- **Hard to measure** — "we built a dashboard" is not as strong as "we reduced blast radius by 80%"
- **Depends on many teams** — you need buy-in from every team that owns an account to implement default-deny without breaking things

---

## When to Choose This

Choose Sebastian's approach if:
- Cross-account governance is the #1 priority for the organization right now
- There's no overlap with existing Transit Gateway work
- You're comfortable with a broader, less thesis-traditional scope
- You have strong support from Sebastian to push through the organizational changes needed
- You're OK with the risk that it might be hard to finish in 3-4 months

---

## Key Technical Components

| Component | AWS Service | What It Does |
|---|---|---|
| Account connectivity control | Transit Gateway route tables | Controls which VPCs/accounts can route traffic to which |
| Traffic monitoring | Transit Gateway Flow Logs | Records all traffic flowing through the TGW |
| Cross-account access control | Resource policies (S3, SQS, KMS, etc.) | Controls which accounts can access shared resources |
| Guardrails | SCPs (Service Control Policies) | Organization-wide rules (e.g., "no account can create VPC peering without approval") |
| Dashboard | CloudWatch Dashboards + custom metrics | Visualizes traffic flows and connection status |
| Approval workflow | GitHub/GitLab + Terraform | PR triggers IaC changes to routing/policies |
| Alerting | CloudWatch Alarms + SNS | Alerts on unauthorized access attempts or unusual traffic |

---

## Simple Analogy

**Think of it like a corporate office building:**
- Each AWS account = one floor of the building
- Transit Gateway = the elevator connecting all floors
- Currently: anyone can press any floor button (all accounts can reach all accounts)
- Sebastian wants: you need a keycard for each floor, a security camera in the elevator showing who goes where, and a request form to get access to a new floor

---

*This is Sebastian's suggestion for Topic 1, focused on cross-account governance and monitoring.*
