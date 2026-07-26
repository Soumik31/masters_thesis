# Thesis Action Plan — Automated Blast Radius Measurement & Workload Hardening

**Student:** Soumik Shadman  
**Program:** Masters in Communication Systems and Networks, TH Köln  
**Company:** Dyn Media GmbH  
**Approach:** Attack Graph + Automated Measurement + Hardening Validation  
**Date:** June 2026

---

## Thesis in One Sentence

You build an automated tool that measures the blast radius of AWS workloads (what can an attacker reach if one component is compromised), apply hardening controls, and prove the reduction mathematically using attack graph analysis.

---

## Research Questions

1. **How can blast radius in AWS cloud workloads be modeled and measured automatically?**
   - Contribution: A reachability model (attack graph) + automated scanner

2. **Which security controls have the most impact on reducing blast radius?**
   - Contribution: Comparative evaluation of controls (network segmentation, egress restriction, IMDSv2, IAM scoping, VPC endpoints)

3. **Does the effectiveness of controls differ between workload architectures (EC2-based vs serverless)?**
   - Contribution: Testing on WordPress (EC2+RDS) AND Article Generator (Lambda+DynamoDB)

---

## What Makes This a Thesis (Not a Work Task)

| Work Task | Thesis |
|---|---|
| "I tightened security groups" | "I developed a method to measure reachability, applied it before and after, and proved X% reduction" |
| "I enforced IMDSv2" | "I compared 5 controls independently and ranked their impact using graph connectivity metrics" |
| "I hardened WordPress" | "I validated my model on two different architectures and showed it generalizes" |

---

## The Blast Radius Model

### What Is It?

A graph where:
- **Nodes** = AWS resources (EC2, RDS, S3 buckets, DynamoDB tables, internet, VPC endpoints)
- **Edges** = "can reach" relationships (network path exists AND permission allows access)

### How You Score It

```
Blast Radius Score = (reachable resources from compromised node) / (total resources in account)

Example WordPress BEFORE:
  EC2 can reach: RDS ✅, Internet ✅, All S3 ✅, SSM ✅, Other VPC resources ✅
  Reachable: 12 out of 15 resources = 80% blast radius

Example WordPress AFTER:
  EC2 can reach: RDS ✅ (only on 3306), S3 media bucket ✅ (via endpoint)
  Reachable: 2 out of 15 resources = 13% blast radius
```

### Edge Types (How Reachability Is Determined)

| Edge Type | How to Check | AWS API |
|---|---|---|
| Network (SG allows traffic) | Security group rules allow source → destination on port | `describe-security-groups` |
| Route (path exists to internet) | Route table has 0.0.0.0/0 → NAT/IGW | `describe-route-tables` |
| IAM (permission to call API) | Role policy allows action on resource | `list-attached-role-policies`, `get-role-policy` |
| Metadata (credential theft possible) | IMDSv1 enabled | `describe-instances` (MetadataOptions) |
| Endpoint (private service access) | VPC endpoint exists with policy allowing access | `describe-vpc-endpoints` |

---

## The Automated Scanner

### What It Does

```
Input:  AWS account ID + region + "entry point" (which resource to start from)
Output: Blast radius score + attack graph + findings list
```

### How It Works (Step by Step)

```
Step 1: DISCOVER
  - List all resources (EC2, RDS, S3, DynamoDB, Lambda, VPC endpoints)
  - Record their network config (subnet, SG, route table)
  - Record their IAM config (role, policies)

Step 2: MAP REACHABILITY
  For the entry point (e.g., WordPress EC2):
    - Check SG egress: what IPs/ports can it reach?
    - Check route table: can it reach internet?
    - Check IAM role: what AWS APIs can it call?
    - Check IMDS: can credentials be stolen via SSRF?
    - For each reachable target: check if target's inbound SG allows it

Step 3: BUILD GRAPH
  - Create nodes for each resource
  - Create edges for each confirmed "can reach" path
  - Label edges with type (network, IAM, metadata, route)

Step 4: CALCULATE SCORE
  - Count reachable nodes from entry point
  - Blast radius % = reachable / total
  - List all attack paths found

Step 5: OUTPUT REPORT
  - Score (0-100)
  - Findings with severity
  - Graph visualization (optional)
  - Recommended controls to reduce score
```

### Technology

- **Language:** Python 3.11
- **AWS Access:** boto3 (same API calls we already ran manually)
- **Graph:** networkx library (for graph modeling and metrics)
- **Output:** JSON report + terminal summary

### How It's Different from Prowler/ScoutSuite

| Existing Tools | Your Scanner |
|---|---|
| Check compliance rules (CIS benchmarks) | Models attack paths from a compromised resource |
| Answer: "Is this misconfigured?" | Answer: "If this is hacked, what can the attacker reach?" |
| Score = % of rules passing | Score = % of resources reachable (blast radius) |
| No graph, no relationships | Full reachability graph with edge types |
| Generic recommendations | Specific: "Block this edge to reduce score by X%" |

---

## Attack Scenarios (Validated by Scanner)

### Scenario 1: SSRF → Credential Theft (IMDSv1)

**Graph edge:** EC2 → Instance Metadata → IAM Credentials → AWS APIs

**Scanner check:**
```python
# Check if IMDSv1 allows credential theft
instance = ec2.describe_instances(...)
if instance['MetadataOptions']['HttpTokens'] == 'optional':
    add_edge(ec2_node, metadata_node, type='metadata_theft')
    add_edge(metadata_node, iam_node, type='credential_access')
```

**Control:** Enforce IMDSv2 → removes this edge from graph

---

### Scenario 2: EC2 → Database Access

**Graph edge:** EC2 → (SG allows 3306) → RDS

**Scanner check:**
```python
# Check if EC2 SG can reach RDS SG on port 3306
rds_sg_rules = describe_security_groups(rds_sg_id)
for rule in rds_sg_rules['IpPermissions']:
    if rule['FromPort'] <= 3306 <= rule['ToPort']:
        if '0.0.0.0/0' in rule['IpRanges']:
            add_edge(ec2_node, rds_node, type='network', port=3306)
```

**Control:** Restrict RDS SG to EC2 SG only → edge now only exists for WordPress EC2 (expected), not for any arbitrary host

---

### Scenario 3: EC2 → Internet (Data Exfiltration)

**Graph edge:** EC2 → (route 0.0.0.0/0) → NAT Gateway → Internet

**Scanner check:**
```python
# Check if route table has internet egress
route_table = describe_route_tables(subnet_id)
for route in route_table['Routes']:
    if route['DestinationCidrBlock'] == '0.0.0.0/0':
        if 'NatGatewayId' in route or 'GatewayId' in route:
            add_edge(ec2_node, internet_node, type='egress_route')
```

**Control:** Remove NAT route + add S3 VPC endpoint → internet edge removed

---

## Implementation Timeline (12 weeks)

### Weeks 1-2: Define the Model

- Define what counts as a node (resource types)
- Define what counts as an edge (reachability rules)
- Define the scoring formula
- Write the methodology chapter of your thesis
- Research related work (attack graphs in cloud, existing tools)

### Weeks 3-5: Build the Scanner

- Week 3: Discovery module (list all resources in an account)
- Week 4: Reachability module (check SGs, routes, IAM, IMDS)
- Week 5: Graph builder + scoring + report output

### Week 6: Baseline Measurement ("Before")

- Run scanner on WordPress Dev → record score + graph
- Run scanner on WordPress Prod → record score + graph
- Run scanner on Article Generator Dev → record score + graph
- Run scanner on Article Generator Prod → record score + graph
- Manually validate: run the 3 attack scenarios on WordPress Dev to confirm scanner findings

### Weeks 7-8: Implement Hardening (WordPress)

Apply controls one at a time, run scanner after each:

| Step | Control | Run Scanner → New Score |
|---|---|---|
| 1 | Enforce IMDSv2 | Score drops from 78 → ? |
| 2 | Restrict RDS SG | Score drops → ? |
| 3 | Restrict egress (remove NAT, add S3 endpoint) | Score drops → ? |
| 4 | Restrict EC2 egress SG | Score drops → ? |
| 5 | Scope VPC endpoint policies | Score drops → ? |

This gives you a **progressive reduction chart** — great for thesis visualization.

### Week 9: Validate on Article Generator

- Run scanner on Article Generator (different architecture)
- Show that the model works for Lambda-based workloads too
- Compare: which controls matter for EC2 vs Lambda?

### Week 10: Apply to WordPress Prod

- Apply hardening to production
- Run scanner → confirm same reduction
- Monitor for 1 week to ensure nothing breaks

### Weeks 11-12: Write Thesis + Package Tool

- Write remaining thesis chapters
- Package scanner as a reusable tool (with README)
- Produce security checklist for Dyn Media
- Create presentation

---

## What You Implement on WordPress (Specific Controls)

### Control 1: Enforce IMDSv2

```
Where: EC2 instance
What: Change HttpTokens from "optional" to "required"
Impact: Blocks SSRF credential theft
Account: Dev first (851725424182), then Prod (851725489819)
```

### Control 2: Restrict RDS Security Group

```
Where: RDS SG (sg-05ed4a22c1af30e4b in dev, sg-095893b787af30460 in prod)
What: Remove 0.0.0.0/0 on port 3306, allow only from EC2 SG
Impact: Database only reachable from WordPress EC2
```

### Control 3: Remove Internet Egress

```
Where: Private subnet route tables
What: Remove 0.0.0.0/0 → NAT Gateway route
Add: S3 Gateway VPC endpoint (for media file access)
Impact: No internet egress path = no data exfiltration
Note: Prod has NO VPC endpoints currently — add SSM + S3 endpoints
```

### Control 4: Restrict EC2 Egress Security Group

```
Where: EC2 SG (sg-0194f0c6af84d86d3 in dev, sg-07eae0c0fd941841d in prod)
What: Remove "allow all to 0.0.0.0/0"
Add: Allow only → RDS on 3306, S3 endpoint on 443, SSM endpoint on 443
Impact: EC2 can only talk to what it needs
```

### Control 5: Scope VPC Endpoint Policies

```
Where: VPC endpoints (SSM, SSMMessages, EC2Messages) — dev has them, prod needs them added
What: Replace Allow * on * for * with: Allow only this role, only needed actions
Impact: Endpoints can't be abused by other principals
```

---

## Expected Results (What Your Thesis Will Show)

### Progressive Blast Radius Reduction (WordPress)

```
Control Applied                    | Score  | Reduction
----------------------------------|--------|----------
Baseline (no controls)             | 78%    | —
+ IMDSv2 enforced                  | 65%    | -13%
+ RDS SG restricted                | 52%    | -13%
+ Internet egress removed          | 25%    | -27%
+ EC2 egress SG restricted         | 15%    | -10%
+ VPC endpoint policies scoped     | 12%    | -3%
```
*(Numbers are estimates — your scanner will produce real values)*

### Architecture Comparison

| Metric | WordPress (EC2+RDS) | Article Generator (Lambda+DynamoDB) |
|---|---|---|
| Baseline blast radius | ~78% | ~45% (Lambda is more isolated by default) |
| Most impactful control | Egress restriction | IAM least-privilege |
| Controls needed | Network-focused | Identity-focused |
| After hardening | ~12% | ~8% |

---

## Deliverables

### Academic (Thesis)

1. **Thesis document** (80-100 pages)
2. **Blast radius model** (formal definition of nodes, edges, scoring)
3. **Scanner tool** (open-source Python, GitHub)
4. **Evaluation results** (before/after across 4 accounts)
5. **Comparative analysis** (EC2 workload vs serverless workload)

### Industry (Dyn Media)

1. **Working scanner** — run on any account to get blast radius report
2. **Hardened WordPress** (dev + prod)
3. **Security checklist** for new workloads
4. **CDK patterns** for secure deployments
5. **Dashboard/report template** for ongoing monitoring

---

## Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Scanner takes too long to build | Keep it simple — focus on SG + routes + IMDS first, add IAM later |
| Model is too simple for academic rigor | Reference existing attack graph literature, show how yours extends it for cloud |
| Hardening breaks WordPress | Always test in dev first; have rollback plan |
| Article Generator too complex to model | Only model Lambda → DynamoDB/S3 reachability (IAM), skip the full pipeline |
| Timeline too tight | Minimum viable: scanner + WordPress hardening + before/after. Article Generator comparison is bonus |

---

## Priority Order (If Running Out of Time)

**Must have (minimum thesis):**
1. ✅ Blast radius model definition
2. ✅ Scanner that checks SGs + routes + IMDS (network layer)
3. ✅ Before/after on WordPress (dev or prod)
4. ✅ Progressive reduction chart

**Should have (strong thesis):**
5. ✅ Scanner also checks IAM policies
6. ✅ Apply to both WordPress dev + prod
7. ✅ Run on Article Generator for comparison
8. ✅ Open-source the scanner

**Nice to have (excellent thesis):**
9. ✅ Graph visualization
10. ✅ Continuous monitoring mode (detect drift)
11. ✅ Comparison with Prowler/ScoutSuite
12. ✅ Conference paper submission

---

## What to Say to Fabian

> "I'm building an automated blast radius scanner that models AWS workloads as attack graphs and calculates a reachability score. I'll validate it on WordPress (hardening + before/after measurement) and then run it on Article Generator to show it works for different architectures. The thesis contributes: (1) a reachability model for cloud workloads, (2) an automated measurement tool, and (3) empirical evaluation of which security controls reduce blast radius the most."

---

## What to Say to Your Thesis Advisor

> "My research question is: How can blast radius in cloud workloads be automatically measured, and which security controls most effectively reduce it? I model workloads as attack graphs (nodes = resources, edges = reachable paths), build an automated scanner to calculate the graph, apply controls progressively, and measure reduction. I validate on two real production workloads with different architectures (EC2-based and serverless). My contribution is the measurement method, the tool, and the comparative evaluation."

---

*Start with Weeks 1-2: Define the model. What counts as a node? What counts as an edge? How do you score it? Once that's clear, the scanner writes itself.*


---

## AWS Existing Services vs Our Tool — Gap Analysis

### What AWS Already Has

| AWS Service | What It Does | Limitation |
|---|---|---|
| **Security Hub (Exposure Findings + Attack Path)** | Correlates findings from GuardDuty, Inspector, Macie, IAM Access Analyzer. Shows "potential attack paths" as a visual graph. Mentions blast radius in context of unused IAM permissions. | No single blast radius score. No before/after comparison. No control effectiveness ranking. No formal model. Passive — can't run on demand. |
| **VPC Reachability Analyzer** | Checks if point A can reach point B over the network (yes/no). Uses automated reasoning on VPC config. | Only checks ONE path at a time. No graph, no score. Network only — doesn't check IAM. |
| **Amazon Inspector (Network Reachability)** | Tells you if an EC2 instance is reachable from the internet. Checks SGs, ACLs, route tables. | Only checks inbound from internet → EC2. Doesn't check lateral movement (EC2 → RDS, EC2 → S3). No IAM analysis. |
| **IAM Access Analyzer** | Finds unused permissions, external access to resources, validates policies. | Only IAM — no network reachability. No graph, no blast radius score. Doesn't combine network + IAM. |

### What We Build

| Our Component | What It Does |
|---|---|
| **Mathematical Model** | Formal graph G=(V,E) defining blast radius as reachability percentage. Predicts score changes when controls are applied. |
| **Automated Scanner** | Discovers all resources, maps ALL reachable paths from a compromised node (network + IAM + IMDS combined). Calculates a single blast radius score. |
| **CDK Enforcement** | Deploys hardening controls as code. Provides drift detection. Defines the "known good" state. |
| **Comparison Engine** | Runs scanner before/after each control. Ranks controls by effectiveness. Validates math predictions against real measurements. |

### The Gap We Fill

| Gap | Why No AWS Service Covers It |
|---|---|
| **Single blast radius score (0-100%)** | Security Hub gives severity labels (Critical/High/Medium/Low) per finding, not one unified score for "how far can an attacker get" |
| **All paths from compromised node** | Reachability Analyzer checks one pair at a time. Nobody maps ALL reachable resources from one entry point as a complete graph |
| **Lateral movement mapping (EC2 → RDS, EC2 → S3, EC2 → Internet)** | Inspector only checks internet → EC2 (inbound). Nobody checks outbound lateral movement |
| **Combined network + IAM + IMDS in one model** | Each AWS service checks one dimension. Nobody unifies all three into a single reachability graph |
| **Before/after measurement** | No AWS service tells you: "your blast radius was 78%, now it's 12%" |
| **Control effectiveness ranking** | No AWS service tells you: "egress restriction reduces blast radius by 27%, IMDSv2 by 13%" — so you know what to fix first |
| **Mathematical model validation** | No AWS service provides formal graph theory model you can validate against automated findings |
| **Closed-loop: model → measure → enforce → verify** | AWS services are passive/reactive. We provide: predict (model) → measure (scanner) → enforce (CDK) → verify (scanner again) |

### How We Position This in the Thesis

> "AWS provides several services that address parts of the security posture problem — Security Hub correlates findings, Inspector detects network exposure, and IAM Access Analyzer identifies unused permissions. However, no existing AWS service provides a unified blast radius measurement that combines network reachability, IAM permissions, and metadata exploitation into a single quantitative score, enables progressive measurement of control effectiveness, or validates mathematical predictions against live infrastructure. This thesis addresses that gap."

### How We Use AWS Services (Complementary, Not Competing)

Our scanner can **use** AWS services as data sources:

```
IAM Access Analyzer  → feeds unused permission data into our IAM edges
Inspector            → feeds network exposure findings into our network edges
Security Hub         → feeds correlated findings for validation
VPC Reachability     → validates individual network paths our model predicts
```

This makes our tool an **integration layer** that unifies what AWS already provides into a single blast radius model — not a replacement for any AWS service.


---

## Key Design Decisions

### Language & Tech Stack

| Component | Technology | Reason |
|---|---|---|
| Scanner | Python 3.11 + boto3 + networkx | Best AWS SDK docs, standard graph library in academia, fastest to develop |
| Infrastructure Hardening | CDK (TypeScript) | Existing stacks are CDK, consistent with Dyn Media tooling |
| Flow Log Analysis | Athena (SQL) | Native AWS integration, point-and-click setup for flow logs |
| Report Output | JSON + terminal summary | Machine-readable + human-readable |

### Scanner Is Universal, CDK Fix Is Specific

```
SCANNER (universal — works for anyone):
  → Scans ANY AWS account
  → Produces blast radius score + findings
  → Tells you WHAT to fix and the impact of each fix
  → Any company can run this on their own accounts

CDK FIX (specific to Dyn Media):
  → Implements the fixes on OUR WordPress workload
  → Serves as an EXAMPLE in the thesis showing how to apply recommendations
  → Other companies would write their own IaC based on scanner output
```

In the thesis: "We demonstrate remediation using CDK on our WordPress workload. The same recommendations can be implemented using any IaC tool on any architecture."

### Impact-Based Findings (Not Generic Severity Labels)

The scanner does NOT use generic Critical/High/Medium/Low labels like Prowler. Instead, it calculates **actual blast radius impact per edge**:

```
Prowler says:  "RDS unencrypted" → Critical
  But blast radius impact? 0% — it's data-at-rest, not reachability.

Prowler says:  "SSH open from 0.0.0.0/0" → Critical
  But in private subnet with no public IP → actual impact? 0%.

Our scanner says: "EC2 → Internet egress exists" → impact: -27% blast radius
  This is CALCULATED from the graph, not a generic rule.
```

**Scanner output categorizes by measured impact:**

| Category | Meaning | Action |
|---|---|---|
| **High Impact Edge (>20%)** | Removing this edge reduces blast radius significantly | Fix first — biggest return |
| **Medium Impact Edge (5-20%)** | Moderate reduction | Fix second |
| **Low Impact Edge (<5%)** | Minor improvement | Fix if time allows |

The scanner measures — it doesn't enforce policy. The human/company decides what score is acceptable. Our thesis contribution is the measurement method, not the policy.

### Complementary to Existing Tools (Not Competing)

| Tool | Answers | Our Scanner |
|---|---|---|
| Prowler | "Is this misconfigured?" (compliance checklist) | "If compromised, what's the blast radius?" (impact measurement) |
| ScoutSuite | "Show me misconfigurations in a dashboard" | "Show me attack paths and rank them by impact" |
| Our scanner | — | Can USE Prowler/ScoutSuite findings as input data |

They are complementary. Prowler finds misconfigurations. Our scanner tells you which misconfigurations actually matter for blast radius — so you know what to fix first.

### "What's Actually Used" Feature (Requires VPC Flow Logs)

The scanner has two modes:

**Mode 1 — Static Analysis (always works):**
- Reads SGs, routes, IAM, IMDS config
- Calculates what CAN be reached (total reachability)
- No prerequisites needed

**Mode 2 — Traffic Analysis (needs flow logs enabled):**
- Reads VPC Flow Logs (via Athena) + CloudTrail
- Calculates what IS actually reached (actual usage)
- Compares: CAN reach vs DOES reach = excess access
- Tells you exactly what's safe to block

**Prerequisite for Mode 2:** Enable VPC Flow Logs on the account (simple, low cost). CloudTrail is already enabled by default (90 days free).

### Known Limitations (Stated in Thesis)

| Limitation | Why | Mitigation |
|---|---|---|
| IAM policy evaluation is simplified | Full IAM eval is extremely complex (deny, conditions, boundaries, SCPs) | Use IAM Access Analyzer output as input instead of reimplementing |
| No transitive attack chains (A→B→C) | Modeling "A can invoke B, B can access C, therefore A reaches C" is complex | Mention as future work; for WordPress (simple) this doesn't apply |
| Not real-time / continuous | Building a daemon is product work, not thesis scope | Run on-demand (before/after); mention continuous mode as future work |
| VPC Flow Logs don't capture metadata traffic | Can't see IMDS access in flow logs | Check IMDS config directly (HttpTokens setting) — don't need flow logs for this |
| CloudTrail free tier is 90 days | Only 90 days of API call history | Sufficient — if unused in 90 days, safe to consider not needed |

### Feasibility Summary

| Feature | Feasible? | Confidence | We Already Proved It? |
|---|---|---|---|
| Discover all resources | ✅ | 100% | Yes — ran on all 4 accounts |
| Map reachability from SGs/routes/IMDS | ✅ | 100% | Yes — identified all paths manually |
| Build graph + calculate score | ✅ | 100% | Standard library (networkx) |
| Before/after comparison | ✅ | 100% | Run scanner twice |
| "Actually used" via Flow Logs | ✅ | 90% | Needs flow logs enabled + 2-4 weeks data |
| "Actually used" via CloudTrail | ✅ | 95% | Already enabled by default |
| CDK hardening deployment | ✅ | 100% | Existing stack is CDK |
| Perfect IAM evaluation | ❌ | Skip | Use Access Analyzer instead |
| Transitive chains | ❌ | Skip | State as future work |
