# Master's Thesis Proposal

## Automated Blast Radius Measurement and Reduction in AWS Cloud Workloads Using Attack Graph Analysis

---

**Student:** Soumik Shadman  
**Program:** Master of Science in Communication Systems and Networks  
**Institution:** Technische Hochschule Köln (TH Köln)  
**Company:** Dyn Media GmbH (Axel Springer SE)  
**Proposed Duration:** 12 weeks  
**Date:** June 2026

---

## 1. Problem Statement

Modern cloud infrastructures on AWS often operate under an implicit trust model: once a workload is deployed, its compute resources can typically reach far more services and data than they functionally require. If an attacker compromises a single component — through a vulnerable dependency, an SSRF exploit, or a supply chain attack — the resulting blast radius (the set of resources the attacker can access) is often unknown and unnecessarily large.

Current AWS security services (Security Hub, Inspector, IAM Access Analyzer) identify individual misconfigurations but do not provide a unified, quantitative measure of blast radius from a specific compromised resource. Existing open-source tools (Prowler, ScoutSuite) perform compliance checks against best-practice benchmarks but do not model inter-resource reachability or rank controls by their actual impact on reducing lateral movement.

There is no established method to:
1. Automatically measure how far an attacker can reach from a compromised resource
2. Quantify the effectiveness of individual security controls on reducing that reach
3. Validate automated findings against a formal mathematical model

---

## 2. Research Objectives

This thesis aims to:

1. **Define a formal blast radius model** for AWS cloud workloads based on graph theory, where resources are nodes, reachability paths are edges, and blast radius is a quantifiable metric.

2. **Develop an automated scanner** that discovers AWS resources, maps reachability (network, identity, metadata), builds the attack graph, and calculates the blast radius score.

3. **Evaluate the effectiveness of security controls** by progressively applying hardening measures and measuring the blast radius reduction after each control.

4. **Validate the model** by comparing mathematical predictions against automated scanner results, identifying discrepancies, and analyzing their causes.

5. **Demonstrate generalizability** by applying the method to two production workloads with different architectures (EC2-based and serverless/Lambda-based).

---

## 3. Research Questions

**RQ1:** How can blast radius in AWS cloud workloads be formally modeled and automatically measured?

**RQ2:** Which security controls produce the greatest measurable reduction in blast radius for EC2-based workloads?

**RQ3:** Does the relative effectiveness of controls differ between traditional (EC2+RDS) and serverless (Lambda+DynamoDB) architectures?

**RQ4:** How accurately does the formal mathematical model predict the blast radius measured by the automated scanner, and what causes discrepancies?

---

## 4. Approach and Methodology

### 4.1 Formal Blast Radius Model

Define a directed graph G = (V, E) where:
- V = set of AWS resources (compute, data stores, endpoints, internet)
- E = set of directed edges representing confirmed reachability

An edge (u, v) ∈ E exists if and only if at least one of the following holds:
- **Network reachability:** Security group rules allow traffic from u to v, and a network route exists
- **IAM reachability:** The IAM role attached to u has permission to perform actions on v
- **Metadata exploitation:** u runs on an EC2 instance with IMDSv1 enabled, allowing credential theft

Blast radius is defined as:

```
BR(v) = |R(v)| / |V \ {v}|
```

Where R(v) is the set of all nodes reachable from v (including transitive network paths).

Control effectiveness for a control c is defined as:

```
CE(c) = BR_before(v) - BR_after(v)
```

### 4.2 Automated Scanner

A Python-based tool (using boto3 and networkx) that:
1. Discovers all resources in a target AWS account
2. Maps reachability by analyzing security groups, route tables, IAM policies, and IMDS configuration
3. Constructs the attack graph programmatically
4. Calculates the blast radius score
5. Ranks all edges by their impact on the score (high/medium/low impact)
6. Optionally compares reachability against actual usage (via VPC Flow Logs and CloudTrail) to identify excess access

### 4.3 Progressive Hardening and Measurement

Security controls are applied one at a time to the target workload, with the scanner running after each control to measure the new score:

| Step | Control Applied | Scanner Runs → New Score |
|---|---|---|
| 0 | Baseline (no controls) | Initial blast radius |
| 1 | Enforce IMDSv2 | Score reduction measured |
| 2 | Restrict database security group | Score reduction measured |
| 3 | Remove internet egress | Score reduction measured |
| 4 | Restrict compute egress rules | Score reduction measured |
| 5 | Scope VPC endpoint policies | Score reduction measured |

This produces a progressive reduction curve — a key thesis visualization.

### 4.4 Dual Validation

The mathematical model predicts expected blast radius values. The scanner measures actual values. Comparing both:
- If predictions match measurements: both methods are validated
- If discrepancies exist: analysis reveals blind spots in either the model or the scanner (a key academic contribution)

### 4.5 Cross-Architecture Comparison

The method is applied to two real production workloads at Dyn Media:
- **WordPress** (EC2 + RDS + S3): Traditional architecture, network-centric security
- **Article Generator** (Lambda + DynamoDB + S3 + Bedrock): Serverless architecture, identity-centric security

This comparison tests whether the model generalizes across architecture types and identifies which controls matter most for each.

---

## 5. Target Environment

### WordPress Workload (Primary Case Study)

| Property | Dev Account | Prod Account |
|---|---|---|
| Account ID | 851725424182 | 851725489819 |
| Compute | EC2 (t3.micro) | EC2 (t3.micro) |
| Database | RDS MySQL 8.0 | RDS MySQL 8.0 (Multi-AZ) |
| Storage | S3 (media files) | S3 (media files) |
| Network | VPC, private subnets, NAT Gateway | VPC, private subnets, 2 NAT Gateways |
| VPC Endpoints | 3 (SSM, SSMMessages, EC2Messages) | None |
| IMDSv2 | Not enforced | Not enforced |
| Deployed via | CDK (CloudFormation) | CDK (CloudFormation) |

### Article Generator Workload (Validation Case Study)

| Property | Dev Account | Prod Account |
|---|---|---|
| Account ID | 905418363445 | 381492097421 |
| Compute | 16+ Lambda functions + AWS Batch (GPU) | 17+ Lambda functions + AWS Batch |
| Database | DynamoDB (8 tables) | DynamoDB (3 tables) |
| Storage | S3 (13 buckets) | S3 (6 buckets) |
| Network | VPC for Batch only; Lambda outside VPC | Same |
| VPC Endpoints | None | None |
| Key Integration | Amazon Bedrock (Claude), SecretsManager | Same |

---

## 6. Expected Contributions

### Academic Contributions

1. **Blast radius model:** A formal graph-theoretic model for quantifying blast radius in AWS workloads, combining network reachability, IAM permissions, and metadata exploitation into a unified metric.

2. **Automated measurement tool:** An open-source scanner that implements the model and produces actionable, impact-ranked findings.

3. **Control effectiveness evaluation:** Empirical data on which security controls reduce blast radius the most, and whether this differs by architecture type.

4. **Model validation:** Analysis of discrepancies between mathematical predictions and automated measurements, identifying limitations of each approach.

### Industry Contributions (Dyn Media)

1. **Hardened WordPress workload** (dev and production)
2. **Reusable scanner** that can be run on any Dyn Media AWS account
3. **CDK hardening patterns** as reference implementations
4. **Security recommendations** for the Article Generator workload

---

## 7. Differentiation from Existing Work

| Existing Tool/Service | What It Does | Gap This Thesis Fills |
|---|---|---|
| AWS Security Hub (Exposure Findings) | Correlates findings, shows attack paths | No unified blast radius score; no before/after comparison; no control ranking |
| AWS VPC Reachability Analyzer | Checks one network path at a time | Doesn't map all paths from a compromised node; no IAM analysis; no scoring |
| Amazon Inspector | Detects inbound network exposure | Only internet→EC2; no lateral movement; no blast radius concept |
| IAM Access Analyzer | Finds unused permissions | IAM only; no network analysis; no combined model |
| Prowler / ScoutSuite | Compliance checks (CIS, PCI-DSS) | No relationship modeling; no impact ranking; no attack graph |

This thesis provides a **unified method** that combines network, identity, and metadata reachability into a single quantitative blast radius metric with progressive measurement and formal validation.

---

## 8. Timeline

| Week | Activity | Deliverable |
|---|---|---|
| 1–2 | Define formal model; literature review | Model definition; related work chapter |
| 3–5 | Develop automated scanner | Working scanner (core: SGs, routes, IMDS, basic IAM) |
| 6 | Enable VPC Flow Logs; run baseline on all 4 accounts | "Before" measurements and attack graphs |
| 7–8 | Implement hardening controls on WordPress (dev, then prod) | Progressive reduction data; CDK stack |
| 9 | Run scanner on Article Generator; cross-architecture comparison | Comparative data |
| 10 | Model vs scanner comparison; discrepancy analysis | Validation chapter data |
| 11–12 | Thesis writing; finalize tool; prepare presentation | Thesis document; open-source tool; presentation |

---

## 9. Thesis Structure (Planned)

1. **Introduction** — Problem, motivation, objectives, scope
2. **Background** — Attack graphs, AWS security model, Zero Trust, related work
3. **Blast Radius Model** — Formal definitions, scoring formula, edge types
4. **Automated Scanner** — Architecture, discovery, graph construction, scoring
5. **Implementation** — CDK hardening, controls applied, deployment
6. **Evaluation** — Baseline measurements, progressive reduction, cross-architecture comparison, model validation
7. **Discussion** — Discrepancies, limitations, generalizability, practical implications
8. **Conclusion** — Contributions, future work

---

## 10. Required Resources

| Resource | Purpose | Status |
|---|---|---|
| AWS accounts (4) | Target environments for scanning and hardening | ✅ Available |
| Python + boto3 + networkx | Scanner development | ✅ Available |
| CDK (TypeScript) | Infrastructure hardening | ✅ Available (existing stacks) |
| VPC Flow Logs | Traffic analysis for "actually used" feature | ⚠️ Needs enabling |
| CloudTrail | API call analysis | ✅ Enabled by default (90 days) |
| Amazon Athena | Query flow logs at scale | ✅ Available |

---

## 11. Risks and Mitigation

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Hardening breaks WordPress service | Medium | High | Test all changes in dev first; run for 1 week before applying to prod |
| Scanner takes longer to build | Low | Medium | Core features (SG + routes + IMDS) are already proven manually; additional features are optional |
| VPC Flow Logs insufficient data | Low | Low | Enable immediately; 2-4 weeks provides sufficient data; this feature is optional for thesis |
| IAM policy evaluation too complex | Medium | Low | Use IAM Access Analyzer output as input; state as limitation |
| Model and scanner always agree (no interesting discrepancies) | Low | Low | Differences in edge cases (transitive access, conditional policies) are expected |

---

## 12. Related Work (Summary)

| Reference | Contribution | Gap This Thesis Fills |
|---|---|---|
| Capobianco et al. (2019) "Employing Attack Graphs for Intrusion Detection" — Penn State/EPFL, NSPW '19 | Formal attack graph model G=(V,E) with attack states and actions; proposes proactive use of attack graphs; automatic generation from configurations | Theoretical only (host/network focus); no cloud application; no quantitative scoring; no hardening validation |
| Ibrahim et al. (2019) "Attack Graph Generation for Microservice Architecture" — TU Munich, ACM SAC '19 | Extends attack graphs to Docker containers; BFS traversal; scalability evaluation up to 1000 nodes | Containers only; no AWS-native resources (IAM, SGs, IMDS); no scoring metric; lab environments |
| Stournaras (2023) "HackerGraph: Knowledge Graph for Security Assessment of AWS Systems" — KTH Stockholm | Knowledge graph for AWS using Neo4j; integrates multiple tools; models IAM privilege escalation paths | Lab environments (CloudGoat) only; explicitly excludes IMDS; no blast radius scoring; no control ranking; no before/after measurement |
| Malik (2023) "Monitoring and Analyzing Cyber Security Attacks in Microservice Applications using AWS" — Cal State Northridge | ML-based attack detection from CloudWatch logs; LSTM/Autoencoder models for classification | Reactive (detects after attack); no prevention or measurement; no graph model; no remediation |

**This thesis extends the above work by:** (1) applying attack graphs to real production AWS workloads, (2) introducing a quantitative blast radius metric, (3) combining network + IAM + IMDS into a unified model, (4) measuring control effectiveness progressively, and (5) validating automated findings against a formal mathematical model.

---

## 13. References

- Capobianco, F. et al. "Employing Attack Graphs for Intrusion Detection." NSPW '19, ACM, 2019.
- Ibrahim, A. et al. "Attack Graph Generation for Microservice Architecture." SAC '19, ACM, 2019.
- Stournaras, A. "HackerGraph: Creating a Knowledge Graph for Security Assessment of AWS Systems." KTH Royal Institute of Technology, 2023.
- Malik, J. "Monitoring and Analyzing Cyber Security Attacks in Microservice Applications using AWS." California State University Northridge, 2023.
- Ou, X. et al. "A Scalable Approach to Attack Graph Generation." ACM CCS, 2006.
- Sheyner, O. et al. "Automated Generation and Analysis of Attack Graphs." IEEE S&P, 2002.
- NIST SP 800-207. "Zero Trust Architecture." 2020.
- AWS Well-Architected Framework — Security Pillar. 2024.
- MITRE ATT&CK — Cloud Matrix. 2024.
- Prowler Documentation. https://github.com/prowler-cloud/prowler
- ScoutSuite Documentation. https://github.com/nccgroup/ScoutSuite

---

*Submitted for review by thesis advisor and industry supervisor (Dyn Media GmbH).*
