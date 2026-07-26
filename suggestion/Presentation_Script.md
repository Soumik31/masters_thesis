# Presentation Script — Thesis Proposal

**Topic:** Automated Blast Radius Measurement and Reduction in AWS Cloud Workloads  
**Duration:** ~10-15 minutes  
**Audience:** Thesis advisor / company supervisors

---

## OPENING (1 minute)

> "Hi everyone, thank you for your time. Today I want to present my thesis proposal. The title is: Automated Blast Radius Measurement and Reduction in AWS Cloud Workloads Using Attack Graph Analysis."

> "In simple terms: I want to answer the question — if one of our services gets hacked, how far can the attacker go? And then I want to build a tool that measures this automatically and proves that specific security controls reduce it."

---

## THE PROBLEM (2 minutes)

> "Let me explain the problem with a simple example."

> "At Dyn Media, we have services like WordPress and the Article Generator running on AWS. Each service has compute (EC2, Lambda), databases (RDS, DynamoDB), storage (S3), and an IAM role with permissions."

> "Right now, if an attacker compromises the WordPress EC2 instance — through a vulnerable plugin, a supply chain attack, or an SSRF vulnerability — what can they reach?"

> "The honest answer is: we don't know exactly. And that's the problem."

> "We suspect the answer is: a lot. The EC2 instance probably has a broad IAM role, a security group that allows outbound to the internet, and sits in a network where it can reach the database, S3 buckets, and possibly other services."

> "AWS gives us individual tools — Security Hub finds misconfigurations, Inspector checks for vulnerabilities, IAM Access Analyzer finds unused permissions. But none of them answers the combined question: from this one compromised resource, what's the total set of things the attacker can reach? That's what I call the blast radius."

---

## WHAT I PROPOSE (3 minutes)

> "My thesis does four things:"

> "**First:** I define a formal model for blast radius. It's based on graph theory. Every AWS resource is a node. If one resource can reach another — through the network, through IAM permissions, or through metadata exploitation — that's an edge. Blast radius is the percentage of all resources that are reachable from the compromised node."

> "**Second:** I build an automated scanner — a Python tool using boto3 and networkx — that discovers all resources in an AWS account, maps every reachability path, constructs the attack graph, and calculates a blast radius score. It also ranks every connection by how much it contributes to the score."

> "**Third:** I apply security controls one by one — enforce IMDSv2, restrict security groups, remove internet egress, tighten IAM policies, scope VPC endpoint policies — and after each control, I run the scanner again. This gives me a progressive reduction curve showing exactly how much each control helps."

> "**Fourth:** I validate by comparing my mathematical model's predictions against the scanner's actual measurements. If they match, both are validated. If they differ, the discrepancies are interesting — they reveal blind spots in the model or the scanner."

---

## THE TARGET WORKLOADS (2 minutes)

> "I'll apply this to two real production workloads at Dyn Media:"

> "**WordPress** — our primary case study. It's a traditional architecture: EC2 instance, RDS MySQL database, S3 for media files, deployed via CDK. We have both a dev account and a production account. This is where I'll do the full hardening."

> "**Article Generator** — our validation case study. It's serverless: 16+ Lambda functions, DynamoDB tables, S3 buckets, Amazon Bedrock integration. Completely different architecture. By applying the same method to both, I can answer the question: does my approach generalize across architecture types?"

> "The interesting comparison is: in a traditional architecture, blast radius is mostly driven by network reachability (security groups, routes). In a serverless architecture, it's mostly driven by IAM permissions (what the Lambda role can do). My model captures both."

---

## WHAT MAKES THIS DIFFERENT (2 minutes)

> "There are existing tools in this space. Let me explain why this thesis is different:"

> "Security Hub shows attack paths, but doesn't give you one unified score or let you compare before and after."

> "VPC Reachability Analyzer checks one network path at a time — it doesn't map everything from a compromised node."

> "IAM Access Analyzer only looks at permissions — it ignores the network."

> "Prowler and ScoutSuite do compliance checks — they tell you 'this security group is too broad' but they don't tell you what that actually means in terms of attacker reach."

> "My thesis combines all of these — network reachability, IAM permissions, and metadata exploitation — into one unified metric. And it measures progressive improvement, which none of the existing tools do."

> "In the academic literature, attack graphs have been applied to traditional networks and to Docker containers, but not to real production AWS workloads with a combined network + identity + metadata model. That's the gap I'm filling."

---

## TIMELINE (1 minute)

> "The thesis is 12 weeks:"

> "Weeks 1-2: Define the formal model and literature review."

> "Weeks 3-5: Build the automated scanner. Core functionality: security groups, route tables, IMDS configuration, basic IAM analysis."

> "Week 6: Enable VPC Flow Logs and run the baseline scan on all four accounts — this gives me the 'before' measurements."

> "Weeks 7-8: Implement hardening controls on WordPress — first in dev, then in production. Run the scanner after each control to build the progressive reduction curve."

> "Week 9: Run the scanner on the Article Generator for the cross-architecture comparison."

> "Week 10: Compare model predictions vs scanner results. Analyze discrepancies."

> "Weeks 11-12: Write the thesis, finalize the tool, prepare the presentation."

---

## WHAT DYN MEDIA GETS (1 minute)

> "Besides the thesis, Dyn Media gets concrete deliverables:"

> "One — a hardened WordPress workload in both dev and production."

> "Two — a reusable scanner tool that can be run on any AWS account to measure blast radius. Other teams can use this immediately."

> "Three — CDK hardening patterns as reference implementations that teams can copy."

> "Four — security recommendations for the Article Generator based on the scan results."

---

## RISKS AND MITIGATION (1 minute)

> "The main risk is breaking WordPress when I apply hardening controls. I mitigate this by testing everything in the dev account first and running it for at least one week before applying to production."

> "The scanner might take longer to build than expected — but the core features (security groups, routes, IMDS) are straightforward with boto3. Advanced features like full IAM policy evaluation are optional and can be listed as limitations if needed."

> "VPC Flow Logs need to be enabled — I'll do that immediately so data is available by the time I need it."

---

## CLOSING (30 seconds)

> "To summarize: I'm proposing to build a formal model and automated tool that answers the question 'how far can an attacker go?' — applies it to two real workloads — proves that specific controls reduce the blast radius — and validates the results mathematically."

> "The output is a thesis with quantitative results, a reusable tool, and hardened production infrastructure."

> "I'm happy to take questions."

---

## LIKELY QUESTIONS & ANSWERS

**Q: "Why not use AWS Security Hub's attack path features?"**
> A: "Security Hub shows individual attack paths but doesn't give a unified score across all paths from one resource. It also doesn't let you measure progressive improvement — you can't see 'applying control X reduced my score by 15%.' My tool fills that gap."

**Q: "Is 12 weeks enough?"**
> A: "Yes. The model definition is 2 weeks. The scanner's core is boto3 API calls to describe security groups, route tables, and IAM roles — that's well-documented and straightforward. The hardening is CDK changes to existing stacks. The most time-intensive part is the writing."

**Q: "What if the model and scanner always agree?"**
> A: "That's a valid outcome — it means the model accurately captures reality. But in practice, I expect discrepancies in edge cases like conditional IAM policies, transitive cross-account access, or time-limited credentials. Either way, the analysis is valuable."

**Q: "How does this relate to Sebastian's cross-account suggestion?"**
> A: "My model currently focuses on blast radius within one account. Cross-account reachability (via Transit Gateway, resource policies, role assumption) could be added as a future extension. I mention this in the Future Work chapter."

**Q: "Will you actually break production?"**
> A: "No. Every control is tested in dev first for at least one week. The scanner itself is read-only — it only calls describe/list/get APIs, never modifies anything. The hardening changes are CDK deployments that can be rolled back with one command."

**Q: "Why WordPress AND Article Generator? Isn't one enough?"**
> A: "One workload proves the method works. Two workloads proves it generalizes. The comparison between traditional (network-centric) and serverless (identity-centric) architectures is an important contribution — it shows which controls matter most for each type."

---

## TIPS FOR DELIVERY

- Speak slowly and clearly, especially during the formal model explanation
- Use the "simple example" at the start — everyone understands "if this server is hacked, what else can the attacker reach?"
- When explaining the graph model, draw a simple diagram with 5-6 nodes and arrows if you have a whiteboard
- Emphasize the before/after measurement — that's what makes this a thesis (not just "I hardened something")
- If time is short, skip the "Related Work" section — save it for questions
- End confidently: "I'm happy to take questions" — not "that's all I have"
