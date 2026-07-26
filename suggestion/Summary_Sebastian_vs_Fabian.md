# Sebastian vs Fabian — Summary & Recommendation

---

## Sebastian's Suggestion — "Security Between AWS Accounts"

### The Problem He Sees

Dyn Media has many AWS accounts (maybe one per team, one per environment, one per service). These accounts are connected — probably through a Transit Gateway. Right now, if Account A is compromised, can the attacker jump to Account B, C, D?

### What He Wants You to Build

- A system that says "Account A can ONLY talk to Account B, and nothing else" (default-deny between accounts)
- A dashboard that shows: which accounts are talking to which, how much data is flowing between them
- A workflow where if someone needs a new connection between accounts, they open a Pull Request, it gets reviewed, and only then the connection is allowed

### Think of It Like This

You have 20 apartments in a building. Right now, all the doors between apartments are unlocked. Sebastian wants you to lock all doors, give each apartment only the keys they need, and install cameras in the hallways to see who's walking where.

### Pros

- Big organizational impact — affects all accounts
- Your manager clearly cares about this problem
- Governance/visibility is valuable

### Cons

- Can become a huge project (building a portal/dashboard is product work, not thesis work)
- Overlaps with Transit Gateway work already happening at Dyn Media
- Hard to scope tightly for a 3-4 month thesis
- More "tooling" than "security research" — harder to write an academic thesis around

---

## Fabian's Suggestion — "Security Inside One Workload"

### The Problem He Sees

Forget about account-to-account for now (that's being handled elsewhere). The real question is: if an attacker gets into ONE service (like your WordPress site or your Article Generator), how far can they go WITHIN that account?

### What He Wants You to Do

- Pick ONE real production workload (WordPress or Article Generator)
- Model 2-3 realistic attack scenarios: "What if the attacker gets code execution on this EC2 instance?"
- Implement controls so the attacker is stuck — can't reach the database, can't reach other services, can't reach the internet
- Then produce reusable patterns (documentation, checklists, SCPs) that other teams can copy

### Think of It Like This

Instead of securing the whole building, pick ONE apartment. Show that if a burglar breaks in through the window, they can only access the living room — not the safe, not the bedroom, not the neighbor's apartment. Then write a guide so every apartment owner can do the same thing.

### Pros

- Perfect thesis scope — one workload, 2-3 scenarios, clear before/after
- No overlap with ongoing Transit Gateway work
- Produces a clear "before vs after" story with measurable numbers
- Reusable patterns benefit the whole org
- Combines networking (security groups, VPC endpoints) + identity (IAM least-privilege) — strong academic content

### Cons

- Smaller blast radius of impact (one workload, not the whole org)
- Depends on picking the right workload and getting access to modify it

---

## Side-by-Side Comparison

| | Sebastian | Fabian |
|---|---|---|
| **Scope** | All accounts, org-wide | One workload, deep dive |
| **Question answered** | "Can Account A reach Account B?" | "If this EC2 is hacked, what can the attacker reach?" |
| **What you build** | Dashboard + governance workflow + monitoring | Security controls + attack validation + reusable docs |
| **Risk of scope creep** | High — can become a product | Low — tightly bounded |
| **Overlap with existing work** | Medium — Transit Gateway project | Low — explicitly avoids it |
| **Thesis-friendly?** | Harder — more tooling than research | Easier — clear hypothesis, measurable results |
| **Time to complete** | Risky in 3-4 months | Comfortable in 3-4 months |
| **Org value** | High (if completed) | Medium-High (reusable patterns) |

---

## My Honest Take

**For a thesis: Fabian's approach is better.** Here's why in one sentence: a thesis needs a clear question, a method, measurable results, and a conclusion — "I hardened workload X, reduced blast radius from 80% to 5%, here's the evidence" is a perfect thesis. "I built a governance dashboard" is a product, not a thesis.

**But you don't have to choose one and ignore the other.** You could do Fabian's approach as the core thesis, and mention Sebastian's cross-account concern in the "Future Work" chapter. That way both leaders see their input reflected.

---

## What to Say When Presenting This

> "I got two suggestions from my leaders. Sebastian wants me to focus on security between AWS accounts — building governance and monitoring for cross-account traffic. Fabian wants me to focus on security inside one workload — picking a real system, modeling attack scenarios, and proving that least-privilege controls reduce the blast radius. I'm leaning toward Fabian's approach because it's better scoped for a thesis, avoids overlap with ongoing Transit Gateway work, and produces a clear before/after measurement. But I'll include cross-account governance as future work."

---

*Use this document to present both options clearly to your thesis advisor or any other stakeholder.*
