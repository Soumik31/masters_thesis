# Running the Blast Radius Scanner

## Requirements

- Python 3.11 or newer (the package declares `requires-python = ">=3.11"`)
- AWS credentials for the account you want to scan, with read access to EC2, S3, Lambda, RDS, DynamoDB, IAM and STS

macOS system Python is 3.9 and will be rejected during install. Install a newer one with `brew install python@3.11` and use `python3.11` explicitly.

## One-time setup

```bash
cd "/Users/soumik.shadman/Library/CloudStorage/OneDrive-AxelSpringerSE/Documents/Soumik/git/thesis_topic/blast-radius-scanner"
python3.11 -m pip install -e .
python3.11 -m pip install matplotlib
```

`matplotlib` is needed for the chart output but is not declared as a dependency, so it must be installed separately.

Verify:

```bash
blast-radius-scanner --help
```

## Authenticate

The scanner uses the standard boto3 credential chain, so any of these work:

- environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- a named profile, passed with `--profile <name>`
- SSO, after `aws sso login`

Confirm which account you are pointed at before scanning:

```bash
aws sts get-caller-identity
```

The scanner also prints the account at startup, so check that line matches what you intended.

## Run

```bash
cd "/Users/soumik.shadman/Library/CloudStorage/OneDrive-AxelSpringerSE/Documents/Soumik/git/thesis_topic/blast-radius-scanner"
blast-radius-scanner --region eu-central-1 --auto-entry-point -v
```

### Flags

| Flag | Purpose |
|---|---|
| `--region` | Required. Region to scan, e.g. `eu-central-1` |
| `--auto-entry-point` | Pick the highest-scoring compute resource as the entry point |
| `--entry-point <id>` | Use a specific instance ID or Lambda ARN |
| `--all-entry-points` | Score every compute resource and print a comparison table |
| `--threat-model code-exec\|ssrf` | Which model drives the detailed sections. Both always appear in the comparison table. Default `code-exec` |
| `--exposed-only` | Only consider entry points an untrusted caller can reach without AWS credentials |
| `--include-stopped` | Also consider EC2 instances that are not running |
| `--profile <name>` | AWS profile to use |
| `--output text\|json` | Output format |
| `-v` | Verbose logging. Recommended, since IAM role resolution can take a while with no other visible progress |

Exactly one of `--auto-entry-point`, `--entry-point` or `--all-entry-points` must be given.

## Three ways to run, and what each one tells you

The same account produces three different numbers depending on which starting points you allow. They answer different questions, and mixing them up is the easiest way to draw a wrong conclusion.

### 1. Externally reachable only — the headline number

```bash
blast-radius-scanner --region eu-central-1 --auto-entry-point --exposed-only -v
```

Restricts entry points to resources an attacker can reach **without any AWS credentials**: an EC2 instance with a public IP, a Lambda with a public Function URL (`AuthType: NONE`), or a Lambda whose resource policy allows any principal.

This answers the question the thesis actually poses: *if an attacker reaches one of my services, how far can they spread?* Use it as the primary result.

If it reports no entry points, that is a finding rather than an error — it means nothing in the account is reachable without first compromising credentials.

### 2. Assumed compromise — the worst case

```bash
blast-radius-scanner --region eu-central-1 --auto-entry-point -v
```

Considers every compute resource, including internal-only ones. Reaching an internal Lambda requires AWS credentials, so this assumes the account is already partly compromised.

Useful as a worst-case bound, but it does **not** answer "how would an attacker get in". Label it clearly as an assumed-compromise figure if you report it.

Output still marks reachability per candidate, and prints a summary line:

```
  Note: 2/83 candidates are externally reachable. Others require prior account access to reach.
```

That ratio is often the most interesting single number in the run.

### 3. Every entry point compared

```bash
blast-radius-scanner --region eu-central-1 --all-entry-points -v
```

Scores every resource and prints one row each, with a `Reach` column separating external from internal:

```
  | #  | Entry Point                | Type   | Reach    | TM1 BR% | TM2 BR% | Status   |
  |----|----------------------------|--------|----------|---------|---------|----------|
  | 1  | wordpress-web              | EC2    | external |   61.2% |   61.2% | CRITICAL |
  | 2  | public-upload-fn           | Lambda | external |   34.8% |    0.0% | HIGH     |
  | 3  | internal-worker-fn         | Lambda | internal |   28.1% |    0.0% | HIGH     |
  ...
  Externally reachable: 2/83 entry points
```

Add `--exposed-only` here too if you want only the external rows.

Use this for the cross-architecture comparison, since it shows both the spread *and* how many places an attacker could start from.

## Reading the output

Blast radius is reported under two threat models:

- **TM1 code execution** — the adversary runs code on the entry point. Execution-role credentials are always obtainable, so IMDS version is irrelevant. This is the worst-case blast radius.
- **TM2 SSRF only** — the adversary can force outbound requests but cannot execute code. The role is only reachable if IMDSv1 is enabled, or IMDSv2 is set with a hop limit above 1.

```
  THREAT MODEL COMPARISON
    | Threat Model                    | Reachable | Total | BR%    |
    | TM1 code execution              | 31        | 41    |  75.6% |
    | TM2 SSRF only                   | 26        | 41    |  63.4% |

  CONTROL EFFECTIVENESS  CE(c) = BR_before - BR_after
    CE(IMDSv2) within code_exec                      0.00 pp
    CE(IMDSv2) within ssrf                          63.40 pp
```

`CE(IMDSv2) within code_exec` near zero is expected and correct: IMDSv2 does not stop an attacker who already runs code on the box. The control's real effect appears under TM2.

### Reachability markers

Each entry point candidate is labelled `external` or `internal`:

| Signal | Counted as externally reachable? | Why |
|---|:---:|---|
| EC2 with a public IP | yes | Directly addressable from the internet |
| Lambda Function URL, `AuthType: NONE` | yes | Callable by anyone over HTTPS |
| Lambda resource policy with `Principal: "*"` | yes | Any caller may invoke it |
| Lambda behind API Gateway | no | Detected and shown, but the API itself may require authentication |
| Lambda behind a load balancer | no | Same reasoning as API Gateway |
| Lambda with an event source mapping | no | Only matters if an attacker can write to the upstream queue or bucket |
| No signal found | no | Reported as "internal only" |

The last four are deliberately excluded from the external set, so the headline number under-claims rather than overstates. They still appear in the candidate's reasons, so you can review them by hand.

One limitation worth stating in the methodology: reaching a function and executing code inside it are separate steps. These signals cover reachability only. Executing arbitrary code additionally needs a flaw in the handler or a compromised dependency, which configuration analysis cannot determine.

## Results location

Each run writes to `results/<DDMMYYYY-HHMM>/`:

| File | Contents |
|---|---|
| `report.txt` | The text report as printed |
| `results.json` | Machine-readable results, including per-threat-model scores and CE values |
| `blast-radius-summary.png` | Reachable resources by type |
| `blast-radius-edge-impact.png` | Per-edge blast radius reduction |
| `blast-radius-diagram.png` | Block diagram of reachable resources |
| `blast-radius-graph.gexf` | Full graph, openable in Gephi |

The three PNGs are skipped when nothing is reachable, so a folder with only three files is a valid 0% result, not a failed run.

**Folder names have minute granularity.** Two scans finishing in the same minute will overwrite each other silently. Check the `All results saved to:` line after each run before starting the next.

## Test plan

Two sets of prior results exist to compare against. Both are superseded:

| Date | State of the code | Numbers |
|---|---|---|
| 18 Aug | Before threat models. Lambda disconnected from its own role | 0.0% / 0.0% / 47.8% / 63.4% |
| 21 Aug 12:xx | Threat models added, but log permissions still counted as full access | 96.7% / 98.2% / 90.9% / 92.2% |

Neither is usable. The first was a false negative for serverless; the second was inflated because almost every role carries CloudWatch Logs permissions, which were scored as full account access.

For each account, run all three modes:

```bash
blast-radius-scanner --region eu-central-1 --auto-entry-point --exposed-only -v   # headline
blast-radius-scanner --region eu-central-1 --auto-entry-point -v                  # worst case
blast-radius-scanner --region eu-central-1 --all-entry-points -v                  # comparison
```

| Account | Workload | What to check |
|---|---|---|
| 851725424182 | WordPress prod | Should be well below 92.2%. Instance is public, so `--exposed-only` must still find it. `CE(IMDSv2) within ssrf` should stay large; `within code_exec` should stay near 0 |
| 851725489819 | WordPress dev | Same pattern, below 90.9% |
| 905418363445 | sep3, serverless | Below 98.2%. Note how many of 81 functions are externally reachable — likely very few |
| 381492097421 | NER, serverless | Below 96.7%. Add `--include-stopped` on one run to cover the stopped EC2 that was previously skipped |

Two specific things to confirm, since they were the point of the fixes:

- Accounts should no longer all cluster near 100%. If they still do, the log fix is not taking effect and the run should be investigated rather than recorded.
- The `Externally reachable: N/M` line should show a small N on the serverless accounts and include the instance on the WordPress accounts. That contrast is the cross-architecture finding.

## Comparing before and after

```bash
cd "/Users/soumik.shadman/Library/CloudStorage/OneDrive-AxelSpringerSE/Documents/Soumik/git/thesis_topic/blast-radius-scanner"
for d in results/*/; do
  a=$(grep -m1 "Account:" "$d/report.txt" 2>/dev/null | awk '{print $2}')
  t=$(grep -m1 "Threat Model:" "$d/report.txt" 2>/dev/null | cut -d: -f2- | xargs)
  b=$(grep -m1 "Blast Radius:" "$d/report.txt" 2>/dev/null | awk '{print $3}')
  printf "%-16s %-14s %-8s %s\n" "$(basename "$d")" "${a:-?}" "${b:-?}" "${t:-<pre-threat-model>}"
done | sort -k2
```

Rows with no threat model are the older baselines, so before and after group together per account.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `zsh: permission denied` on `cd` | Smart quotes from a copy-paste. Retype the quotes, or omit them |
| `command not found: pip` | Use `pip3` or `python3.11 -m pip` |
| `Package requires a different Python: 3.9.6 not in '>=3.11'` | System Python is too old. `brew install python@3.11`, then use `python3.11` |
| `ModuleNotFoundError: No module named 'matplotlib'` | `python3.11 -m pip install matplotlib` |
| `Could not list IAM roles` warning | The caller lacks `iam:ListRoles`. The scan completes, but role chains are limited to compute-attached roles. Do not treat a low score as final until this is resolved |
| `Role resolution capped at 200 roles` | A role can assume broadly and the worklist hit its bound. Chains may be truncated. Record it, and the cap can be raised |
| `No externally reachable entry points found` with `--exposed-only` | Not an error. Nothing in the account is reachable without credentials. Record it, then re-run without the flag for the worst-case figure |
| All accounts land near 100% | The log-permission fix is not in effect. Confirm you are on commit `94bcedd` or later |
| `Operation timed out (os error 60)` reading project files | OneDrive has not synced the files locally. In Finder, right-click the folder and choose "Always Keep on This Device" |
| Result folder has only 3 files | Expected when blast radius is 0% — there is nothing to chart |

## Effect on the AWS account

The scanner is read-only. Every AWS call it makes is a `Describe*`, `Get*` or `List*`:

- **EC2** `describe_instances`, `describe_security_groups`, `describe_route_tables`, `describe_vpc_endpoints`, `describe_nat_gateways`, `describe_internet_gateways`
- **S3** `list_buckets`, `get_bucket_location`, `get_bucket_policy`, `get_public_access_block`
- **Lambda** `list_functions`, `get_function_url_config`, `get_policy`, `list_event_source_mappings`
- **RDS** `describe_db_instances`
- **DynamoDB** `list_tables`, `describe_table`
- **IAM** `list_roles`, `list_role_policies`, `get_role_policy`, `list_attached_role_policies`, `get_policy`, `get_policy_version`, `get_instance_profile`, `list_account_aliases`
- **STS** `get_caller_identity`

Two qualifications: the scanner writes report files to local disk, and the reads are recorded in CloudTrail. Read volume has grown noticeably — role chaining resolves policies transitively, and exposure detection makes up to three calls per Lambda function, so an account with 81 functions adds roughly 240 read calls on top. Worth knowing before scanning production if anyone monitors API rates.

To confirm empirically that nothing was written, while logged into the account:

```bash
aws cloudtrail lookup-events \
  --start-time <scan start, ISO8601 Z> --end-time <scan end, ISO8601 Z> \
  --query 'Events[?ReadOnly==`false`].[EventTime,EventName,EventSource]' --output table
```

An empty table means no write API call occurred during the window. Worth capturing once as evidence for the methodology chapter.
