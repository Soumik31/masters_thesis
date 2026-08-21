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
| `--include-stopped` | Also consider EC2 instances that are not running |
| `--profile <name>` | AWS profile to use |
| `--output text\|json` | Output format |
| `-v` | Verbose logging. Recommended, since IAM role resolution can take a while with no other visible progress |

Exactly one of `--auto-entry-point`, `--entry-point` or `--all-entry-points` must be given.

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

Four accounts, with the Aug 18 baselines to compare against:

| Account | Workload | Baseline BR | Run | Check |
|---|---|---:|---|---|
| 381492097421 | NER, serverless | 0.0% | `--auto-entry-point`, then `--include-stopped --all-entry-points` | No longer 0%. Entry-point scores differ between Lambdas rather than all reading 20/100. The previously skipped stopped EC2 now appears |
| 905418363445 | sep3, serverless | 0.0% | `--auto-entry-point`, then `--all-entry-points` | No longer 0% across functions, not just the selected one |
| 851725489819 | WordPress dev | 47.8% | `--auto-entry-point` | TM1 at or above 47.8%. `CE(IMDSv2) within code_exec` near 0 |
| 851725424182 | WordPress prod | 63.4% | `--auto-entry-point` | TM1 at or above 63.4%. Compare `CE(IMDSv2) within ssrf` against the earlier −58.5% figure |

The serverless accounts test the identity-edge fix. The WordPress accounts test role chaining — if their numbers do not move, no `sts:AssumeRole` grants were found, which is a finding to record rather than a failure.

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
| `Operation timed out (os error 60)` reading project files | OneDrive has not synced the files locally. In Finder, right-click the folder and choose "Always Keep on This Device" |
| Result folder has only 3 files | Expected when blast radius is 0% — there is nothing to chart |

## Effect on the AWS account

The scanner is read-only. Every AWS call it makes is a `Describe*`, `Get*` or `List*`:

- **EC2** `describe_instances`, `describe_security_groups`, `describe_route_tables`, `describe_vpc_endpoints`, `describe_nat_gateways`, `describe_internet_gateways`
- **S3** `list_buckets`, `get_bucket_location`, `get_bucket_policy`, `get_public_access_block`
- **Lambda** `list_functions`
- **RDS** `describe_db_instances`
- **DynamoDB** `list_tables`, `describe_table`
- **IAM** `list_roles`, `list_role_policies`, `get_role_policy`, `list_attached_role_policies`, `get_policy`, `get_policy_version`, `get_instance_profile`, `list_account_aliases`
- **STS** `get_caller_identity`

Two qualifications: the scanner writes report files to local disk, and the reads are recorded in CloudTrail. Role chaining increases that read volume noticeably compared with earlier versions, which is worth knowing before scanning production.
