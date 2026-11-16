# Ghost Data Still Exists

Deletion audit agent for the HackerRank Orchestrate October 2026 challenge.

A deletion workflow can report Complete while the person's data is still sitting in a database, a
replica, a search index, an analytics profile, a support attachment, an export bucket, a cache, or a
backup that is still restorable. This agent ignores what the workflow claims, reconstructs the state
of every record at the case's `audit_at` time from the supplied evidence, applies
`dataset/deletion_rules.csv`, and decides whether the deletion actually happened.

For every request it writes one row to `output.csv` with a status and an ordered list of steps:
what remains, what to do about it, and what must be checked afterwards.

```text
case_id,deletion_status,steps_json
```

---

## Setup

Requirements: Python 3.10 or newer. No API key, no model download, no GPU and no network access at
run time. Everything except the PDF reader is the standard library.

1. Lay the project out so the dataset sits beside the code:

   ```text
   ghost-data-still-exists/
     dataset/          the supplied participant dataset, unzipped as given
     code/             the agent
     evaluation/       metrics, validation, custom cases, the two required reports
     output.csv        written by the run, at the project root
   ```

2. Install the one optional dependency. It is used only to read the PDF artifacts in
   `dataset/evidence/documents/`; every other format is parsed directly.

   ```bash
   pip install pymupdf
   ```

3. Run the agent from the project root:

   ```bash
   python code/main.py
   ```

   The run prints `wrote 518 rows to .../output.csv` followed by a token counter that reads
   `model calls: 0` on this dataset, because no model is called. Expect about 5 seconds. Two runs
   produce a byte identical file: rows are ordered by numeric `case_id` and JSON keys are emitted in
   a fixed order.

4. Verify the result:

   ```bash
   python evaluation/validate_output.py   # contract checks, exits 0 with no errors
   python evaluation/main.py              # metrics on the 32 supplied sample cases
   python evaluation/custom_cases.py      # 5 participant authored cases
   ```

`validate_output.py` re reads the manifest, the activity stream and the policy file and checks the
submission independently of the pipeline: row count, vocabulary, step numbering, phase order,
citation provenance, citation timing, evidence rules per status, finding to remediation to
verification coverage, and policy legality.

`dataset/` is not part of this archive. The agent reads it from the project root, and the paths are
resolved relative to `code/audit_agent/config.py`, so the project works from any directory and on
Windows, macOS and Linux.

---

## How it works

```text
dataset/                code/audit_agent/
  deletion_requests.csv   identity.py     resolve email to a subject and its full alias history
  user_identities.csv     evidence.py     94 artifacts to 2879 observations
  user_audit_log.csv      anchors.py      recover a lost account id from the workflow stream
  system_activity.csv     policy.py       deletion_rules.csv as executable guards
  deletion_rules.csv      planner.py      reconciled states to ordered steps
  evidence_files.csv      intent.py       does the message authorise deletion
  evidence/               pipeline.py     load, reconcile at audit_at, plan, serialise
```

### 1. Intent

A deletion audit is only authorised if the person asked for deletion. Access, correction, export and
marketing opt out requests return `NOT_APPLICABLE` with an empty step list even when every other
field looks like a deletion case. Withdrawal phrases are checked first and win over any deletion
word in the same message. A follow up asking the desk to confirm that the profile is gone still
counts as authorising the audit.

All 518 requests are decided by the deterministic matcher: 508 carry a deletion marker in one of the
supported languages, 10 are explicit withdrawals. An optional model hook exists for requests that
carry no marker at all; it is off unless a provider, model and key are supplied through environment
variables, and it was never reached on this dataset.

### 2. Identity

The request email may be an address the person stopped using years ago. The resolver matches the
current snapshot first, then the full history in `user_audit_log.csv`, and turns every address,
phone number and email hash the person ever used into a search key. Secondary systems keep old
spellings long after the primary service moved on, so a single current address is not enough.

### 3. Evidence

Every manifest entry is parsed into observations of the form:

```text
(file, artifact capture time, row time, system, resource, policy category, state, identity keys)
```

Eleven parsers cover the supplied formats: SQL snapshots and replicas, snapshot bundles, service
resource exports, connector configs, audit ledgers, export manifests, observability logs, read back
traces, support replicas, handover tables, PDFs, and screenshots.

Two parsing details matter more than they look:

- Records wrap the interesting fields one or two levels down (`{"document": {...}}`,
  `{"profile": {...}}`), so identity extraction recurses.
- Resource prefixes are matched longest first. `audit_record_003` is a security audit record, not an
  `audit` prefix with an unknown category.

Screenshots carry no text layer. Their visible facts were read once and are stored in
`code/vision_cache.json` with the file id, the focal record, the visible identifiers and the state
the screen establishes, so a screenshot is cited exactly like any other artifact and the run itself
needs no model.

### 4. Reconciliation at `audit_at`

Two clocks gate every observation.

- The row time is when the row was recorded.
- The artifact time is when the file was collected.

An artifact collected after `audit_at` did not exist yet, so nothing inside it may decide the case,
even when its rows or per store snapshot times are earlier. That artifact may still name a resource,
and it may still prove a compliant state, because a check step needs no citation. A violation needs
one, so a violation must come from a cited artifact. This single rule is the difference between
plausible answers and correct ones.

Within the window, the newest observation per `(system, resource)` wins. That is what makes
replication drift visible: a regional replica captured a day after the primary still holds a profile
the primary already deleted, and the replica is the truth at audit time.

Two refinements:

- A workflow link row proves ownership, not state. For connectors and backups it says nothing about
  whether a sync runs or a restore is possible, so those rows never decide a state.
- When a screenshot or snapshot agrees with the settled state, the file is cited rather than a newer
  workflow row, because the file is what an auditor would open.

### 5. Policy

`deletion_rules.csv` is loaded at run time rather than duplicated as constants. Each category maps to
one guard: delete, redact, anonymize, retain, block restore, or disable flow.

- A `SECURITY_AUDIT_LOG` or `LEGAL_HOLD_RECORD` must still be there, so it is verified present.
- A `SUPPORT_MESSAGE` that still carries the customer address is redacted, not deleted, because the
  conversation also holds agent and order context.
- An `ANALYTICS_PROFILE` that is still attributable is anonymized.
- A `BACKUP_ARCHIVE` that can still restore is a restore risk.
- An `ACCOUNT_TOMBSTONE` keeps only the stable internal reference and nothing else.

### 6. Planning

Findings, then remediation, then verification, in the operation order from the problem statement,
then by system, then by resource.

For an `INCOMPLETE` case the plan is complete: every finding gets a remediation of the right kind,
and every remediated record gets a post remediation check. Copying and restoring are stopped before
records change, so a running sync cannot recreate a record that was just deleted. Remediation and
future checks carry an empty `evidence_id` because they describe work that has not happened yet.

For a `COMPLETE` case every step is a verification step with a citation, covering every record the
audit touched, including the records policy requires to remain.

### 7. Missing account records

Some subjects have no account row in any snapshot because the profile was already deleted. An absent
account is exactly what a finished deletion should prove, so the identifier is recovered from the
ownership index, and when it appears nowhere, from the deletion worker stream
(`source_system=deletion_worker`, `target_system=account_service`, `event_type=DELETE_RECORD`) by
matching the cases reported in the same time window. A recovered identifier is only ever used for an
absent account check, never as a finding, so a wrong guess cannot flip a status. 17 of 518 cases use
this path.

---

## Results

Sample set, 32 cases:

| Measure | Result |
|---|---|
| Deletion status accuracy | 32 / 32 (1.000) |
| Step precision | 0.995 |
| Step recall | 0.943 |
| Step F1 | 0.968 |
| Field accuracy on aligned steps | 1.000 for phase, system, resource, operation, state, evidence |
| Sequence accuracy | 22 / 32 (0.688) |
| Participant authored cases | 5 / 5 exact |

The real run writes 518 rows and 2807 steps: 159 `COMPLETE`, 349 `INCOMPLETE`, 10 `NOT_APPLICABLE`,
and `validate_output.py` reports zero contract errors.

Every remaining sample set difference is documented in `evaluation/evaluation_report.md`,
including the records that no artifact in the dataset can tie to a subject and the one case where
two candidate accounts were equally plausible.

`evaluation/usage_report.md` records the provider and model accounting for the run that produced
`output.csv`: zero model calls, zero tokens, zero cost, and why a deterministic agent needs none.

---

## Project layout

```text
README.md                  this file
code/
  main.py                  entry point, python code/main.py
  vision_cache.json        screenshot transcriptions, read once, cited as files
  audit_agent/
    config.py              paths, phases, operation order, operation to state
    identity.py            identity resolution and alias history
    evidence.py            all artifact parsers, observation model, repository
    anchors.py             workflow stream account recovery
    policy.py              deletion_rules.csv as executable guards
    planner.py             reconciled states to ordered steps
    intent.py              request authorisation
    pipeline.py            load, reconcile, plan, serialise
evaluation/
  main.py                  sample set metrics with step alignment
  custom_cases.py          5 participant authored cases
  validate_output.py       independent contract validation
  evaluation_report.md     metrics, custom cases, failures and fixes
  usage_report.md          provider, model calls, tokens, cost
```

`dataset/` is not part of the submitted archive. The solution reads it from the project root.
