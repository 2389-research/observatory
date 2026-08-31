# Specification Package Validation

These checks validate the handoff documents and synthetic interface examples. **They are not tests of a running Firecracker Observatory implementation.** No VMM, guest sensor, proxy, terminal, isolation, crash-recovery or performance acceptance test was executed as part of preparing this package.

The canonical check is `validation/check.py`, run as `uv run docs/validation/check.py`. Re-run it after changing any file in `docs/` and append a dated revision below. Earlier revisions are the historical record; never rewrite them.

## Revision 2 (2026-08-31) — agent-interface revision

Run after adding the agent-operations layer: principles P-01..P-08, requirements R-15..R-17, acceptance tests AT-089..AT-102, the run block in the launch schema, the run-report schema, two new examples and the `agent_interface` host-config block. The check script itself is new in this revision; it re-implements and extends the revision-1 checks.

### Results

- 46 package checks passed (`uv run docs/validation/check.py`, exit 0).
- All three JSON schemas passed Draft 2020-12 metaschema validation.
- Four positive examples validated; 13 invalid boundary examples were rejected as required, including the new run-block and run-report rules (exec_exit_zero without initial_exec, unknown completion policy, oversized/empty goal, rollup count without `reproduce_query`, outcome without evidence links, unknown severity and status enums).
- YAML parsed; the `agent_interface` caps match the schema bounds they mirror (`run_goal_max_bytes` = goal maxLength, `report_tail_max_bytes` = tail maxLength) and all 8 attention trigger classes enumerate as booleans.
- 102 unique sequential acceptance test IDs cover all 17 product requirements.
- P-01 through P-08 are defined once in SPEC §1.4 and every principle reference in SPEC and ACCEPTANCE resolves.
- 22 verification-ledger entries refer to the 17 primary source definitions.
- All 4 embedded JSON examples in SPEC parse; the embedded event still satisfies the envelope schema.
- No stale revision-1 counts (88 tests, 14 requirements) remain in prose.

### Check log

- PASS — event-envelope schema validates against Draft 2020-12
- PASS — launch-request schema validates against Draft 2020-12
- PASS — run-report schema validates against Draft 2020-12
- PASS — Synthetic event satisfies envelope schema
- PASS — Synthetic launch satisfies launch schema
- PASS — Launch-with-run example satisfies launch schema
- PASS — Run-report example satisfies run-report schema
- PASS — Reject numeric 64-bit counter in envelope
- PASS — Reject unknown provenance enum
- PASS — Reject HTTP header capture in transport mode
- PASS — Reject strict telemetry with degrade-only action
- PASS — Reject exec_exit_zero criteria without initial_exec
- PASS — Reject unknown run completion policy
- PASS — Reject oversized run goal
- PASS — Reject empty run goal
- PASS — Launch with null run block remains valid
- PASS — Reject rollup count without reproduce_query
- PASS — Reject outcome without evidence links
- PASS — Reject unknown attention severity
- PASS — Reject unknown run outcome status
- PASS — YAML host configuration parses as a mapping
- PASS — YAML body-capture off remains a string
- PASS — Spool limit matches 512 MiB prose target
- PASS — Frame cap matches 256 KiB prose target
- PASS — Terminal replay cap matches 4 MiB prose target
- PASS — Config run goal cap matches launch schema bound
- PASS — Config report tail cap matches report schema bound
- PASS — Attention trigger classes enumerate as booleans
- PASS — Acceptance test IDs are unique
- PASS — Exactly 102 unique sequential acceptance IDs
- PASS — SPEC defines exactly R-01 through R-17
- PASS — Acceptance matrix covers all 17 requirements
- PASS — SPEC defines exactly P-01 through P-08
- PASS — Every referenced principle ID is defined
- PASS — Exactly 22 unique sequential source-verification IDs
- PASS — Every inline source reference is defined
- PASS — Exactly 17 primary source definitions
- PASS — Markdown fenced code blocks balance in SPEC.md
- PASS — Markdown fenced code blocks balance in ACCEPTANCE.md
- PASS — Markdown fenced code blocks balance in README.md
- PASS — Markdown fenced code blocks balance in VALIDATION.md
- PASS — All 4 embedded JSON examples in SPEC parse
- PASS — Embedded event example satisfies envelope schema
- PASS — Prose test counts state 102
- PASS — No stale 88-test count remains
- PASS — Every file listed in README exists

### Not re-executed from revision 1

Revision 1 ran several boundary cases the current script does not repeat (invalid VM UUID, undeclared envelope property, boot-scoped event without VM scope, string boolean in quality, unbounded RAM, zero vCPU, undeclared host command, unpinned template, empty initial executable, filename-encoding match, resource-default match, status-labeling greps). The schemas those cases exercised are unchanged in this revision except for the additive `run` property; their revision-1 results stand as recorded below.

## Revision 1 (2026-08-30) — initial package

### Results

- 39 package checks passed.
- Both JSON schemas passed Draft 2020-12 metaschema validation.
- Positive examples and 13 invalid boundary examples behaved as expected under the schemas.
- YAML parsed; units/defaults checked for consistency.
- 88 unique sequential acceptance test IDs cover all 14 product requirements.
- 22 verification-ledger entries refer to the 17 primary source definitions.
- Embedded JSON examples parsed; the embedded event matched its schema.

### Check log

- PASS — event-envelope schema validates against Draft 2020-12
- PASS — launch-request schema validates against Draft 2020-12
- PASS — Synthetic event satisfies schema
- PASS — Synthetic launch satisfies schema
- PASS — Encoded example filename matches display bytes
- PASS — offline metadata-only launch is valid
- PASS — transport metadata-only launch is valid
- PASS — Strict telemetry with pause is valid
- PASS — Host-wide pre-index envelope is valid
- PASS — Reject numeric 64-bit counter
- PASS — Reject invalid VM UUID
- PASS — Reject unknown provenance enum
- PASS — Reject undeclared envelope property
- PASS — Reject boot-scoped event without VM scope
- PASS — Reject string boolean in quality
- PASS — Reject unbounded launch RAM
- PASS — Reject zero vCPU
- PASS — Reject undeclared launch host command
- PASS — Reject HTTP header capture in transport mode
- PASS — Reject strict telemetry with degrade-only action
- PASS — Reject unpinned template syntax
- PASS — Reject empty initial executable
- PASS — YAML host configuration parses as a mapping
- PASS — YAML body-capture off remains a string
- PASS — Launch resource examples match host defaults
- PASS — Spool limit matches 512 MiB prose target
- PASS — Frame cap matches 256 KiB prose target
- PASS — Terminal replay cap matches 4 MiB prose target
- PASS — Exactly 88 unique sequential acceptance IDs
- PASS — Acceptance matrix covers all 14 requirements
- PASS — Exactly 22 unique sequential source-verification IDs
- PASS — Every inline source reference is defined
- PASS — Exactly 17 primary source definitions
- PASS — Markdown fenced code blocks balance
- PASS — Embedded JSON example 1 parses
- PASS — Embedded JSON example 2 parses
- PASS — Embedded event example 2 satisfies envelope
- PASS — Specification labels unimplemented status
- PASS — Acceptance suite labels all rows not run

## Explicitly not established

Runtime correctness, safety against attacks, TLS-client compatibility, actual resource overhead, supported concurrent-VM count, terminal latency, event throughput, durable recovery and final-diff accuracy all require implementation and the real acceptance evidence described in `ACCEPTANCE.md`. The source verification ledger establishes external design premises only. The agent-interface additions raise the bar further: interaction-budget compliance (AT-102), situation/attention correctness (AT-089..091) and run-report truthfulness (AT-092..095) are all implementation claims that only the acceptance suite can establish.
