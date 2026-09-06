# /// script
# requires-python = ">=3.11"
# dependencies = ["jsonschema>=4.21", "pyyaml>=6.0", "rfc3339-validator>=0.1"]
# ///
# ABOUTME: Canonical check for the Firecracker Observatory specification package.
# ABOUTME: Validates schemas, examples, ID sequences, coverage and cross-references; run with `uv run docs/validation/check.py`.

import json
import re
import sys
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator, FormatChecker

DOCS = Path(__file__).resolve().parent.parent
RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    RESULTS.append((bool(ok), label))


def load_json(rel: str):
    return json.loads((DOCS / rel).read_text())


def validator(schema) -> Draft202012Validator:
    return Draft202012Validator(schema, format_checker=FormatChecker())


def valid(schema, instance) -> bool:
    return not list(validator(schema).iter_errors(instance))


def main() -> int:
    envelope = load_json("schemas/event-envelope.schema.json")
    launch_schema = load_json("schemas/launch-request.schema.json")
    report_schema = load_json("schemas/run-report.schema.json")

    for name, schema in [
        ("event-envelope", envelope),
        ("launch-request", launch_schema),
        ("run-report", report_schema),
    ]:
        try:
            Draft202012Validator.check_schema(schema)
            check(True, f"{name} schema validates against Draft 2020-12")
        except Exception:
            check(False, f"{name} schema validates against Draft 2020-12")

    event = load_json("examples/event.json")
    launch = load_json("examples/launch.json")
    launch_run = load_json("examples/launch-with-run.json")
    report = load_json("examples/run-report.json")

    check(valid(envelope, event), "Synthetic event satisfies envelope schema")
    check(valid(launch_schema, launch), "Synthetic launch satisfies launch schema")
    check(valid(launch_schema, launch_run), "Launch-with-run example satisfies launch schema")
    check(valid(report_schema, report), "Run-report example satisfies run-report schema")

    # Negative boundary cases: re-run key revision-1 rejections.
    bad = json.loads(json.dumps(event))
    bad["source_seq"] = 918
    check(not valid(envelope, bad), "Reject numeric 64-bit counter in envelope")
    bad = json.loads(json.dumps(event))
    bad["provenance"] = "self_attested"
    check(not valid(envelope, bad), "Reject unknown provenance enum")
    bad = json.loads(json.dumps(launch))
    bad["network"]["profile"] = "transport"
    bad["capture"]["http_headers"] = "redacted"
    check(not valid(launch_schema, bad), "Reject HTTP header capture in transport mode")
    bad = json.loads(json.dumps(launch))
    bad["observation"]["require_telemetry"] = True
    bad["observation"]["on_failure"] = "degrade"
    check(not valid(launch_schema, bad), "Reject strict telemetry with degrade-only action")

    # Negative boundary cases: declarative run block.
    bad = json.loads(json.dumps(launch_run))
    bad["initial_exec"] = None
    check(not valid(launch_schema, bad), "Reject exec_exit_zero criteria without initial_exec")
    bad = json.loads(json.dumps(launch_run))
    bad["run"]["on_completion"] = "detonate"
    check(not valid(launch_schema, bad), "Reject unknown run completion policy")
    bad = json.loads(json.dumps(launch_run))
    bad["run"]["goal"] = "x" * 4096
    check(not valid(launch_schema, bad), "Reject oversized run goal")
    bad = json.loads(json.dumps(launch_run))
    bad["run"]["goal"] = ""
    check(not valid(launch_schema, bad), "Reject empty run goal")
    bad = json.loads(json.dumps(launch_run))
    bad["run"] = None
    check(valid(launch_schema, bad), "Launch with null run block remains valid")

    # Negative boundary cases: run report linkage rules.
    bad = json.loads(json.dumps(report))
    del bad["event_rollup"][0]["reproduce_query"]
    check(not valid(report_schema, bad), "Reject rollup count without reproduce_query")
    bad = json.loads(json.dumps(report))
    bad["outcome"]["evidence_links"] = []
    check(not valid(report_schema, bad), "Reject outcome without evidence links")
    bad = json.loads(json.dumps(report))
    bad["attention"][0]["severity"] = "catastrophic"
    check(not valid(report_schema, bad), "Reject unknown attention severity")
    bad = json.loads(json.dumps(report))
    bad["outcome"]["status"] = "probably_fine"
    check(not valid(report_schema, bad), "Reject unknown run outcome status")

    # Host configuration consistency.
    config = yaml.safe_load((DOCS / "examples/host-config.yaml").read_text())
    check(isinstance(config, dict), "YAML host configuration parses as a mapping")
    check(config["capture"]["http_bodies_default"] == "off", "YAML body-capture off remains a string")
    check(config["observation"]["max_runner_spool_bytes"] == 536870912, "Spool limit matches 512 MiB prose target")
    check(config["observation"]["max_frame_bytes"] == 262144, "Frame cap matches 256 KiB prose target")
    check(config["terminal"]["max_replay_bytes_per_session"] == 4194304, "Terminal replay cap matches 4 MiB prose target")
    agent_cfg = config.get("agent_interface", {})
    goal_max = launch_schema["properties"]["run"]["anyOf"][0]["properties"]["goal"]["maxLength"]
    check(agent_cfg.get("run_goal_max_bytes") == goal_max, "Config run goal cap matches launch schema bound")
    tail_max = report_schema["$defs"]["stream_digest"]["properties"]["tail"]["maxLength"]
    check(agent_cfg.get("report_tail_max_bytes") == tail_max, "Config report tail cap matches report schema bound")
    triggers = agent_cfg.get("attention_triggers", {})
    check(len(triggers) == 8 and all(isinstance(v, bool) for v in triggers.values()), "Attention trigger classes enumerate as booleans")

    spec = (DOCS / "SPEC.md").read_text()
    acceptance = (DOCS / "ACCEPTANCE.md").read_text()
    readme = (DOCS / "README.md").read_text()

    # Acceptance ID sequence and requirement coverage.
    at_ids = re.findall(r"\| (AT-\d{3}) \|", acceptance)
    check(len(at_ids) == len(set(at_ids)), "Acceptance test IDs are unique")
    expected = [f"AT-{i:03d}" for i in range(1, 103)]
    check(sorted(at_ids) == expected, "Exactly 102 unique sequential acceptance IDs")

    # internal/evidence refuses to publish a record for a row this document does
    # not define, which only holds while its mirror of the row count agrees with
    # the document. This document is the source of truth; the constant follows.
    evidence_go = (DOCS.parent / "internal/evidence/evidence.go").read_text()
    mirrored = re.search(r"^const acceptanceRows = (\d+)$", evidence_go, re.MULTILINE)
    check(
        mirrored is not None and int(mirrored.group(1)) == len(expected),
        "internal/evidence acceptanceRows mirrors the acceptance row count",
    )

    spec_reqs = re.findall(r"^\| (R-\d{2}) \|", spec, re.MULTILINE)
    check(spec_reqs == [f"R-{i:02d}" for i in range(1, 18)], "SPEC defines exactly R-01 through R-17")
    covered = set(re.findall(r"R-\d{2}", acceptance))
    check(covered >= set(spec_reqs), "Acceptance matrix covers all 17 requirements")

    spec_principles = re.findall(r"^\| (P-\d{2}) \|", spec, re.MULTILINE)
    check(spec_principles == [f"P-{i:02d}" for i in range(1, 9)], "SPEC defines exactly P-01 through P-08")
    referenced_p = set(re.findall(r"P-\d{2}", acceptance)) | set(re.findall(r"\(P-\d{2}", spec))
    check({p.strip("(") for p in referenced_p} <= set(spec_principles), "Every referenced principle ID is defined")

    # Source verification ledger integrity.
    v_ids = re.findall(r"^\| (V-\d{2}) \|", spec, re.MULTILINE)
    check(v_ids == [f"V-{i:02d}" for i in range(1, 23)], "Exactly 22 unique sequential source-verification IDs")
    defined_sources = set(re.findall(r"^- \*\*(S\d+) — ", spec, re.MULTILINE))
    inline_sources = set(re.findall(r"\[(S\d+)\]", spec))
    check(inline_sources <= defined_sources, "Every inline source reference is defined")
    check(len(defined_sources) == 17, "Exactly 17 primary source definitions")

    # Markdown and embedded-example integrity.
    for name in ["SPEC.md", "ACCEPTANCE.md", "README.md", "VALIDATION.md"]:
        text = (DOCS / name).read_text()
        check(text.count("```") % 2 == 0, f"Markdown fenced code blocks balance in {name}")

    embedded = re.findall(r"```json\n(.*?)```", spec, re.DOTALL)
    parsed = []
    ok = True
    for block in embedded:
        try:
            parsed.append(json.loads(block))
        except Exception:
            ok = False
    check(ok and len(embedded) >= 4, f"All {len(embedded)} embedded JSON examples in SPEC parse")
    envelope_blocks = [p for p in parsed if isinstance(p, dict) and "source_instance_id" in p]
    check(
        len(envelope_blocks) >= 1 and all(valid(envelope, dict(p)) for p in envelope_blocks),
        "Embedded event example satisfies envelope schema",
    )

    # Prose count consistency and file inventory.
    check("102" in readme and "102 rows" in acceptance, "Prose test counts state 102")
    check(not re.search(r"\b88 (rows|mandatory|V1)", acceptance + readme + spec), "No stale 88-test count remains")
    listed = re.findall(r"`(schemas/[\w.-]+|examples/[\w.-]+|design/[\w.-]+|validation/check\.py)`", readme)
    missing = [f for f in listed if not (DOCS / f).exists()]
    check(not missing, "Every file listed in README exists")

    failures = [label for ok, label in RESULTS if not ok]
    for ok, label in RESULTS:
        print(f"{'PASS' if ok else 'FAIL'} — {label}")
    print(f"\n{len(RESULTS) - len(failures)}/{len(RESULTS)} package checks passed.")
    if failures:
        print("Failed:", *failures, sep="\n  - ")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
