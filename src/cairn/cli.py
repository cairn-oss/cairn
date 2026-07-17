"""Cairn command-line interface.

Exit codes (stable contract for CI):
    0 — scan completed; no findings at/above the fail threshold
    1 — scan completed; findings at/above the fail threshold remain
    2 — Cairn could not run (bad usage, unreadable target, broken config)
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

from cairn import __version__
from cairn.audit import record_scan
from cairn.autofix import AutofixError, plan_fixes, render_plan
from cairn.costs import diff_costs, render_cost_diff
from cairn.drift import DriftError, detect_drift, render_drift
from cairn.editions import FREE_FOREVER, current_edition
from cairn.engine import run_scan
from cairn.findings import Finding, Severity
from cairn.llm import ExplainError, build_explainer
from cairn.policy import Config, ConfigError, load_config
from cairn.report import FORMATS
from cairn.report.proposal import render_proposal
from cairn.rules import all_rules

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cairn",
        description=(
            "Local-first IaC auditor: cost + security in a single pass, "
            "with fixes. Nothing leaves your machine by default."
        ),
    )
    parser.add_argument("--version", action="version", version=f"cairn {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a Terraform file or directory")
    scan.add_argument("path", help="a .tf file or a directory to scan recursively")
    scan.add_argument(
        "--format",
        choices=sorted(FORMATS),
        default="console",
        help="output format (default: console)",
    )
    scan.add_argument(
        "--output", metavar="FILE", help="write the report to FILE instead of stdout"
    )
    scan.add_argument(
        "--config",
        metavar="FILE",
        help="policy file (default: .cairn.yaml near the target)",
    )
    scan.add_argument(
        "--min-severity",
        metavar="SEV",
        help="drop findings below this severity (CRITICAL|HIGH|MEDIUM|LOW|INFO)",
    )
    scan.add_argument(
        "--fail-on",
        metavar="SEV",
        help=(
            "exit 1 when findings at/above this severity remain "
            "(default: HIGH; NEVER always exits 0)"
        ),
    )
    scan.add_argument(
        "--explain",
        action="store_true",
        help="expand findings with your configured LLM (BYO-key/local; opt-in)",
    )
    scan.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    scan.add_argument("--quiet", action="store_true", help="suppress the report; exit code only")
    scan.add_argument(
        "--no-plugins",
        action="store_true",
        help="ignore third-party rule plugins; run only built-in rules",
    )
    scan.add_argument(
        "--provider",
        metavar="LIST",
        help="comma-separated providers to include (aws,azure,gcp,vsphere,kubernetes)",
    )

    propose = sub.add_parser(
        "propose",
        help="draft a remediation proposal (review-ready markdown; changes nothing)",
    )
    propose.add_argument("path", help="a .tf file or a directory to scan recursively")
    propose.add_argument(
        "--output", metavar="FILE", help="write the proposal to FILE instead of stdout"
    )
    propose.add_argument(
        "--config",
        metavar="FILE",
        help="policy file (default: .cairn.yaml near the target)",
    )
    propose.add_argument(
        "--explain",
        action="store_true",
        help="expand fixes with your configured LLM (BYO-key/local; opt-in)",
    )

    diff = sub.add_parser(
        "diff",
        help="estimate the monthly cost impact of a change (old dir vs new dir)",
    )
    diff.add_argument("old", help="baseline Terraform file or directory")
    diff.add_argument("new", help="proposed Terraform file or directory")
    diff.add_argument(
        "--config",
        metavar="FILE",
        help="policy file providing budget.max_monthly_increase (default: near NEW)",
    )

    fix = sub.add_parser(
        "fix",
        help="apply whitelisted, policy-granted fixes (Trust Ladder rung 2)",
    )
    fix.add_argument("path", help="a .tf file or directory to scan and fix")
    fix.add_argument("--config", metavar="FILE", help="policy file (autonomy.allow grants)")
    fix.add_argument(
        "--apply",
        action="store_true",
        help="write the fixes (default is a dry run; requires a clean git worktree)",
    )

    drift = sub.add_parser(
        "drift",
        help="compare declared IaC against a `terraform show -json` snapshot",
    )
    drift.add_argument("path", help="Terraform file or directory (the declared config)")
    drift.add_argument("state", help="a state snapshot from `terraform show -json`")

    sub.add_parser(
        "license",
        help="show the running edition and the free-forever guarantee",
    )

    sub.add_parser(
        "providers",
        help="show which cloud/on-prem providers Cairn covers and how many rules each has",
    )

    rules = sub.add_parser("rules", help="list every built-in rule")
    rules.add_argument("--format", choices=["console", "markdown"], default="console")

    sub.add_parser("version", help="print the version")
    return parser


def _apply_cli_overrides(config: Config, args: argparse.Namespace) -> Config:
    """CLI flags win over file configuration (12-factor style layering)."""
    changes: dict[str, object] = {}
    if args.min_severity:
        changes["min_severity"] = Severity.from_str(args.min_severity)
    if args.fail_on:
        if args.fail_on.strip().upper() == "NEVER":
            changes["fail_never"] = True
        else:
            changes["fail_on"] = Severity.from_str(args.fail_on)
    if not changes:
        return config
    return replace(config, **changes)  # type: ignore[arg-type]


def _collect_explanations(config: Config, findings: list[Finding]) -> dict[Finding, str]:
    explainer = build_explainer(config.llm)
    if explainer.provider == "none":
        # --explain without configuration: default to a helpful error.
        raise ExplainError(
            "--explain requires an LLM provider. Set llm.provider in "
            ".cairn.yaml (openai|ollama|anthropic) or drop --explain. "
            "Cairn never sends data anywhere without this opt-in."
        )
    explanations: dict[Finding, str] = {}
    for finding in findings:
        text = explainer.explain(finding)
        if text:
            explanations[finding] = text
    return explanations


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"cairn: path does not exist: {target}", file=sys.stderr)
        return EXIT_ERROR

    try:
        config = load_config(
            explicit=Path(args.config) if args.config else None, search_dir=target
        )
        config = _apply_cli_overrides(config, args)
    except (ConfigError, ValueError) as exc:
        print(f"cairn: configuration error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    providers = (
        tuple(p.strip().lower() for p in args.provider.split(",") if p.strip())
        if args.provider
        else None
    )
    result = run_scan(
        target, config, use_plugins=not args.no_plugins, providers=providers
    )

    explanations: dict[Finding, str] = {}
    if args.explain and result.findings:
        try:
            explanations = _collect_explanations(config, result.findings)
        except ExplainError as exc:
            print(f"cairn: {exc}", file=sys.stderr)
            return EXIT_ERROR

    color = (
        not args.no_color
        and "NO_COLOR" not in os.environ
        and args.output is None
        and sys.stdout.isatty()
    )
    report = FORMATS[args.format](result, explanations=explanations, color=color)

    if args.output:
        # --quiet silences stdout, never a file the user explicitly asked for
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    elif not args.quiet:
        print(report)

    exit_code = EXIT_FINDINGS if config.should_fail(result.findings) else EXIT_OK
    record_scan(
        config.audit,
        target=str(target),
        files_scanned=result.files_scanned,
        resources_scanned=result.resources_scanned,
        findings_by_severity=result.counts_by_severity,
        duration_seconds=result.duration_seconds,
        exit_code=exit_code,
    )
    return exit_code


def _cmd_propose(args: argparse.Namespace) -> int:
    """Trust Ladder rung 1: Cairn drafts the change; a human applies it."""
    target = Path(args.path)
    if not target.exists():
        print(f"cairn: path does not exist: {target}", file=sys.stderr)
        return EXIT_ERROR
    try:
        config = load_config(
            explicit=Path(args.config) if args.config else None, search_dir=target
        )
    except ConfigError as exc:
        print(f"cairn: configuration error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result = run_scan(target, config)
    explanations: dict[Finding, str] = {}
    if args.explain and result.findings:
        try:
            explanations = _collect_explanations(config, result.findings)
        except ExplainError as exc:
            print(f"cairn: {exc}", file=sys.stderr)
            return EXIT_ERROR

    proposal = render_proposal(result, explanations=explanations)
    if args.output:
        Path(args.output).write_text(proposal + "\n", encoding="utf-8")
    else:
        print(proposal)
    record_scan(
        config.audit,
        target=str(target),
        files_scanned=result.files_scanned,
        resources_scanned=result.resources_scanned,
        findings_by_severity=result.counts_by_severity,
        duration_seconds=result.duration_seconds,
        exit_code=EXIT_OK,
        action="propose",
    )
    return EXIT_OK


def _cmd_diff(args: argparse.Namespace) -> int:
    old, new = Path(args.old), Path(args.new)
    for path in (old, new):
        if not path.exists():
            print(f"cairn: path does not exist: {path}", file=sys.stderr)
            return EXIT_ERROR
    try:
        config = load_config(
            explicit=Path(args.config) if args.config else None, search_dir=new
        )
    except ConfigError as exc:
        print(f"cairn: configuration error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    diff = diff_costs(old, new)
    limit = config.budget.max_monthly_increase
    print(render_cost_diff(diff, limit))
    if limit is not None and diff.delta > limit:
        return EXIT_FINDINGS
    return EXIT_OK


def _cmd_license() -> int:
    edition = current_edition()
    print(f"cairn edition: {edition.value}")
    print()
    print("Free forever (this repository, MIT):")
    for feature in sorted(FREE_FOREVER):
        print(f"  - {feature}")
    print()
    print("Team/Enterprise capabilities are provided by a separate commercial")
    print("package; the open-source core is complete and never degrades.")
    print()
    return EXIT_OK


def _cmd_fix(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"cairn: path does not exist: {target}", file=sys.stderr)
        return EXIT_ERROR
    try:
        config = load_config(
            explicit=Path(args.config) if args.config else None, search_dir=target
        )
    except ConfigError as exc:
        print(f"cairn: configuration error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    result = run_scan(target, config)
    root = target if target.is_dir() else target.parent
    try:
        plan = plan_fixes(
            result, config.autonomy.allow, apply=args.apply, root=root
        )
    except AutofixError as exc:
        print(f"cairn: {exc}", file=sys.stderr)
        return EXIT_ERROR

    print(render_plan(plan, applied=args.apply))
    if args.apply and plan.applied:
        record_scan(
            config.audit,
            target=str(target),
            files_scanned=result.files_scanned,
            resources_scanned=result.resources_scanned,
            findings_by_severity=result.counts_by_severity,
            duration_seconds=result.duration_seconds,
            exit_code=EXIT_OK,
            action="fix-apply",
        )
    return EXIT_OK


def _cmd_drift(args: argparse.Namespace) -> int:
    code_path, state_path = Path(args.path), Path(args.state)
    if not code_path.exists():
        print(f"cairn: path does not exist: {code_path}", file=sys.stderr)
        return EXIT_ERROR
    if not state_path.is_file():
        print(f"cairn: state snapshot not found: {state_path}", file=sys.stderr)
        return EXIT_ERROR
    try:
        report = detect_drift(code_path, state_path)
    except DriftError as exc:
        print(f"cairn: {exc}", file=sys.stderr)
        return EXIT_ERROR
    print(render_drift(report))
    return EXIT_FINDINGS if report.has_drift else EXIT_OK


def _cmd_providers() -> int:
    from cairn.providers import COVERED_PROVIDERS
    from cairn.rules import coverage_summary, load_plugins

    load_plugins()
    summary = coverage_summary()
    print("Cairn is cloud-agnostic and on-prem friendly. Covered providers:")
    print()
    for provider in COVERED_PROVIDERS:
        n = summary.get(provider, 0)
        label = "on-prem / private cloud" if provider == "vsphere" else provider
        print(f"  {label:<26} {n:>2} rule(s)")
    generic = summary.get("(any)", 0)
    if generic:
        print(f"  {'(all providers)':<26} {generic:>2} rule(s)")
    print()
    print("Terraform for any provider is parsed; resources with no rules are")
    print("reported as 'not scanned' rather than silently 'clean'. Kubernetes")
    print("manifests scan the same whether on a cloud or bare metal on-prem.")
    print("Add a provider or rule: see CONTRIBUTING.md.")
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    from cairn.rules import load_plugins

    load_plugins()
    rules = all_rules()
    if args.format == "markdown":
        print("| ID | Severity | Category | Title |")
        print("|----|----------|----------|-------|")
        for rule in rules:
            print(f"| {rule.id} | {rule.severity.value} | {rule.category.value} | {rule.title} |")
    else:
        width = max(len(r.id) for r in rules)
        for rule in rules:
            tag = "" if rule.source == "builtin" else f"  [{rule.source}]"
            print(
                f"{rule.id:<{width}}  {rule.severity.value:<8}  "
                f"{rule.category.value:<11}  {rule.title}{tag}"
            )
        n_plugin = sum(1 for r in rules if r.source != "builtin")
        extra = f" ({n_plugin} from plugins)" if n_plugin else ""
        print(f"\n{len(rules)} rules{extra}. Details: docs/rules.md")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "propose":
            return _cmd_propose(args)
        if args.command == "diff":
            return _cmd_diff(args)
        if args.command == "drift":
            return _cmd_drift(args)
        if args.command == "fix":
            return _cmd_fix(args)
        if args.command == "license":
            return _cmd_license()
        if args.command == "providers":
            return _cmd_providers()
        if args.command == "rules":
            return _cmd_rules(args)
        if args.command == "version":
            print(f"cairn {__version__}")
            return EXIT_OK
        return EXIT_ERROR  # pragma: no cover - argparse enforces choices
    except KeyboardInterrupt:
        print("cairn: interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
