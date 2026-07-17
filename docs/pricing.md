# Cost estimates: how the numbers are made

Cost findings carry a `monthly_cost` figure — the approximate USD/month
recovered by applying the fix. These come from a **bundled, offline price
book** (`src/cairn/pricing.py`), not from a cloud API.

## Why offline?

Local-first is the product's trust contract: a scan makes no network calls.
An offline price book keeps that promise while still putting an
order-of-magnitude dollar figure next to a decision at the moment it is
made. That is the job — decision support, not billing reconciliation.

## What the numbers are

- **Basis:** AWS on-demand, us-east-1, Linux, 730 hours/month.
- **EC2 / RDS right-sizing:** estimated waste = current type's monthly cost
  minus the suggested type's monthly cost.
- **gp2 → gp3:** volume size × ($0.10 − $0.08) per GB-month.
- **Idle Elastic IP:** $0.005/hour × 730.
- Types not in the book produce findings **without** a dollar figure rather
  than a guessed one.

## What they are not

- Not your negotiated rate, savings plan, or spot price.
- Not region-adjusted (differences are typically within ±25%).
- Not a substitute for your bill or a FinOps platform.

## Maintenance

The price book is reviewed each release. Corrections are welcome —
`pricing.py` is deliberately a plain dict so a PR is a one-line diff.
Roadmap: per-region books and an optional live-pricing plugin (opt-in,
because it is a network call).
