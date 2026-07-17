# Cairn — Brand Guide (v1)

Local-first IaC auditor · cost + security in one pass · writes the fix

A **cairn** is a stack of balanced stones that marks the safe path for those who
follow. That's the whole idea of the tool: it goes ahead of you into your
infrastructure and marks the safe route — flagging the cost and security
hazards, and pointing to the exact fix. The mark is a stacked-stone cairn with a
small **amber beacon** spark on top (the guiding light), which also appears as
the dot on the "i" in the wordmark.

Why this beats a generic security shield: it's ownable, it's literal to the
name, it carries the *guidance* idea (not just "guard"), and it sidesteps the
crowded shield/lock/cyber-cyan visual space.

---

## The mark

- **Primary** — purple gradient stones (light top → deep base) + amber beacon spark.
  Works on light and dark (the stones carry their own colour field).
- **Mono white** — one colour for dark UIs, stamps, single-colour print.
- **Mono ink** — one colour for light backgrounds and documents.
- **Favicon** — a simplified 3-stone stack + spark; still legible at 16px.

Never recolour the stones arbitrarily, add drop shadows, tilt the stack, or
separate the spark from the top stone. For one-colour use, use the mono files —
don't flatten the gradient by hand.

## Clear space & minimum size

- Clear space around the mark = **½ the mark's height**.
- Minimum mark size: **20px** on screen (favicon may go to 16px).
- On busy photography, use a solid tile or the avatar, never the bare gradient mark.

## Colour palette

| Token | Hex | Use |
|---|---|---|
| Cairn Purple | `#a371f7` | Primary brand, links, accents |
| Brand Deep | `#7c3aed` | Gradient base, pressed states |
| Brand Light | `#c9a7ff` | Gradient top, highlights |
| Beacon Amber | `#f0b429` | The spark / i-dot / CLI caret — the "guiding light" accent only |
| Verified Green | `#3fb950` | "pass / saved / recovered" only — never decorative |
| Ink | `#0d1117` | Primary dark background |
| Surface | `#161b22` | Cards, terminal panes |
| Text | `#e6edf3` | Primary text on dark |

Purple is the hero; amber is the single warm accent (the beacon); green is
*earned* — reserve it for verified/passed and for dollar savings so it keeps its
meaning (this mirrors the product's honesty principle: no fake green).

## Typography

- **Wordmark / headings:** a sturdy geometric sans (ships as outlines — no font
  needed). In product/web, pair with **Inter** or **Space Grotesk**.
- **Code / CLI / data:** a monospace (JetBrains Mono / Fira Code / DejaVu Mono).
  The CLI lockup and all terminal output use mono — core to the identity.

## Files (this folder)

```
cairn-brand/
├─ Cairn-brand-board.(png|svg)   one-glance system overview
├─ cairn-hero.png                LinkedIn launch hero (3240×4080, 4:5)
├─ BRAND-GUIDE.md                this file
├─ svg/   ← source of truth, scalable, self-contained
│   cairn-mark, -mark-white, -mark-ink, -favicon
│   cairn-logo-horizontal-dark, -light · cairn-logo-stacked-dark
│   cairn-cli-dark  · cairn-avatar-dark, -white-on-purple
│   cairn-social-card (1280×640) · cairn-readme-banner (1280×340)
└─ png/   ← ready-to-upload rasters
    marks 128/256/512/1024 · avatars 400/512/1024
    favicon 16/32/180 + favicon.ico · social-card 1280 · banner 1280/2560
```

Prefer the **SVG** wherever the destination accepts it (web, docs, README). Use
PNG only where a platform needs a raster (avatars, favicons, social card).

---

## Weekend launch playbook (DevOps / SRE / Platform)

Consistency across every surface *before* the post goes live is what makes a new
project look real. In order:

1. **GitHub org avatar** → `png/cairn-avatar-dark-512.png` (org → Settings → Profile).
2. **GitHub repo social preview** → `png/cairn-social-card-1280.png`
   (repo → Settings → Social preview) — this renders when the repo is shared.
3. **README header** → `svg/cairn-readme-banner.svg` (or the PNG) at the top of README.
4. **Favicon** for any docs/site → `png/favicon.ico` + `favicon-180.png` (apple-touch).
5. **X / LinkedIn / npm avatars** → `png/cairn-avatar-dark-400.png`.
6. **LinkedIn launch visual** → `cairn-hero.png` (the terminal hero; 4:5 feed-optimal).
7. **Dev-community flex** → the CLI lockup (`cairn-cli-dark`) reads as native
   terminal chrome — good for slide corners, stickers, a pinned-tweet image.

Handles are `cairn-oss` (bare `cairn` was taken): org `cairn-oss`, repo
`cairn-oss/cairn`, package `cairn-iac`, command `cairn`, site `cairn-oss.dev`.
