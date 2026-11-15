---
name: Autonomous Defense Interface
colors:
  surface: '#0c1321'
  surface-dim: '#0c1321'
  surface-bright: '#323949'
  surface-container-lowest: '#070e1c'
  surface-container-low: '#151b2a'
  surface-container: '#19202e'
  surface-container-high: '#232a39'
  surface-container-highest: '#2e3544'
  on-surface: '#dce2f6'
  on-surface-variant: '#c3c6d7'
  inverse-surface: '#dce2f6'
  inverse-on-surface: '#2a3040'
  outline: '#8d90a0'
  outline-variant: '#434654'
  surface-tint: '#b3c5ff'
  primary: '#b3c5ff'
  on-primary: '#002a76'
  primary-container: '#5f8bff'
  on-primary-container: '#002467'
  inverse-primary: '#0354d6'
  secondary: '#5de6ff'
  on-secondary: '#00363e'
  secondary-container: '#00cbe6'
  on-secondary-container: '#00515d'
  tertiary: '#4edea3'
  on-tertiary: '#003824'
  tertiary-container: '#00a572'
  on-tertiary-container: '#00311f'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#dbe1ff'
  primary-fixed-dim: '#b3c5ff'
  on-primary-fixed: '#00184a'
  on-primary-fixed-variant: '#003fa5'
  secondary-fixed: '#a2eeff'
  secondary-fixed-dim: '#2fd9f4'
  on-secondary-fixed: '#001f25'
  on-secondary-fixed-variant: '#004e5a'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#0c1321'
  on-background: '#dce2f6'
  surface-variant: '#2e3544'
typography:
  display-lg:
    fontFamily: Geist
    fontSize: 48px
    fontWeight: '600'
    lineHeight: 56px
    letterSpacing: -0.03em
  display-lg-mobile:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-xl:
    fontFamily: Geist
    fontSize: 36px
    fontWeight: '600'
    lineHeight: 44px
    letterSpacing: -0.025em
  headline-xl-mobile:
    fontFamily: Geist
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '500'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-sm:
    fontFamily: Geist
    fontSize: 18px
    fontWeight: '500'
    lineHeight: 24px
    letterSpacing: -0.015em
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: -0.005em
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0em
  label-code:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: -0.01em
  label-badge:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.04em
  metric-stat:
    fontFamily: Geist
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1.5rem
  gutter-mobile: 0.75rem
  margin: 2rem
  margin-mobile: 1rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2.5rem
---

## Brand & Style

This design system embodies high-assurance precision, predictive intelligence, and operational clarity. Engineered for SecOps leaders, cloud architects, and threat hunters, it projects an aura of cryptographic security and uncompromising technical rigor. The interface balances high-density utility with modern developer-centric elegance, drawing tactical inspiration from low-latency platforms like Linear, Stripe, and Cloudflare.

The visual direction merges refined technical minimalism with layered glassmorphism. Deep, void-like midnight canvases reduce cognitive fatigue in continuous surveillance environments, while crisp electric accents guide immediate threat remediation. UI elements feel tangible yet atmospheric—utilizing subtle sub-pixel borders, fine interior glow lines, and precise chromatic state indicators that instill quiet confidence under mission-critical conditions.

## Colors

The palette leverages an ultra-deep luminous spectrum optimized for OLED and dark workspaces, strictly calibrated to convey threat severity and cryptographic states without visual noise.

### Foundations & Surfaces
- **Canvas Default (`#0B1220`):** Pure deep midnight navy. The global backdrop across full-viewport consoles.
- **Surface Subdued (`#111C2E`):** Dark slate used for structural paneling, sidebars, and elevated workspace sections.
- **Surface Elevated (`#162238`):** Resting state for cards, tables, dialogs, and modular telemetry modules.
- **Surface Interactive (`#1E2D4A`):** Hover, active states, and nested focus layers.
- **Surface Light / Inverse (`#F8FAFC`):** Crisp off-white reserved for high-impact CTAs, inverted visual indicators, and dominant textual elements.

### Accent & Luminescence
- **Primary Electric (`#477DFF`):** Used for focal CTAs, active telemetry indicators, and focused bounding states.
- **Secondary Cyan (`#22D3EE`):** AI synthesis indicators, dynamic packet streams, and automated patch queues.
- **Border Luminescence (`rgba(71, 125, 255, 0.15)`): The foundational structural stroke providing definition against dark backgrounds without overpowering content.

### Telemetry & Severity Statuses
- **Verified / Safe (`#10B981`):** Shield active, automated mitigation successful, compliant nodes.
- **Warning / Suspicious (`#F59E0B`):** Anomalous egress, drift detected, unverified certificates.
- **Critical / Danger (`#EF4444`):** Active breach attempt, privilege escalation, unpatched zero-day.
- **Muted Slate (`#94A3B8`):** Informational metrics, secondary labels, timestamp metadata.

## Typography

Typography prioritizes rapid legibility, dense parsing speed, and technical exactitude. The typographic hierarchy pairs Geist for structured structural headings with Inter for high-density reading and JetBrains Mono for cryptographic proofs, IP routing, hash digests, and machine logs.

- **Headlines & Display:** Set tightly with negative letter spacing (`-0.015em` to `-0.03em`) to project architectural solidity and modern software precision.
- **Body & Data:** Standard neutral tracking (`-0.005em` to `0em`) ensures seamless scanability across large telemetry feeds and audit trails.
- **Labels & Monospace:** Small-scale metadata, protocol chips, and hash summaries use JetBrains Mono to avoid alphanumeric ambiguity (e.g., distinguishing `0` and `O`, `1` and `l`). Monospace numbers (`font-variant-numeric: tabular-nums`) must be enforced across all quantitative data streams.

## Layout & Spacing

The layout is built on a 12-column fluid-grid architecture calibrated for continuous desktop viewport densities (1440px+ command consoles) with robust responsiveness down to mobile incident-response views.

### Structure & Density
- **Command Density:** Compact spacing modules (`space-xs`, `space-sm`) are preferred within data grids, timeline nodes, and configuration editors to allow high informational throughput without vertical scroll fatigue.
- **Canvas Breakpoints:**
  - **Desktop (≥ 1280px):** 12-column fluid layout with persistent contextual sidebars and fixed utility rails. Spacing uses standard `margin` (32px) and `gutter` (24px).
  - **Tablet (768px – 1279px):** 8-column layout with collapsable navigation ribbons and stacked metric rails.
  - **Mobile (< 768px):** 4-column layout; data grids collapse to single-metric cards with horizontal audit streams. Margin drops to `margin-mobile` (16px).
- **Rhythm:** Spacing follows an intentional 4px baseline matrix. Container inner padding scales between `space-md` (16px) for cards and `space-lg` (24px) for master inspector panels.

## Elevation & Depth

Visual hierarchy does not rely on heavy drop-shadows. Instead, elevation is achieved through physical surface stratification, glassmorphism, and internal neon rim lighting.

### Surface Hierarchy
1. **Base Layer (Level 0):** Unlit midnight navy (`#0B1220`). Global background.
2. **Structural Layer (Level 1):** Solid `#111C2E` with 1px border `rgba(255, 255, 255, 0.05)`. Navigation shells, splitters, tab bars.
3. **Card & Module Layer (Level 2):** `#162238` with `backdrop-filter: blur(12px)` and 1px border of `rgba(71, 125, 255, 0.15)`.
4. **Floating / Modal Layer (Level 3):** `#1E2D4A` elevated with a compound edge: a 1px border of `rgba(71, 125, 255, 0.3)` paired with an ambient tinted glow: `0 8px 32px -4px rgba(0, 0, 0, 0.6), 0 0 24px -2px rgba(71, 125, 255, 0.12)`.

### Rim & Glow Lighting
- **Active / Focused Containers:** Highlighted via an inner inset glow: `inset 0 1px 1px 0 rgba(71, 125, 255, 0.25)`.
- **Threat Escalation Glow:** Critical containers utilize a perimeter halo of `0 0 20px -2px rgba(239, 68, 68, 0.25)` to demand instant visual resolution.

## Shapes

The design system employs a soft, technical shape profile (Level 1). By utilizing controlled 4px to 12px radii, interfaces preserve an engineered, high-precision aesthetic reminiscent of low-level developer platforms rather than consumer software.

- **Micro-Controls (Inputs, Buttons, Checkboxes):** Base radius of 4px (`rounded-sm`).
- **Telemetry Cards & Panels:** Standard radius of 8px (`rounded-lg`).
- **Modals & Flyouts:** Outer boundary radius of 12px (`rounded-xl`).
- **Status Badges & Chips:** Fully pill-shaped (`rounded-full`) to immediately delineate qualitative status tags from rectangular actionable controls.

## Components

### Buttons
- **Primary:** High-contrast off-white (`#F8FAFC`) fill with dark navy typography (`#0B1220`) for immediate primary actions. Hover transitions to `#E2E8F0` with a subtle electric outer aura (`0 0 16px rgba(248, 250, 252, 0.2)`).
- **Secondary (Technical):** Dark slate surface (`#162238`) with 1px border `rgba(71, 125, 255, 0.2)` and text in `#477DFF`. Hover shifts border to `rgba(71, 125, 255, 0.5)` and surface to `#1E2D4A`.
- **Destructive:** Surface `rgba(239, 68, 68, 0.1)`, 1px border `rgba(239, 68, 68, 0.3)`, text `#EF4444`. Hover elevates background to `rgba(239, 68, 68, 0.2)`.

### Badges & Pill Indicators
- Compact, high-visibility badges with an uppercase tracking (`0.04em`).
- Structure: 1px border, 10% opacity tinted fill of corresponding status color, and a leading 6px glowing status dot.
  - *Safe:* Text `#10B981`, border `rgba(16, 185, 129, 0.25)`, dot glow `0 0 8px #10B981`.
  - *Warning:* Text `#F59E0B`, border `rgba(245, 158, 11, 0.25)`, dot glow `0 0 8px #F59E0B`.
  - *Critical:* Text `#EF4444`, border `rgba(239, 68, 68, 0.3)`, dot glow `0 0 8px #EF4444`.

### Input Fields & Search Bars
- Background `#0B1220` inset into surface containers. 1px border of `rgba(255, 255, 255, 0.1)`.
- Text `#F8FAFC`, placeholder `#64748B`.
- **Focus State:** 1px border `#477DFF` accompanied by electric halo `0 0 0 2px rgba(71, 125, 255, 0.2)`. Monospace query inputs include an automated terminal cursor indicator.

### Telemetry Cards & Metric Panels
- Constructed from `#162238` with `backdrop-filter: blur(12px)`.
- Enclosed with a 1px border of `rgba(71, 125, 255, 0.15)`.
- Top edge features an inner stroke gradient highlight fading from `rgba(71, 125, 255, 0.3)` to transparent to emulate directional key-light reflection.

### Lists & Data Grids
- Alternating rows avoid striped fills; separation is maintained via 1px horizontal dividers (`rgba(255, 255, 255, 0.04)`).
- Hovering a row initiates a background transition to `rgba(71, 125, 255, 0.05)` with an electric accent bar (2px wide, `#477DFF`) anchored to the far left margin.
- Monospace values for IP addresses, SHA-256 hashes, and execution latencies aligned via tabular numerals.

### Checkboxes & Toggle Switches
- Checkboxes: 4px rounded squares with `rgba(255, 255, 255, 0.1)` border. Checked state fills with `#477DFF` and displays a crisp white SVG check.
- Toggles: 24px wide pill track in `#111C2E` with 1px border. The thumb glows slightly (`#22D3EE` when activated) to convey machine operational states.