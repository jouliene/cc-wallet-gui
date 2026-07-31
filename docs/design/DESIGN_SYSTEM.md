# CC Wallet — design system as rebuilt

The rules below are what the HTML copy now obeys everywhere. They start from the
repo's own tokens (`ui/design_tokens.slint`, `ui/theme.slint`) and settle the
places where the Slint corpus still disagreed with itself. Every value lives as a
CSS custom property in the DC's `:root`, so a change lands on the whole page.

## Colour

Palette is unchanged from `design_tokens.slint`, with these corrections:

- **The boundary family is one hue, four strengths, and each has one job.** `#A8BBD9`
  at 17 / 20 / 56 / 102:

  | token | role | worn by |
  | --- | --- | --- |
  | `--b-hair` 17 | separator | row-to-row inside one list |
  | `--b-subtle` 20 | container | card edges, chips, pills, segmented tracks, badges |
  | `--b-strong` 56 | control | every field, the token selector, an asset row, the lock button, a floating menu |
  | `--sel-line` 102 | selected | the chosen asset row |

  Plus one state pair: `--b-focus` `#D6E2F5B0` with `--b-focus-glow` for focused,
  open or active. `--b-med` was retired — it was a fourth value with no role, and
  its two users (the lock button, the OUT badge) belonged to `control` and
  `container` respectively.

  The rule is **role, not page**. Assets and Send looked like two different kits
  because a row that holds a value was drawn at container strength while the field
  beside it was drawn at control strength; the repo has the same split
  (`AssetListRow` takes `border_subtle`, `Field` takes `border_strong`). Anything
  that holds a value or takes input is a control, wherever it lives.

  White over the near-black page also reads warm, which is where the "brown line"
  came from; `--b-strong` came down from 90 to 56 in the same pass, because three
  stacked fields at 35% opacity were the loudest thing on the card. Quiet base,
  one step up for anything you can type into.
- `--b-focus` / `--b-focus-glow` are new. Field focus was the accent blue, which
  made a focused field look *selected*; it is now the resting border, lighter,
  plus a 1px inner glow. An open menu wears the same pair — an open dropdown is
  an active control, not a selected one.

**Accent marks actions and place. Silver marks state.**

- *Accent* — the primary button, MAX, the active tab, and the section badge every
  card and page header wears (40px, `--r-md`, `--accent-quiet` fill,
  `--accent-text` icon at `--ic-lg`; one spec, no exceptions — an earlier pass
  demoted the Assets / Send / Activity badges to keep the accent rare, which only
  made the wallet badge look like the odd one out).
- *Silver* — focus (`--b-focus` + `--b-focus-glow`), an open menu (the same pair),
  and selection (`--sel-fill` `#A8BBD91A` + `--sel-line` `#A8BBD966`). The
  selected asset row used to be an accent slab with a 50%-accent outline, while
  the same choice in the token menu was a check mark — one concept, two visual
  languages, and the slab's outline was louder than any border left in the app.
  Both now use the silver fill, and the menu keeps its check in `--t-secondary`.

The split is what makes each one legible: a page you are on and a button you can
press are the app talking about itself, whereas focus, open and chosen are the app
reporting your position inside it.

**Text tones**, four steps, one job each:

| token | used for |
| --- | --- |
| `--t-primary` | values, names, balances |
| `--t-secondary` | prose, counterparty names, settled figures, control icons |
| `--t-tertiary` | labels beside values, tickers, inline icons |
| `--t-quiet` | structural caps labels, counts, placeholders |

`--t-value` is retired — it held the same colour as `--t-secondary`.

## Type

Manrope for language, Chivo Mono (`--mono` / `--num`) for anything a reader
compares column to column: addresses, balances, amounts, fees, times, the node
endpoint. Chivo Mono's zero is a plain oval and its advances are equal across
weights, which is why the amount overlay can sit under a caret drawn from the
input's own text.

`font-variant-ligatures: none` is set on the root. Chivo Mono ligates `ff`, so an
address ending `…eeff0011` came out one cell shorter than its neighbour.

Sizes: `--f-micro` 11.5 · `--f-small` 12.5 · `--f-body` 14 · `--f-title` 19 ·
`--f-balance` 16 · `--f-amount` 20, all scaled by `--fs`. Those steps are
re-declared in px by the logic class: `calc(14px * var(--fs))` written in `:root`
resolves against the page's own `--fs`, so a scale set further down never reached
it — the tweak silently did nothing to the type.

**Addresses do not scale.** `--f-addr` is `min(var(--f-body), 14px)` and
`--f-addr-sm` is `min(var(--f-micro), 11.5px)`. An address is never worth
eliding, and a 67-character masterchain address (`-1:` + 64) needs 563px at 14px
— at a 1.2 scale it would need 675 and would have to be cut. It keeps the size it
was measured for and shrinks only downward.

**The overview strip sizes ADDRESS, not WALLET.** ADDRESS is fixed at 632px —
exactly the masterchain address plus its two actions — and WALLET takes whatever
is left (283px at 1180). It is the wallet *name* that varies in length, so the
slack belongs to it; sizing the name column and letting the address fight for the
remainder is how an address ends up elided.

The amount field is the exception in the other direction: it steps *down*
(20 → 17 → 14px) past 17 and 20 characters, because MAX on a nine-figure balance
must still read whole in a 280px field.

**Two label voices, not three:**

1. **Label** — micro, 700, `--track` (1.6px), caps, `--t-quiet`. Everything that
   names something: WALLET / ADDRESS / STATUS, RECIPIENT ADDRESS / AMOUNT, table
   heads, day bands. One voice, so a label never has to be identified by its case.
   (A pass tried the repo's unfinished CASE-01 split — sentence case for field
   names, caps for regions — and it read as an inconsistency, not a hierarchy:
   the reader sees two label styles on one card and looks for a meaning that
   isn't there. Hierarchy comes from position and size instead.)
2. **Value** — body or larger, 600, `--t-primary`.

## Money, one rule

Integer 600 in full tone, fraction 400 at `--frac` (0.65), monospaced and
tabular, integer grouped with `’`, fraction grouped in threes with a 1/3-em
space. It applies to balances, activity amounts, **fees**, and the amount field
while it is being typed — the separators live in the field's value so the caret
stays true. Fees carry the same nine decimals as amounts; shown to six they read
as a different kind of number from the AMOUNT beside them.

## Geometry

- Radii: `--r-sm` 8 · `--r-md` 12 · `--r-lg` 16, plus `50%` for dots and `30%`
  for avatars (one ratio, not twelve magic numbers).
- Icons: `--ic-sm` 14 (inline marks, every chevron) · `--ic-md` 17 (control
  icons) · `--ic-lg` 20 (card and page headers). Icon strokes were thickened
  1.8 → 2.15 to survive those sizes.
- Hit targets, all tokens — no bare pixel values in the markup:
  `--ctl-dense` 24 (a pair of actions inside a table row) · `--ctl-inline` 28
  (inside a field) · `--ctl-chip` 30 (chip, pill, segmented track, and the
  segment inside it at `calc(--ctl-chip - 8px)`) · 40 (standalone).
- Avatars: `--av-md` 32 (asset row) · `--av-sm` 22 (token selector) · `--av-xs`
  18 (activity token), each with its initial at `calc(size × 0.44 × --fs)` — the
  repo's own Avatar rule, which had been baked in as 14 / 9.68 / 7.92.
- `--label-h` 18: one height for every label row, so a field with a validation
  message beside its label does not shift against one without.

## Spacing, three registers

1. **Page rhythm 10** — the gap between cards and the page inset. This is the
   repo's `Space.page_inset` / `stack_gap` and nothing else uses it.
2. **Inside a surface 12 / 16 / 24** — card padding 16 across and 12 down, card
   header gap 12, strip column gap 16, the brand-to-tabs gap 24.
3. **Micro pairs 4 / 6 / 8** — label to value 4, icon to text 6, label row to
   field 8.

One-offs that used to sit between the registers are gone: the 26px nav spacer,
`8px 18px` tab padding, the 14px strip gap, `6px 12px 6px 10px` on the connection
pill, the 17px label row.
- Columns are sized to their longest real content, not to a round number: TIME
  52 (`14:02` in mono is 34.5px), FEE 112 (nine decimals), AMOUNT 175
  (`+100’000’000.999 999 999`).

## Motion

120ms for a hover or a border, 160ms for a fill, 900ms for the connection pulse,
1400ms for an acknowledgement tick. `ease-out` throughout.

## Tweaks

`accent` (three-tone palette), `density`, `radius`, `borderStrength`,
`fontScale`, `fracOpacity`, `groupFraction`, `stressNumbers`, `monoRecipient`.
`stressNumbers` swaps in nine-figure balances **and** the matching balances, so
the form's own validation still agrees with what is drawn — it is how the column
widths above were settled.
