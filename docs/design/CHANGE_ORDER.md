# Change order — Wallet and Contacts

Scope: the **Wallet** page and the **Contacts** page only. Everything else in the
app is untouched by this order; see "Out of scope" at the end.

This is written against an HTML/CSS rebuild of both pages at the real 1180×820
window size. Its companion is `DESIGN_SYSTEM.md` in this same folder, which states
each rule and why it exists; where the two disagree, `DESIGN_SYSTEM.md` is right —
it is the one being maintained. These two files are the whole design brief; there is
no other design documentation to consult.

Two things to keep in mind while applying it:

- **Most of it is `ui/design_tokens.slint`.** Values, not call sites. Resist the
  urge to edit the 340 places that read a token.
- **Intent, not implementation.** The HTML reference works around browser
  limitations that Slint does not have (a transparent input with the figure drawn
  over it, a placeholder colour reset, literal-only hover rules). Read the *rule*
  in each item, not the trick.

Every item is marked:

    TOKEN      a value in design_tokens.slint; no structural change
    LAYOUT     geometry in theme.slint or a page/component
    RUST       formatting or a limit that lives outside the UI
    DECISION   needs your call before it is applied

---

## Phase 1 — tokens

One commit. It changes pixels on every screen, so regenerate the whole baseline
set in the same commit (see "Baseline" below). Reviewing this phase screenshot by
screenshot is not useful; review it token by token.

### 1.1 One boundary family, four strengths, by role — TOKEN

Replace the four boundary tokens. One hue, `#A8BBD9`, four alphas:

| token | alpha | role | worn by |
| --- | --- | --- | --- |
| `border_hairline` | 17 (`#A8BBD911`) | separator | row-to-row inside one list |
| `border_subtle` | 20 (`#A8BBD914`) | container | card edges, chips, pills, segmented tracks, badges |
| `border_strong` | 56 (`#A8BBD938`) | control | every `Field`, the token selector, `AssetListRow`, the lock button, `MenuSurface` |
| `selected_border` | 102 (`#A8BBD966`) | selected | the chosen asset row |

Delete `border_medium`. Its two consumers move by role: the lock button
(`wallet_sections.slint`) is a control → `border_strong`; the OUT badge
(`wallet_components.slint`) is a chip → `border_subtle`.

Two reasons this is not just a tint:

1. `#FFFFFF5A` over `#06070A` reads warm — a brown line. The cool tint at the same
   strength does not.
2. `AssetListRow` took `border_subtle` while the `Field` beside it took
   `border_strong`, so Assets and Send looked like two different kits. A row that
   holds a value is a control.

`border_strong` also drops from alpha 90 to 56: three stacked fields at 35%
opacity were the loudest thing on the Send card, louder than the money in it.

### 1.2 Focus is not selection — TOKEN

Retire `focus_ring` as a field treatment. New pair:

    focus_border: #D6E2F5B0     // the resting control border, lighter
    focus_glow:   #A8BBD924     // drawn as a 1px inner ring

A focused `Field` takes `focus_border` plus the glow. An **open** menu — the token
selector, the wallet switcher, the activity filters — takes the same pair on its
anchor, because an open dropdown is an active control, not a selected one.

Keyboard focus on buttons, tabs, checkboxes and chips keeps its own ring; that is a
different job and it stays accent. If you prefer one treatment
there too, that is a **DECISION**, not part of this order.

### 1.3 Selection speaks silver — TOKEN

    selected_fill:       #A8BBD91A
    selected_fill_hover: #A8BBD92E
    selected_border:     #A8BBD966   // as in 1.1
    drag_marker:         #C6D4EA

- `AssetListRow` selected: `selected_fill` + `selected_border` instead of
  `accent_quiet` + a 50%-accent outline.
- `TokenPickerMenu` / `ActivityTokenMenu`: the chosen row gets `selected_fill`,
  and its check mark moves from `accent_text` to `text_secondary`.
- The contacts drag insertion line and the lifted row's frame move from `accent`
  to `drag_marker`.

The rule this comes from: **accent marks actions and place; silver marks state.**
Accent stays on the primary button, MAX, the active tab and the section badge every
card header wears. Focus, open, selected and dragging are all silver. The split is
what makes each legible — a page you are on and a button you can press are the app
talking about itself; focus, open and chosen are the app reporting your position
inside it.

Two things this fixes beyond the colour: the selected row's outline was stronger
than any other boundary in the app, and "which token is chosen" was being said two
different ways — an accent slab in the list, a check mark in the menu.

### 1.4 Hover has to be visible on a raised surface — TOKEN

`hover_row` (`#FFFFFF08`, 3%) all but vanishes on `surface_overlay`. Menu rows take
`hover_strong`. A row that is already selected takes `selected_fill_hover` — at
present a chosen row does not answer the pointer at all, because its hover value
equals its resting value.

### 1.5 Type — TOKEN

- `tracking_caps`: **1.6px** (was 2px on an 11.5px label — too wide at that size).
- New step `Fonts.balance` = **16px**, used by `AssetListRow`'s balance. 14px made
  the one number the card exists for the same size as the label above it.
- **Addresses do not scale.** Cap them: `Fonts.address` = `min(body, 14px)`,
  `address_small` = `min(micro, 11.5px)`, `address_medium` = `min(small, 12.5px)`.
  A 67-character masterchain address (`-1:` + 64) needs 563px at 14px; the strip
  can offer 639px. At a 1.2 type scale it would need 675 and would have to elide,
  and an address is never worth eliding.
- The Send amount field goes to **20px** and steps *down* — 20 → 17 → 14px past 16
  and 19 characters — so MAX on a nine-figure balance still reads whole. This is
  the one place type shrinks to fit, and it is deliberate: the integer must never
  be cut.
- Field labels stay **caps**, and the sentence-case alternative is rejected: it was
  tried in the reference and read as an inconsistency rather than a hierarchy — two
  label styles on one card make the reader look for a meaning that is not there.
  The unused `FieldLabel` component in `widgets.slint` can be deleted.

### 1.6 One face for every figure — TOKEN + RUST

Chivo Mono, tabular, for anything a reader compares down a column: balances,
activity amounts, fees, times, the amount field, the recipient field. Manrope stays
for language. `Fonts.mono` is already the right token; this is about which call
sites use it.

Then one rule for how an amount is written, everywhere:

> integer at `semibold` in full tone · fraction at `regular` at `Fade.muted` ·
> integer grouped with `’` · fraction grouped in threes with a 1/3-em space

`Amount` in `widgets.slint` already does the first half. Missing pieces:

- the fraction is not grouped at all — nine digits in a row is unscannable;
- **the fee is not an amount today** (RUST): it is shown to six decimals as one
  flat 65%-opacity string. It carries the same nine decimals as the amount beside
  it and splits into integer + fraction like every other figure. Shown to six it
  reads as a different *kind* of number.

Column widths in 2.3 assume the fee at nine decimals.

### 1.7 Ligatures — DECISION, then TOKEN

In the HTML reference Chivo Mono ligated `ff`, so an address ending `…eeff0011`
rendered one cell narrower than its neighbour and the column stopped aligning. Your
bundled Chivo Mono is instanced and subset by hand, so it may already have no
`liga`/`calt` tables. **Check before changing anything**: render two addresses, one
containing `ff`, and compare widths. If they differ, disable ligatures for the mono
face app-wide.

### 1.8 Icons — TOKEN

- Three sizes only: **14** (inline marks, every chevron), **17** (control icons),
  **20** (card and page headers). The corpus currently spans 11 to 24.
- Stroke weight in the bundled SVGs: **1.8 → 2.15**. At 14–17px the 1.8 stroke
  reads as a grey smudge; `paste.svg` in particular was unreadable in the field.
- `contacts.svg` (a card with a face and two lines) is replaced by `users.svg` at
  the recipient field's picker. At 18px the card metaphor is unreadable; two
  figures are not.
- The two row actions (copy, open-in-explorer) drop to 14px and `text_quiet`. They
  were the same weight as the address they follow, and they are the supporting
  cast.

### 1.9 Control sizes and spacing — TOKEN

Hit targets, all named, no bare literals:

    control_dense:  24px   // a pair of actions inside a table row
    control_inline: 28px   // inside a field
    control_chip:   30px   // chip, pill, segmented track (segment = chip − 8)
    control_large:  40px   // standalone

Avatars: **34 / 32 / 22 / 18**, initial at `size × 0.44` — the rule `Avatar` already
expresses, currently baked in as the literals 14 / 9.68 / 7.92 at three call sites.

`label_row_h: 18px` — one height for every label row, so a field with a validation
message beside its label does not shift against one without. It is 17px today,
which is a measurement, not a decision.

Spacing collapses to three registers:

1. **page 10** — `page_inset` / `stack_gap`, and nothing else uses it;
2. **inside a surface 12 / 16 / 24** — card padding 16 across and 12 down, card
   header gap 12, strip column gap 16, brand-to-tabs 24;
3. **micro pairs 4 / 6 / 8** — label to value 4, icon to text 6, label row to
   field 8.

Retire the values that sit between the registers: the 26px nav spacer, `8px 18px`
tab padding, the 14px strip gap, `6px 12px 6px 10px` on the connection pill.

### 1.10 Text selection — TOKEN

`selection-background-color` is `Palette.accent` today. Move it to `#A8BBD94D`:
after 1.3, an accent selection is the only place where accent means "state".

---

## Phase 2 — structure

One change per commit, each with its own baseline diff. In this order.

### 2.1 The overview strip sizes ADDRESS, not WALLET — LAYOUT

`wallet_sections.slint` / `theme.slint`:

- ADDRESS becomes **fixed at 632px** — exactly a 67-character masterchain address
  plus the two actions beside it.
- The **wallet switcher takes the slack** (283px at a 1180 window) instead of its
  fixed 248px.
- `wallet_status_w` 96 → **90**; column gap → 16; strip padding → 16 all round.

The reasoning is the inverse of what is there now: the address has a known maximum
width and must never elide, the wallet *name* is the thing that varies, so the
slack belongs to the name. Sizing the name column and letting the address fight for
the remainder is exactly how an address ends up elided.

### 2.2 An Explorer jump wherever there is an address — LAYOUT

Beside the copy button, in a pair with zero gap between them:

- the wallet's own address in the overview strip → opens this account;
- every contact row → opens that account;
- every activity row → opens the transaction, **or the account when there is no
  hash yet**. Today the button disappears on a pending transfer. The account on
  the other side is already on chain, so the jump stays and only its destination
  changes.

### 2.3 Activity columns — LAYOUT

`theme.slint`, with the fee at nine decimals (1.6):

| column | from | to | why |
| --- | --- | --- | --- |
| `activity_time_w` | 78 | **58** | `14:02` in mono is 34.5px; 78 left a visible hole before TYPE |
| `activity_type_w` | 58 | **64** | air on the other side of the badge |
| `activity_amount_w` | 220 | **175** + 71 token block | `+100’000’000.999 999 999` needs 166px and was being clipped |
| `activity_money_gap` | 36 | **12** | reclaimed for the amount |
| `activity_fee_w` | 92 | **112** | nine decimals in a monospaced face |
| fee → finality gap | — | **12** | at 6px the fee and `sending…` read as one string |
| `activity_final_w` + `activity_action_w` | 70 + 26 | **72 merged** | the mark belongs to FINALITY; the header now stands over both |

`FINALITY` was sized for `sending…`, which is on screen for about a second, while
`1.6s` lives there the rest of the time.

### 2.4 The Send card — LAYOUT + RUST

- AMOUNT, the token selector and the Send button move into a **462px left
  column**; the space to their right takes a new **COMMENT** field, full height of
  that group.
- The amount field gains a **Clear** beside MAX, on the same spec as the recipient
  field's — with `×` in one field and nothing in the other, the pair read as an
  oversight.
- **COMMENT limit (RUST).** The body is a 32-bit zero op code plus UTF-8 in a Cell
  of 1023 bits: 123 bytes in the root cell, then 127 per referenced cell in snake
  format. Budget **four referenced cells → 631 bytes**, counted in **bytes, not
  characters** (a Cyrillic letter spends two, an emoji up to four), truncating on a
  character boundary. The counter reads `400 / 631`. If the wallet cannot chain
  snake cells yet, the honest limit is 123 and the counter says so.
- The token selector becomes a real dropdown on the `MenuSurface` spec, opening
  **down** and reaching a few pixels past the primary button's right edge —
  otherwise a blue sliver of the button shows beside the menu.

### 2.5 The asset row — LAYOUT

Name and balance get a hard boundary: the name elides, the **integer never
shrinks**, and when space runs out the ellipsis eats the *fraction* from the right
(`.250 000…`), never a digit before the point. Balance at `Fonts.balance` (1.5).

### 2.6 Contacts — LAYOUT

- Contact address at `Fonts.small`, capped per 1.5.
- The three draft fields get the focus pair (1.2); they have no focus state today,
  unlike the search field beside them.
- Drag: the marker and the lifted row's frame in `drag_marker` (1.3). The rows
  already animate out of the way on `Motion.base`; keep that.
- The hint stays in the interface face even in the monospaced address field, as the
  comment on `Field`'s placeholder in `widgets.slint` already requires.

---

## Baseline

Phase 1 changes every screen, so regenerate all of `ui/Wallet/*.png` in that
commit: `page-wallet`, `page-contacts`, `page-swap`, `page-explorer`,
`page-settings`, `overlay-auth`, `overlay-lock`, `overlay-picker`, `overlay-risk`,
`popup-book`, `popup-menus`, `popup-wallet`, `sheet-trace`, `spinner-*`,
`state-focus-field`, `state-hover-button`, `state-hover-nav`, and the `-min`
variants.

Phase 2 commits touch `page-wallet` and `page-contacts` (plus `popup-menus` for
2.4). Each should be a small, readable diff — that is the point of splitting them.

The six contact tones and five asset tones stay in `src/bridge/render.rs`, and the
test that keeps identity colour out of the token layer must keep passing. The
reference reads those values from `render.rs` and hashes the address the same way,
so a reordered list keeps its colours.

---

## Out of scope

Not rebuilt, not reviewed, not covered here. Do not "finish" these from the
reference:

- the wallet switcher menu, and the Activity token and counterparty filters
  (drawn, inert in the reference);
- Swap, Explorer, Settings — placeholders;
- the lock screen, the wallet picker, the auth dialog, the risk dialog;
- autolock, screen lock, seed handling, endpoint management;
- everything in `cc-wallet-vault`, `-storage`, `-tycho`, `-chain`.

## Questions to settle first

- **1.2** — should the keyboard focus ring on buttons and tabs also move to silver,
  or stay accent? The reference only settled fields and menus.
- **1.7** — ligatures in your instanced Chivo Mono: measure before deciding.
- **2.4** — does the wallet chain snake cells for comments today? The 631-byte
  budget assumes four referenced cells.
- The Assets list is capped at `asset_list_max_h` 236px and the Send card body ends
  ~24px above its own bottom. If the window ever needs to open shorter than 780px,
  that is the slack to spend — the mid row is the largest fixed block on the page.
