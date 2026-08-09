# Change order — Storage

Scope: the **Storage** page only, one file — `ui/pages/storage_page.slint`. No
widget, token or theme value changes. Nothing is redesigned: the page keeps its
two cards, its columns, its copy and its components. What changed is where
things sit.

Its companion is the handoff in `design_handoff_storage_tuning/`, whose HTML
mock draws the four grid lines this order aligns to. Where the two disagree,
the formulas here are right — the mock rounds them to whole pixels.

---

## The grid

Every column is a formula over tokens, and the heading, the rows and the add
form all read the same three properties, so a column and its label cannot start
in different places.

```slint
col_free_w  = width - 2*s_16 - col_number_w - col_actions_w - 3*col_gap
col_title_w = col_free_w / 4
col_data_w  = col_free_w - col_title_w
form_title_w = col_number_w + col_gap + col_title_w
```

The form's first column swallows the ordinal gutter: a record being written has
no number yet, and its field still ends where the NAME column ends.

## The items

1. **Page rhythm.** `Space.stack_gap` between the cards and no top padding —
   Storage was the only page that shifted 4px down when you switched to it.
2. **One right edge.** The list was inset 8 on the right while the header and
   the form were inset 16, so refresh, the delete buttons and Clear stood on
   three different lines. All 16 now, as Activity already does.
3. **Row height agrees with its own padding** — `control_dense + 2*s_12`, not
   `s_10`, which was 4px short of what the row actually pads.
4. **One line per row.** The two text columns are different sizes (body 14 and
   mono 12.5) and were top-aligned, so the number, the name, the record and the
   24px buttons sat at four heights. Every text column now gets the buttons'
   line box. A multi-line record is unaffected — its height already exceeds it.
5. **Address / Balance on the card inset** — `card_pad_h` / `card_pad_v`
   outside, symmetric 12 inside; its border used to stick out to the left of
   everything else.
6. **The footer rule only when there is something to say.** The reserve stays,
   so nothing jumps; the hairline arrives with the message.
7. **Add a record reads like Send.** Left column is the short field with its
   buttons under it, right column is the tall field whose height comes from
   that stack — `field_h + s_8 + form_btn_h`, exactly how COMMENT is sized
   against AMOUNT + Send. Both columns end on the same line. The pinned 96px
   row height, the hand-rolled 18px label spacer and the 132px action column
   are gone; the form error lives in a `label_row_h` reserve on the fields' own
   left edge.
8. **Small change.** The "More below" chevron moves to `Sizes.icon_sm`, and the
   header refresh becomes the shared `RefreshButton`, so it acknowledges with a
   tick like Explorer's.

## Acceptance, window 1180 → card 1160

| Thing | Expected |
| --- | --- |
| `col_free_w` | 1010 → title 252.5, data 757.5 |
| Columns start at | `#` 16 · NAME 58 · RECORD 322.5 · actions 1092 |
| Right edge, everything | 1144 — refresh, the trash column, Clear |
| NAME field | 16 → 310.5, ending where the NAME column ends |
| RECORD field | 322.5 → 1144, under the RECORD column |
| Both form columns | 114 tall |

## Not done

`TableHeader` / `TableColumn` would give the heading the same 32px box Wallet
and Explorer use, but neither of those draws a rule under it and Storage does.
Adopting the widget would have removed a separator this order was not asked to
touch. The heading stays hand-built and reads the same column properties.
