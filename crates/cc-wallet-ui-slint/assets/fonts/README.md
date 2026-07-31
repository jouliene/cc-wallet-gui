# Bundled fonts

**Manrope** — the interface face (Regular, Medium, SemiBold, Bold, ExtraBold).

**Chivo Mono** — the face for hashes, addresses, BOCs and endpoint URLs, where
characters must line up in columns. Copyright 2019 The Chivo Project Authors
(https://github.com/Omnibus-Type/Chivo), SIL Open Font License 1.1 — see
`ChivoMono-OFL.txt`. No reserved font name is declared.

Chosen for two reasons: its zero is a plain oval (no slash, no dot), and at
0.60 em per character a 64-hex hash still fits the Explorer's value column.

The bundled files are modified: the upstream variable font was instanced at
weight 400 and 600, then subset to Latin-1 plus the punctuation the wallet
shows (…, ·, –, —, quotes, −). That is what takes each file from ~180 KB to
16 KB, which matters for a single-file portable build.

Every bundled face — Manrope too — then gained one glyph the subset had
dropped: U+2004 THREE-PER-EM SPACE, blank, advance one third of the em. It is
the separator inside a fraction (`0.002 451 000`), where an apostrophe reads
as noise next to the apostrophes grouping the integer. A face re-subset from
upstream without it will draw a missing-glyph box in every amount.
