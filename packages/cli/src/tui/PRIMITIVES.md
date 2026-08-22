# TUI layout primitives

`primitives.tsx` exists to delete one bug, repeated. Roughly sixty rendering
defects were fixed across `run.tsx` and `chat-screen.tsx` in a single session,
and they were nearly all the same mistake wearing different clothes.

This document explains the mistake, shows the primitives that make it
unexpressible, and gives a checklist for migrating a row or a box.

---

## 1. The failure mode

### Horizontal: Yoga shrinks, it does not clip

OpenTUI lays rows out with Yoga. Put two auto-width `<text>` siblings in a row
and give them, between them, more cells than the row has:

```tsx
<box flexDirection="row">
  <text fg={MUTED}>EVIDENCE LEDGER</text>
  <text fg={MUTED}> · {empty ? "awaiting an objective" : `${entries.length} records`}</text>
</box>
```

Yoga does not truncate either child. It *shrinks their boxes* and both children
keep painting their full strings into boxes that are now too small. The cells
overlap and the terminal shows the interleaving of the two strings. That is
exactly how these were produced:

| Intended | Rendered |
| --- | --- |
| `Show available slash commands` | `Showpavailableenslash commands` |
| `0sec / chat` above `target: none` | `target:cnone` |
| `runs` then `12` | `runs12` |
| `Describe an objective. 0sec enforces…` | `Describe-anrobjective.y0seceenforces...` |

Note the shape of the corruption: it is not truncation, it is two strings
alternating character by character. Once you have seen it, every one of these
sixty defects is recognisable on sight.

### Vertical: the same thing, one axis over

A bordered box squeezed below its content height still paints its own border at
its new bottom edge, straight through its last content rows. The slash-command
menu produced:

```
-/clear--------/new-
```

That is the box's bottom border and two command rows occupying the same cells.

### The trimming trap

`fitTuiText` routes through `sanitizeTuiText`, which collapses whitespace **and
trims**. So:

```ts
fitTuiText("runs ", 8) === "runs"   // the trailing space is gone
```

Any design that carries its separator inside the string — `"runs "`, `` `${label}: ` ``,
`" · "` prefixes — loses that separator the moment the string is budgeted, and
the label fuses to its value *even when the row had cells to spare*. `runs12`
is this variant, not the overlap variant.

### Why the convention did not hold

The cure was, until now, a five-part convention every author had to remember:

1. give every sibling an explicit `width={n}`,
2. add `flexShrink={0}` so a parent cannot squeeze it,
3. budget the string with `fitTuiText(value, n)` against that *same* `n`,
4. use a real `gap` rather than a padded literal,
5. hand-verify that widths plus gaps never exceed the container.

Five invariants, enforced by nothing, at every one of several hundred call
sites. It was broken dozens of times. `chat-layout.ts` fixed step 5 for four
specific rows by moving their arithmetic into a tested pure function; these
primitives generalise that idea and fix steps 1–4 as well.

---

## 2. What the primitives do

The design goal is not "make the right thing easy". It is **make the wrong
thing hard to type**.

### `Cells` — a text leaf that cannot overflow

```tsx
<Cells width={12} fg={MUTED} align="right">{count}</Cells>
```

- `width` is **required**. There is no default and no `"auto"` — a leaf sized
  by its own content is the thing that overlaps its neighbours.
- It always sets `flexShrink={0}` and `flexGrow={0}`. A parent cannot compress it.
- It always routes its text through `fitTuiText` against **that exact width**.
  There is no code path through this component that renders unbudgeted text.
- It then *pads back up* to the width, so the rendered string is exactly
  `width` cells — not merely "at most". `fitCells(anything, n).length === n`
  is a unit test.
- `children` is typed `string | number | null`, **not** `ReactNode`. You cannot
  nest an unbudgeted `<text>` inside a `Cells`.
- `wrapMode="none"`, so a long token cannot spill onto a second row and push a
  border down — the horizontal fix does not create a vertical bug.

### `Columns` — a row that does its own arithmetic

The caller states *intent* per column; the component computes the allocation.

```tsx
<Columns
  available={contentWidth}
  gap={1}
  columns={[
    { fixed: 4, text: "0sec", fg: PRIMARY, priority: 2 },
    { flex: 1, text: headerEngagement, fg: MUTED, fit: "middle", priority: 0 },
    { content: modeLabel(mode), max: 10, fg: modeColor, priority: 1 },
  ]}
/>
```

Three column intents, and the `?: never` members on each make
`{ fixed: 4, flex: 1 }` a **type error** rather than a silent precedence question:

| Spec | Meaning |
| --- | --- |
| `{ fixed: n }` | exactly `n` cells, or fewer if the row cannot pay for it |
| `{ flex: w, min?, max? }` | a `w`-weighted share of the surplus |
| `{ content: s, min?, max? }` | sized to its own text, clamped |

`priority` (default 0) is the survival order when the row cannot fit
everything: columns are dropped lowest-priority-first, then right-to-left, and
grown back in the reverse order. `min` means *"below this I am noise — drop me
whole rather than render me at one cell"*, because a 1-cell column shows a lone
`.` and still costs a gap.

`{ fixed: 0 }`, `{ content: "" }` and a zero-weight flex are *inert*: they cost
neither a cell nor a gap. That is what the `runsLabelWidth > 0 ? <text/> : null`
guards at the call sites were doing by hand, so pass the column unconditionally
and delete the guard.

Two structural properties matter more than the spec vocabulary:

- **`Columns` has no `children` prop.** You cannot smuggle an unbudgeted
  sibling into the row; there is nowhere to put one.
- The row declares `width={allocation.used}` and `flexShrink={0}`, where `used`
  is provably `<= available`. Neither the row nor any column can be compressed.

The escape hatch is `render: (width) => ReactNode`, which is handed the cells
the column actually got. It is deliberately parameterised by the allocation, so
even the escape hatch tells you your budget.

### `LabelValue` — separation that lives in the layout

```tsx
<LabelValue available={metricContentWidth} label="runs" value={snapshot.scans.length} labelFg={TEXT} valueFg={PRIMARY} />
```

There is no string concatenation anywhere on this path. The separator is a real
Yoga `gap` (minimum 1), so there is no trailing space for `sanitizeTuiText` to
trim, so `runs12` cannot happen. The value outranks the label: when only one of
the two fits, the number survives and the caption is dropped, because `12` with
no caption is still information and `runs` with no number is not.

### `fitRows` + `Rows` — the vertical equivalent

```tsx
const fit = fitRows({
  available: ledgerRows,
  chrome: 4,          // two borders, the COMMANDS header, the hint footer
  rowsPerItem: 2,
  items: commands.length,
  maxShare: 0.45,     // never take more than 45% of the column
});

<Rows fit={fit} border borderColor={BORDER} backgroundColor={PANEL}>
  {commands.slice(0, fit.visible).map(renderCommand)}
</Rows>
```

`Rows` renders with an explicit `height={fit.boxHeight}` and `flexShrink={0}`,
so the box is never resized behind its content's back — and `fit.visible`
already limited the content to what the height holds. Both halves of
`-/clear--------/new-` are removed.

When nothing fits, `fit.boxHeight` is 0 and `Rows` renders **nothing**. That is
deliberate: a box one row shorter than its content is corruption that looks
like a crash, while an absent box is merely missing information.

`maxShare` exists because fitting is necessary but not sufficient. A box sized
purely by "what is left over" grows until the region *above* it is squeezed to
nothing — and that region then overlaps its own content instead. This is the
`Describe-anrobjective.y0seceenforces...` defect.

### The pure layer

`allocateColumns`, `allocateLabelValue`, `fitRows`, `fitCells`, `toCells` and
`textCells` are pure and exported separately from the components, following the
precedent set by `chat-layout.ts`. They are unit-tested with no renderer at all.

The sweep in `primitives.test.ts` asserts, for available widths **0..200**, four
gap sizes and seventeen column-list shapes (all-fixed, all-flex, weighted flex,
flex with min/max, content-sized with and without max, prioritised mixes, more
columns than cells, a single oversized column, and deliberate garbage):

```
sum(widths) + gap * (renderedColumns - 1) <= available
```

plus: every width is a non-negative integer, `used` agrees with that sum
exactly, and nothing throws at `available` of 0, 1, 2, −100, NaN or Infinity.
`fitRows` gets the same treatment across heights 0..100.

### What the compiler rejects

These are all type errors, not review comments:

```tsx
<Columns available={10} columns={[{ fixed: 4, flex: 1 }]} />  // two sizing intents
<Cells fg={MUTED}>hello</Cells>                               // no width
<Cells width={4}><text>hi</text></Cells>                      // unbudgeted child
<Columns available={10} columns={[]}><text>hi</text></Columns> // stray sibling
```

---

## 3. Before / after: the metric card in `run.tsx`

This is the literal source of `runs12`. From `MissionControlScreen`
(`run.tsx`, the three metric cards):

**Before**

```tsx
<box flexDirection="row" width="100%" minWidth={0} gap={metricLabelGap}>
  {runsLabelWidth > 0
    ? <text width={runsLabelWidth} flexShrink={0} fg={TEXT}>{fitTuiText("runs", runsLabelWidth)}</text>
    : null}
  <text fg={PRIMARY}>
    {fitTuiText(String(snapshot.scans.length), Math.max(1, metricContentWidth - runsLabelWidth - metricLabelGap))}
  </text>
</box>
```

Four separate things have to be right here, and each is the author's problem:

- `runsLabelWidth` is computed somewhere else and guarded with `> 0` by hand.
- The value's `<text>` has **no `width` and no `flexShrink`** — it is the
  auto-width sibling that overlaps when the card is narrow.
- `Math.max(1, metricContentWidth - runsLabelWidth - metricLabelGap)` is the
  overflow arithmetic, written inline, duplicated verbatim in the two sibling
  cards, and never checked against `metricContentWidth` by any test.
- Change `metricLabelGap` and all three copies must change with it.

**After**

```tsx
<LabelValue
  available={metricContentWidth}
  gap={metricLabelGap}
  label="runs"
  value={snapshot.scans.length}
  labelFg={TEXT}
  valueFg={PRIMARY}
/>
```

The `> 0` guard, the subtraction, the `Math.max(1, …)` floor and the missing
`flexShrink` all disappear into `allocateLabelValue`, which is swept across
widths 0..200 by the test suite.

### A second one, for the shape of a general row

The ledger title in `chat-screen.tsx` — two auto-width `<text>` siblings, no
widths, no `fitTuiText`, and a `" · "` literal doing the separating:

**Before**

```tsx
<box flexDirection="row" width="100%" minWidth={0} flexShrink={0}>
  <text fg={MUTED}>EVIDENCE LEDGER</text>
  <text fg={MUTED}> · {empty ? "awaiting an objective" : `${entries.length} records`}</text>
</box>
```

**After**

```tsx
<Columns
  available={transcriptWidth}
  gap={1}
  columns={[
    { content: "EVIDENCE LEDGER", fg: MUTED, priority: 1 },
    { fixed: 1, text: "·", fg: MUTED, priority: 1 },
    { flex: 1, text: empty ? "awaiting an objective" : `${entries.length} records`, fg: MUTED, priority: 0 },
  ]}
/>
```

The separator is now a column plus two gaps instead of a literal that
`sanitizeTuiText` would trim, the title is sized to itself, the subtitle takes
what is left, and the subtitle is what gives way first on a narrow terminal.

---

## 4. Migration checklist

For each `flexDirection="row"` you touch:

- [ ] Does the row have two or more `<text>`/`<box>` siblings? If yes it is a
      `Columns` candidate — every such row is a latent overlap.
- [ ] Replace each sibling with a column spec stating **intent**, not cells:
      `{ fixed }` for a stamp or a marker, `{ content }` for a caption sized to
      itself, `{ flex }` for the one that should absorb the slack.
- [ ] Delete every inline `Math.max(1, width - other - gap)`. That arithmetic is
      what `allocateColumns` is for, and yours is not swept by a test.
- [ ] Delete every `width={…} flexShrink={0} minWidth={0}` triple. `Cells` and
      `Columns` set those unconditionally.
- [ ] Delete every `fitTuiText(value, n)` at the call site. Passing `text` to a
      column budgets it against the width it was actually allocated, which is
      not always the `n` you had in hand.
- [ ] Replace padded literals — `"runs "`, `` `${label}: ` ``, `" · "` — with a
      `gap` or with their own column. If a space matters for layout,
      `sanitizeTuiText` will eat it.
- [ ] Set `priority` on the columns that must survive a narrow terminal, and
      `min` on the ones that are noise below some width. The default (all 0)
      drops right-to-left, which is right more often than not.
- [ ] Use `fit: "middle"` for paths, URLs and anything whose tail carries
      meaning; the default truncates the end.

For each bordered `flexDirection="column"` box:

- [ ] Compute a `fitRows({ available, chrome, rowsPerItem, items })` first.
      `chrome` is every row the box spends on itself — count the borders.
- [ ] Slice the item list to `fit.visible`. Rendering more items than fit is
      what pushes the border through the content.
- [ ] Render with `<Rows fit={fit}>`, never with a hardcoded height constant.
- [ ] Add `maxShare` when the box shares a column with a region that must keep
      real rows (the transcript, mainly).
- [ ] Handle `fit.boxHeight === 0` — `Rows` renders nothing, so if the box is
      load-bearing, say so elsewhere (`fit.overflow` gives you the count).

### Known limitation

`fitTuiText`, `fitCells` and the content-sizing math all measure `String.length`,
which is not display width for CJK, emoji or combining marks. That assumption is
inherited from `text.ts` and is unchanged here; a wide-character string will
under-claim cells and can still overlap. Fixing it means a grapheme-aware width
function in `text.ts`, at which point these primitives pick it up for free —
every measurement in this module goes through `textCells`.

---

## 5. Adoption

`primitives.tsx` is additive and opt-in. Nothing imports it yet. Adopt it row by
row, starting with the rows that have already been fixed once — those are the
ones the convention demonstrably fails to protect.
