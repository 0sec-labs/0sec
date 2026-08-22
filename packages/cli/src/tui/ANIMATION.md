# Console busy-state animation

`animation.ts` decides what the console draws while the operator is waiting.
It is a pure lookup: `frameAt(kind, elapsedMs, opts)` returns a frame, and it
does not read a clock, hold state, or paint. The React layer owns the ticker.

```ts
import { frameAt, frameIntervalMs, GLYPH_CELLS } from "./animation.js";

const frame = frameAt("thinking", Date.now() - startedAt);
// { glyph: "⠶⠶⠶", label: "thinking", elapsedLabel: "12s" }
```

Why the split: a spinner that calls `Date.now()` inside itself can only be
tested by sleeping, so in practice it never gets tested, and the bugs it hides
are exactly the ones that hurt — a frame one cell too wide, a glyph the
terminal cannot render, a counter that prints `-1s`. Here every one of those
is an assertion in `animation.test.ts` (74 of them), and none of them sleep.

## The five states

| kind | interval | frames | period | reads as |
| --- | --- | --- | --- | --- |
| `connecting` | 150 ms | 4 | 600 ms | a ping going out |
| `thinking` | 140 ms | 8 | 1120 ms | a balance beam rocking |
| `streaming` | 100 ms | 6 | 600 ms | flow, left to right |
| `tool` | 120 ms | 6 | 720 ms | something turning |
| `awaiting-operator` | 700 ms | 2 | 1400 ms | an idle cursor breathing |

### `connecting` — a ping, not a spinner

```
unicode   ⠀⠶⠀   ⠀⠒⠀   ⠐⠀⠂   ⠂⠀⠐
ascii     .O.    .o.    (.)    <.>
```

A core flashes, a ripple travels outward, and it starts over. Repeated
outbound attempts is literally what bringing the runtime up is, and the
restart is honest about that — nothing is accumulating yet. It does not
rotate and it does not sweep, so it can never be misread as work in progress.
150 ms gives roughly one ping every 0.6 s, about the rhythm of a dial tone.

### `thinking` — the long wait

```
unicode   ⠠⠴⠾   ⠤⠴⠶   ⠶⠶⠶   ⠶⠦⠤   ⠷⠦⠄   ⠶⠦⠤   ⠶⠶⠶   ⠤⠴⠶
ascii     _-"    _--    ---    --_    "-_    --_    ---    _--
```

Six braille sub-columns form a beam that tilts one way, then the other, with
the centre steady — a balance being weighed. This is the state the operator
stares at longest and trusts least, so two properties matter more than
prettiness:

- **It goes nowhere.** No direction of travel means no implied progress
  toward a finish line, which is the honest thing to show when nothing in the
  process knows how long the turn will take. A left-to-right bar here would
  be a progress bar in everything but name.
- **It is the slowest busy cycle.** 8 frames at 140 ms is 1.12 s per rock,
  about one calm breath. Fast motion during a long wait reads as strain.

### `streaming` — flow

```
unicode   ⠤⠀⠀   ⠠⠄⠀   ⠀⠤⠀   ⠀⠠⠄   ⠀⠀⠤   ⠄⠀⠠
ascii     o--    -o-    --o    O--    -O-    --O
```

Two lit dots on the **bottom row only**, marching left to right through six
sub-columns and wrapping. Low, fast and directional: output pouring in, as
opposed to the beam's stationary rocking. It is the fastest animation in the
set and sits exactly on the 100 ms / 10 Hz cap — the model is producing, and
this is the one state where the transcript is repainting anyway.

The default label is `responding`, not `streaming`: the operator cares that
an answer is arriving, not about the transport.

### `tool` — rotation

```
unicode   ⠀⠙⠀   ⠀⠸⠀   ⠀⠴⠀   ⠀⠦⠀   ⠀⠇⠀   ⠀⠋⠀
ascii     '..    .'.    ..'    .._    ._.    _..
```

A three-dot arc orbiting a single centred braille cell — the classic spinner,
kept deliberately, because rotation is the one motion every operator already
reads as *a machine is turning*. It is distinct from `thinking` (which never
rotates) and from `streaming` (which never stays put). 720 ms per revolution
is fast enough to look driven, slow enough that the arc stays legible.

Pass the tool name as `label`; a tool run that outlives a few seconds should
show `elapsedLabel` next to it, because "which tool, and for how long" is the
whole question an operator has about a long tool call.

### `awaiting-operator` — not busy

```
unicode   ⠤⠤⠤   ⠒⠒⠒
ascii     ...    :::
```

The bottleneck here is the human, so this must not look like the machine is
straining — a spinner in front of an approval prompt is a lie about who is
holding things up. Two frames, no travel, no rotation: a low line lifting
slightly and settling, like an idle cursor breathing. At 700 ms per frame it
is ~0.7 Hz, an order of magnitude below every busy cycle, and that difference
in *tempo* is what carries the meaning even before the label is read.

Tests pin this: it shares no frame string with any busy kind in either glyph
set, its interval is at least 4× the slowest busy interval, and it is the only
kind with a two-frame cycle.

## The constant-width rule

**Every frame of every kind, in both glyph sets, is exactly `GLYPH_CELLS`
(= 3) terminal cells wide.** Not "roughly three".

This project has already been bitten by width bugs, and an animated glyph is
the worst place for one: it is the only thing on screen that changes ten times
a second. A frame that renders one cell wider than its neighbour makes the
label after it shuffle left and right, and inside a bordered row it pushes the
right border off the grid and corrupts the frame — a bug that appears only
while something is running and vanishes the moment you look for it.

Three things enforce it:

1. **An allowlist of code points.** Frames contain only printable ASCII
   (U+0020..U+007E, `East_Asian_Width=Na`) and Braille Patterns
   (U+2800..U+28FF, `East_Asian_Width=N`). Both ranges are one cell in every
   terminal. No emoji, no geometric shapes, no arrows, no box-drawing — those
   are `Ambiguous` and render two cells wide under a CJK locale. The test
   helper `cellWidth` throws rather than measure anything outside the
   allowlist, so a future frame using a "nice-looking" glyph fails loudly.
2. **The width is asserted per kind, per set**, both as
   `[...glyph].length === 3` and as the allowlist width, plus
   `new Set(widths).size === 1`.
3. **Equal frame counts across sets.** The unicode and ASCII cycles of a kind
   have the same number of frames, so `framePeriodMs` is the same whichever
   set is active and the caller's ticker never needs to know.

Braille does the heavy lifting because it is the only block that gives
sub-cell resolution — two columns × three rows inside one cell — while
staying narrow. It also supplies a blank that is *not* a space: U+2800
BRAILLE PATTERN BLANK. That is why `⠀⠤⠀` survives a `.trim()` or a
`\s+ → " "` collapse unchanged where `" ⠤ "` would not. The ASCII set avoids
spaces for the same reason and paints unlit cells with a visible rail
character instead.

**Render `glyph` verbatim.** Do not pass it through `fitTuiText` /
`sanitizeTuiText` — it is already sanitary, and fitting it can only shorten
it. Give it a fixed box: `<box width={GLYPH_CELLS} flexShrink={0}>`.

## Frame rates

Nothing repaints faster than 10 Hz, asserted in the tests. A spinner at 20 Hz
in a scrollback-heavy TUI is measurable CPU on a laptop on battery, and past
about 10 Hz the eye stops resolving frames anyway — it just reads as buzz.
The intervals also *rank* the states: `streaming` (100) is faster than `tool`
(120) is faster than `thinking` (140) is far, far faster than
`awaiting-operator` (700). The tempo alone tells the operator which state
they are in.

Use one ticker at `frameIntervalMs(kind)` and restart it when the kind
changes. Do not run a single 100 ms ticker for all states — that is a 7×
overspend while waiting on a human.

## Options

- `ascii: true` — the fallback set, for terminals that cannot be trusted with
  braille. Reasonable triggers: `TERM=dumb`, a non-UTF-8 `LANG`/`LC_ALL`, CI,
  or an explicit user setting. Decide once at startup and thread it through;
  do not sniff per frame.
- `motion: false` — pins the glyph to frame 0 forever. This is both an
  accessibility switch (vestibular sensitivity, reduced-motion preferences)
  and a cost switch. **`elapsedLabel` keeps advancing when motion is off** —
  elapsed is information, not animation, and with the glyph frozen it is the
  only thing left distinguishing "waiting" from "hung". Callers that honour
  reduced motion should stop the ticker's *repaint* of the glyph but keep a
  ~1 Hz repaint for the counter.
- `label` — override, typically the tool name. It is sanitized here (ANSI and
  control characters stripped, whitespace collapsed, capped at 48 chars)
  because tool names come from the model; an empty or whitespace-only
  override falls back to the kind's default.

## Elapsed

`elapsedLabel` is omitted below `ELAPSED_VISIBLE_AFTER_MS` (3 s) so short
turns do not flicker a counter, then formats compactly:

```
3s      9s      59s     1m00s   1m04s   59m59s   1h00m   99h59m
```

Clamped at 99h59m, so the label is never wider than six characters and the
line budget is knowable. `formatElapsed` is exported separately for callers
that want the same formatting elsewhere (a status bar, a turn summary).

There is deliberately **no percentage and no ETA**. Nothing in this process
knows how long a model turn or a tool call will take, and a fabricated bar
that sits at 90% is worse than an honest counter that says `2m13s`. A test
asserts no `%` / `eta` / `remaining` string can appear in a frame.

Degenerate elapsed values — negative, `NaN`, `±Infinity`, `MAX_SAFE_INTEGER`
— are clamped to a valid frame rather than throwing. A console that crashes
while drawing a spinner is worse than one drawing the wrong spinner, which is
also why an unrecognised `kind` falls back to `thinking` instead of throwing.

## Wiring recipe

Map the console's existing states onto kinds:

| console state | kind | label | show elapsed? |
| --- | --- | --- | --- |
| runtime starting, no session yet (`connecting runtime…`) | `connecting` | default | no — if this takes 3 s something is wrong, and the error path should own it |
| turn submitted, no tokens yet | `thinking` | default | **yes** — this is the wait that needs it most |
| assistant tokens arriving | `streaming` | default | optional; the growing text is already proof of life |
| a tool call is executing | `tool` | the tool name | **yes**, once past the threshold |
| scope authorization, co-pilot approval, or a secret prompt is open | `awaiting-operator` | default, or the thing being asked for | no — elapsed here reads as nagging |

Two places in `chat-screen.tsx` want this today:

- The transcript tail currently renders a static
  `◌ evidence collection in progress` while `busy`. That line should become
  `{glyph} {label} {elapsedLabel}`, with the glyph in a `GLYPH_CELLS`-wide
  box and the elapsed in `MUTED` so it stays subordinate to the label.
- The composer placeholder currently reads `0sec is working…` while busy and
  `connecting runtime…` before a session exists. Both are the same idea at
  different phases: `frameAt("connecting" | …)`, with elapsed appended only
  in the transcript, not in the composer — two counters ticking on one screen
  is noise.

Precedence when several are true at once: `awaiting-operator` wins over
everything (the machine is not the bottleneck), then `tool`, then `streaming`,
then `thinking`, then `connecting`.

Colour is the caller's business — `PRIMARY` for the busy kinds, `WARNING` for
`awaiting-operator` (it matches the approval panels), `MUTED` for the elapsed
counter. This module never emits colour, because a glyph carrying its own
escape codes cannot be width-checked.
