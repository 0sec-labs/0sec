# Recency flywheel — daily bench scheduler

> Status: 2026-07-17. Living document.

The **recency flywheel** is a continuous kernel-LPE discovery loop that hunts the
freshness window: it pulls fresh `linux-next` commits daily, keeps only the ones
touching unprivileged-reachable subsystems, classifies each diff SEMANTIC (a real
lifetime/refcount/lock change) vs COSMETIC (a reshuffle around unchanged lifetime
logic), runs the refined invariant engine on the survivors, adversarially verifies,
and writes a ranked report.

The thesis: the frozen kernelCTF-LTS snapshot is TAPPED because it is *hardened*
(syzkaller + the top groups have swept it). Bugs live in the recency window — in
the days after a commit lands and before that same machinery hardens it. This is
the only structure that beats the audit-density wall.

The engine + CLI live in `@pwnkit/core` (`stages/recency-hunt.ts`) and
`pwnkit recency-hunt`. This directory is just the **daily driver** on bench.

## Files

| File | Role |
|---|---|
| `run-recency-flywheel.sh` | The driver: `git fetch` linux-next → `pwnkit recency-hunt --report-dir …`. Idle-priority, additive, non-disruptive. |
| `recency-flywheel.service` | `oneshot` systemd unit that runs the driver with `HOME=/root` (for `/root/.codex/auth.json`). |
| `recency-flywheel.timer` | Daily `OnCalendar=06:30` trigger, `Persistent=true` (catches missed runs). |

## Install on bench (one-time)

The driver expects a **built** engine checkout at `/root/pwnkit-recency-flywheel`
(a git worktree of the `tools/pwnkit` submodule on the `feat/recency-flywheel`
branch, `pnpm build`-ed). Then:

```sh
# copy the driver + units into place
install -Dm755 scripts/recency-flywheel/run-recency-flywheel.sh /root/recency-flywheel/run-recency-flywheel.sh
install -Dm644 scripts/recency-flywheel/recency-flywheel.service /etc/systemd/system/recency-flywheel.service
install -Dm644 scripts/recency-flywheel/recency-flywheel.timer   /etc/systemd/system/recency-flywheel.timer

systemctl daemon-reload
systemctl enable --now recency-flywheel.timer     # start the daily schedule
```

## Operate

```sh
# run it right now (out of schedule), stream the log:
systemctl start recency-flywheel.service
journalctl -u recency-flywheel.service -f

# when does it next fire?
systemctl list-timers recency-flywheel.timer

# stop the schedule (does not delete reports):
systemctl disable --now recency-flywheel.timer

# fully remove:
systemctl disable --now recency-flywheel.timer
rm /etc/systemd/system/recency-flywheel.{service,timer}
systemctl daemon-reload
```

Reports land in `/root/recency-flywheel/reports/YYYY-MM-DD.{json,md}`. A one-line
funnel summary is logged to journald each run:

```
recency-flywheel 2026-07-17: 1573 commits → 214 files → 22 in-scope → 3 semantic → 4 candidates → 0 survivor(s). reports: /root/recency-flywheel/reports/2026-07-17.{json,md}
```

## Non-disruption contract

The driver **only** fetches `/root/linux-next` (the snapshot repo) and runs one
CLI process at `Nice=15 / IOSchedulingClass=idle / CPUWeight=20`. It does **not**
touch:

- the KCSAN/AIO syzkaller fuzzer (`/root/kcsan-experiment`)
- the kmsan QEMUs / built kernels (`/root/kernel-objects`, `/root/next-recency`)
- `/root/cp*`

## Wiring the tails (operator-gated)

A high-confidence **survivor** in the report is shaped as a `bugSpec` +
trigger-seed ready for the next step:

- **Weaponize**: `pwnkit exploit --autoclimb --source <tree> --target <file>`.
- **Disclose**: hand the survivor to the disclosure stager.

Nothing is auto-sent. Disclosure is operator-gated (embargo discipline). A
survivor is a LEAD — verify real reachability + novelty (not already patched later
in the same window) before acting.
