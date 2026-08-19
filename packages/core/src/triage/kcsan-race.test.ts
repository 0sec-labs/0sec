/**
 * Offline unit tests for the KCSAN data-race report parser (issue #1112).
 * Pure string parsing — no VM, no LLM.
 */

import { describe, it, expect } from "vitest";
import { parseKcsanReport } from "./kcsan-race.js";

// A real-shape KCSAN report (ext4 inode counter race). Two access blocks, a
// `value changed` line, header `FUNC1 / FUNC2`.
const EXT4_REPORT = `==================================================================
BUG: KCSAN: data-race in ext4_free_inode / ext4_mark_iloc_dirty

write to 0xffff8881033c1a40 of 8 bytes by task 6398 on cpu 0:
 ext4_mark_iloc_dirty+0x2d4/0x680 fs/ext4/inode.c:5876
 __ext4_mark_inode_dirty+0x1a0/0x4c0 fs/ext4/inode.c:6132
 ext4_dirty_inode+0x80/0xc0 fs/ext4/inode.c:6210
 __mark_inode_dirty+0x8c/0x7a0 fs/fs-writeback.c:2493

read to 0xffff8881033c1a40 of 8 bytes by task 6403 on cpu 1:
 ext4_free_inode+0x33c/0x8d0 fs/ext4/ialloc.c:320
 ext4_evict_inode+0x5a0/0xd40 fs/ext4/inode.c:212
 evict+0x1d0/0x4a0 fs/inode.c:704

value changed: 0x0000000000000001 -> 0x0000000000000000

Reported by Kernel Concurrency Sanitizer on:
CPU: 1 PID: 6403 Comm: syz-executor.3 Not tainted 6.12.93 #1
==================================================================`;

describe("parseKcsanReport", () => {
  it("parses both racing sites, files/lines, access dirs, sizes, and the object", () => {
    const race = parseKcsanReport(EXT4_REPORT);
    expect(race).toBeDefined();
    const r = race!;

    // Side A = the header's first function (write side here).
    expect(r.a.fn).toBe("ext4_mark_iloc_dirty");
    expect(r.a.file).toBe("fs/ext4/inode.c");
    expect(r.a.line).toBe(5876);
    expect(r.a.access).toBe("write");
    expect(r.a.size).toBe(8);
    expect(r.a.address).toBe("0xffff8881033c1a40");
    expect(r.a.stack.length).toBe(4);
    expect(r.a.stack[0]).toContain("ext4_mark_iloc_dirty");

    // Side B = the header's second function (read side).
    expect(r.b.fn).toBe("ext4_free_inode");
    expect(r.b.file).toBe("fs/ext4/ialloc.c");
    expect(r.b.line).toBe(320);
    expect(r.b.access).toBe("read");

    expect(r.object).toBe("0xffff8881033c1a40");
    expect(r.valueChanged).toEqual({ from: "0x0000000000000001", to: "0x0000000000000000" });
    expect(r.raw).toContain("KCSAN: data-race");
  });

  it("handles a top frame with no file:line", () => {
    const report = `BUG: KCSAN: data-race in tcp_recvmsg / tcp_data_queue

read to 0xffff888100112233 of 4 bytes by task 900 on cpu 2:
 tcp_recvmsg+0x100/0x300
 inet_recvmsg+0x50/0x120 net/ipv4/af_inet.c:850

write to 0xffff888100112233 of 4 bytes by task 901 on cpu 3:
 tcp_data_queue+0x2a0/0x1400 net/ipv4/tcp_input.c:5100
`;
    const r = parseKcsanReport(report)!;
    expect(r.a.fn).toBe("tcp_recvmsg");
    expect(r.a.access).toBe("read");
    expect(r.a.file).toBeUndefined(); // top frame had no file:line
    expect(r.b.fn).toBe("tcp_data_queue");
    expect(r.b.line).toBe(5100);
  });

  it("handles a same-function race (`data-race in FUNC`)", () => {
    const report = `BUG: KCSAN: data-race in cfg80211_registered_device_stop

write to 0xffff88811 of 8 bytes by task 5 on cpu 0:
 cfg80211_registered_device_stop+0x40/0x80 net/wireless/core.c:1500

read to 0xffff88811 of 8 bytes by task 6 on cpu 1:
 cfg80211_registered_device_stop+0x40/0x80 net/wireless/core.c:1500
`;
    const r = parseKcsanReport(report)!;
    expect(r.a.fn).toBe("cfg80211_registered_device_stop");
    expect(r.b.fn).toBe("cfg80211_registered_device_stop");
    expect(r.a.access).toBe("write");
    expect(r.b.access).toBe("read");
  });

  it("returns undefined for non-KCSAN text", () => {
    expect(parseKcsanReport("BUG: KASAN: slab-use-after-free in foo")).toBeUndefined();
    expect(parseKcsanReport("just some dmesg noise")).toBeUndefined();
  });
});
