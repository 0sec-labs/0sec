/**
 * ops-harvest — in-process tree-sitter ops-struct designated-initializer
 * extraction. Fixture-driven: one resolved assignment (happy path), malformed
 * C, and empty input.
 */

import { describe, expect, it } from "vitest";
import { harvestOps } from "./ops-harvest.js";

// ── Fixtures ───────────────────────────────────────────────────────────────────

const UNIX_STREAM_OPS = `
const struct proto_ops unix_stream_ops = {
    .family = PF_UNIX,
    .owner = THIS_MODULE,
    .release = unix_release,
    .bind = unix_bind,
    .connect = unix_stream_connect,
    .socketpair = unix_socketpair,
    .accept = unix_accept,
    .getname = unix_getname,
    .poll = unix_poll,
    .listen = unix_listen,
    .shutdown = unix_shutdown,
    .setsockopt = sock_no_setsockopt,
    .getsockopt = sock_no_getsockopt,
    .sendmsg = unix_stream_sendmsg,
    .recvmsg = unix_stream_recvmsg,
    .mmap = sock_no_mmap,
};
`;

const STATIC_STRUCT = `
static struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .open = my_open,
    .release = my_release,
};
`;

const UNION_EXAMPLE = `
union my_union u = {
    .ptr = get_ptr,
    .val = 42,
};
`;

// ── Happy path: resolved assignments ──────────────────────────────────────────

describe("harvestOps", () => {
  it("extracts function-pointer designated initializers from a const struct", () => {
    const edges = harvestOps(UNIX_STREAM_OPS, "net/unix/af_unix.c");
    // All plain-identifier function assignments should be found.
    const fnNames = edges.map((e) => e.fnName).sort();
    expect(fnNames).toContain("unix_release");
    expect(fnNames).toContain("unix_stream_recvmsg");
    expect(fnNames).toContain("sock_no_setsockopt");
    // Data fields (string, sizeof, THIS_MODULE, PF_UNIX) must NOT appear.
    expect(fnNames).not.toContain("PF_UNIX");
    expect(fnNames).not.toContain("THIS_MODULE");

    // Every edge carries the struct name, file, and a valid line.
    for (const e of edges) {
      expect(e.structName).toBe("proto_ops");
      expect(e.file).toBe("net/unix/af_unix.c");
      expect(e.line).toBeGreaterThanOrEqual(1);
      expect(e.field.length).toBeGreaterThan(0);
    }

    // Spot-check one specific assignment.
    const recvmsg = edges.find((e) => e.field === "recvmsg");
    expect(recvmsg).toBeDefined();
    expect(recvmsg!.fnName).toBe("unix_stream_recvmsg");
    expect(recvmsg!.line).toBeGreaterThan(1); // not the struct open-brace line
  });

  it("handles a static struct with function assignments", () => {
    const edges = harvestOps(STATIC_STRUCT, "drivers/char/mydev.c");
    expect(edges.length).toBe(2);
    expect(edges.map((e) => e.field).sort()).toEqual(["open", "release"]);
    expect(edges.map((e) => e.fnName).sort()).toEqual(["my_open", "my_release"]);
    expect(edges[0].structName).toBe("file_operations");
  });

  it("harvests a dispatch table wrapped in a preprocessor branch", () => {
    const edges = harvestOps(
      `#ifdef CONFIG_TEST\n${STATIC_STRUCT}\n#endif`,
      "drivers/char/mydev.c",
    );
    expect(edges.map((edge) => edge.fnName).sort()).toEqual(["my_open", "my_release"]);
  });

  it("handles union initializers the same as structs", () => {
    const edges = harvestOps(UNION_EXAMPLE, "test.c");
    // Only the function-pointer field, not the literal.
    expect(edges.length).toBe(1);
    expect(edges[0].field).toBe("ptr");
    expect(edges[0].fnName).toBe("get_ptr");
    expect(edges[0].structName).toBe("my_union");
  });

  // ── Malformed / empty input ─────────────────────────────────────────────────

  it("returns empty array for empty source", () => {
    expect(harvestOps("", "empty.c")).toEqual([]);
  });

  it("returns empty array for source with no struct initializers", () => {
    const src = `
int add(int a, int b) {
    return a + b;
}
void main(void) {
    int x = 42;
}
`;
    expect(harvestOps(src, "no_structs.c")).toEqual([]);
  });

  it("returns empty array for a struct with only data fields", () => {
    const src = `
struct config cfg = {
    .name = "default",
    .timeout = 5000,
    .enabled = 1,
};
`;
    const edges = harvestOps(src, "config.c");
    // String literals and numbers are NOT collected.
    expect(edges).toEqual([]);
  });

  it("returns empty array for syntactically invalid C", () => {
    const src = `this is not valid C @@@ { broken syntax ###`;
    // parseC returns null → harvestOps returns [].
    expect(harvestOps(src, "broken.c")).toEqual([]);
  });
});

