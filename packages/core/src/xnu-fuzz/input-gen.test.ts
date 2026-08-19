import { describe, expect, it } from "vitest";
import {
  makeRng,
  generateBaseInput,
  generateInputsForSelector,
  variableLengthSchedule,
  mutateStructured,
  havoc,
  lengthBoundaryValues,
  mutantBudget,
  type StructGrammar,
} from "./input-gen.js";
import { VARIABLE_SIZE, type SelectorModel } from "./types.js";

const fixedSel: SelectorModel = {
  sel: 17,
  scalarInCnt: 0,
  structInSize: 24,
  scalarOutCnt: 0,
  structOutSize: 0,
};
const varSel: SelectorModel = {
  sel: 9,
  scalarInCnt: 2,
  structInSize: VARIABLE_SIZE,
  scalarOutCnt: 0,
  structOutSize: 4,
};

describe("makeRng — deterministic", () => {
  it("same seed => same stream", () => {
    const a = makeRng(42);
    const b = makeRng(42);
    expect([a.u32(), a.u32(), a.byte()]).toEqual([b.u32(), b.u32(), b.byte()]);
  });
  it("different seeds diverge", () => {
    expect(makeRng(1).u32()).not.toBe(makeRng(2).u32());
  });
  it("u64 fills 64 bits", () => {
    const v = makeRng(7).u64();
    expect(v).toBeGreaterThanOrEqual(0n);
    expect(v).toBeLessThan(1n << 64n);
  });
});

describe("2.1 valid-sized base inputs (gate-passing)", () => {
  it("emits exactly scalarInCnt scalars and structInSize bytes for fixed-size", () => {
    const inp = generateBaseInput(fixedSel, makeRng(1));
    expect(inp.scalarInput).toHaveLength(0);
    expect(inp.structureInput.byteLength).toBe(24);
    expect(inp.structOutSize).toBe(0);
  });

  it("a selector with scalars gets that many u64s", () => {
    const sel: SelectorModel = { sel: 21, scalarInCnt: 4, structInSize: 0, scalarOutCnt: 0, structOutSize: 0 };
    expect(generateBaseInput(sel, makeRng(3)).scalarInput).toHaveLength(4);
  });

  it("variableLengthSchedule covers 0/1/word, header±1 and page/64K boundaries", () => {
    const sched = variableLengthSchedule(0x20);
    expect(sched).toContain(0);
    expect(sched).toContain(1);
    expect(sched).toContain(0x20);
    expect(sched).toContain(0x1f);
    expect(sched).toContain(0x21);
    expect(sched).toContain(0x1000);
    expect(sched).toContain(0x10000);
    // sorted + unique
    expect([...sched].sort((a, b) => a - b)).toEqual(sched);
    expect(new Set(sched).size).toBe(sched.length);
  });

  it("VAR selector sweeps one input per schedule length, each labelled", () => {
    const inputs = generateInputsForSelector(varSel, makeRng(5));
    const sched = variableLengthSchedule();
    expect(inputs).toHaveLength(sched.length);
    for (const inp of inputs) {
      expect(inp.scalarInput).toHaveLength(2); // scalarInCnt preserved
      expect(inp.lengthLabel).toMatch(/^len-\d+$/);
    }
    expect(inputs.map((i) => i.structureInput.byteLength).sort((a, b) => a - b)).toEqual(sched);
  });

  it("fixed selector honours fixedReplicas", () => {
    const inputs = generateInputsForSelector(fixedSel, makeRng(9), { fixedReplicas: 3 });
    expect(inputs).toHaveLength(3);
    expect(inputs.every((i) => i.structureInput.byteLength === 24)).toBe(true);
  });
});

describe("2.2 structure-aware mutation", () => {
  it("lengthBoundaryValues includes 0/1/signed-max/all-ones and total±1", () => {
    const v = lengthBoundaryValues(4, 0x40);
    expect(v).toContain(0n);
    expect(v).toContain(1n);
    expect(v).toContain(0x7fffffffn); // signed max u32
    expect(v).toContain(0xffffffffn); // all ones u32
    expect(v).toContain(0x3fn);
    expect(v).toContain(0x40n);
    expect(v).toContain(0x41n);
  });

  it("writes boundary values into a length field little-endian", () => {
    const base = new Uint8Array(0x20); // 32-byte struct
    const grammar: StructGrammar = {
      totalSize: 0x20,
      fields: [{ offset: 4, size: 4, kind: "length" }],
    };
    const mutants = mutateStructured(base, grammar, makeRng(1));
    // find the all-ones mutant
    const allOnes = mutants.find(
      (m) => m[4] === 0xff && m[5] === 0xff && m[6] === 0xff && m[7] === 0xff,
    );
    expect(allOnes).toBeDefined();
    // and a 0x20±1 mutant exists (len=0x21 => byte[4]=0x21)
    expect(mutants.some((m) => m[4] === 0x21 && m[5] === 0x00)).toBe(true);
  });

  it("magic field is pinned to the valid constant most of the time, with one flip", () => {
    const base = new Uint8Array(8);
    const grammar: StructGrammar = {
      fields: [{ offset: 0, size: 4, kind: "magic", magic: 0x4d495355n }],
    };
    const mutants = mutateStructured(base, grammar, makeRng(2));
    // 0x4d495355 little-endian => bytes 55 53 49 4d
    const pinned = mutants.find((m) => m[0] === 0x55 && m[1] === 0x53 && m[2] === 0x49 && m[3] === 0x4d);
    expect(pinned).toBeDefined();
    // magic ^ 1 = 0x4d495354 => low byte 0x54
    const flipped = mutants.find((m) => m[0] === 0x54);
    expect(flipped).toBeDefined();
  });

  it("handle field gets boundary handle values (0, -1, table-overflow)", () => {
    const base = new Uint8Array(8);
    const grammar: StructGrammar = { fields: [{ offset: 0, size: 8, kind: "handle" }] };
    const mutants = mutateStructured(base, grammar, makeRng(3));
    const minusOne = mutants.find((m) => Array.from(m.slice(0, 8)).every((b) => b === 0xff));
    expect(minusOne).toBeDefined();
  });

  it("havoc only flips bytes, preserves length, and is deterministic per seed", () => {
    const base = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const grammar: StructGrammar = { fields: [] };
    const a = havoc(base, grammar, makeRng(11));
    const b = havoc(base, grammar, makeRng(11));
    expect(a.byteLength).toBe(base.byteLength);
    expect(Array.from(a)).toEqual(Array.from(b));
    expect(Array.from(a)).not.toEqual(Array.from(base)); // something changed
  });

  it("degrades gracefully: empty grammar still yields a havoc mutant", () => {
    const mutants = mutateStructured(new Uint8Array([9, 9, 9, 9]), { fields: [] }, makeRng(1));
    expect(mutants.length).toBeGreaterThanOrEqual(1);
  });

  it("mutantBudget matches the number produced", () => {
    const base = new Uint8Array(0x20);
    const grammar: StructGrammar = {
      totalSize: 0x20,
      fields: [
        { offset: 0, size: 4, kind: "length" },
        { offset: 8, size: 8, kind: "handle" },
        { offset: 0x10, size: 4, kind: "magic", magic: 0x1234n },
      ],
    };
    const mutants = mutateStructured(base, grammar, makeRng(4));
    expect(mutants).toHaveLength(mutantBudget(grammar, 0x20));
  });
});
