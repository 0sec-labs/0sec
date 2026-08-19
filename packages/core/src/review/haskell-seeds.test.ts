import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtemp, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateHaskellSeeds } from "./haskell-seeds.js";

/**
 * Small Haskell tree exercising every bug class the seed layer covers. Each
 * snippet is intentionally a textbook example so the regex layer should pick it
 * up; the review agent does the real reachability work downstream.
 */
const FFI_MODULE = `module Cardano.Crypto.FFI where

import Foreign.Ptr (Ptr, plusPtr, castPtr)
import Foreign.Storable (peekByteOff, pokeByteOff)
import Foreign.Marshal.Alloc (mallocBytes, allocaBytes)

foreign import ccall unsafe "crypto_derive"
  c_derive :: Ptr Word8 -> Ptr Word8 -> IO ()

encryptedDerivePublic :: ByteString -> IO ByteString
encryptedDerivePublic bs =
  allocaBytes 64 $ \\out -> do
    x <- peekByteOff out 0 :: IO Word8
    pokeByteOff out 32 x
    let p = out \`plusPtr\` 16
    pure (castPtr p \`seq\` mempty)
`;

const UNSAFE_MODULE = `module Plutus.Unsafe where

import System.IO.Unsafe (unsafePerformIO)
import Unsafe.Coerce (unsafeCoerce)

cachedThing :: Int
cachedThing = unsafePerformIO (readCounter)

reinterpret :: a -> b
reinterpret = unsafeCoerce
`;

const DECODER_MODULE = `module Cardano.Ledger.Decode where

decodeTx :: ByteString -> Tx
decodeTx bytes =
  case deserialise bytes of
    tx -> tx

readScript :: ByteString -> Script
readScript = unsafeFromBuiltinData . decodeFull'
`;

const PARTIAL_MODULE = `module Cardano.Node.Partial where

firstInput :: [TxIn] -> TxIn
firstInput xs = head xs

riskyIndex :: [a] -> Int -> a
riskyIndex xs i = xs !! i

mustHave :: Maybe a -> a
mustHave = fromJust
`;

const ARITH_MODULE = `module Cardano.Ledger.Arith where

feePerByte :: Integer -> Integer -> Integer
feePerByte total n = total \`div\` n

narrow :: Integer -> Word8
narrow = fromIntegral
`;

const LAZY_MODULE = `module Cardano.Node.Lazy where

sumAll :: [Int] -> Int
sumAll = foldl (+) 0
`;

describe("generateHaskellSeeds", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hs-seeds-"));
    await mkdir(join(dir, "src"), { recursive: true });
    await writeFile(join(dir, "src", "FFI.hs"), FFI_MODULE);
    await writeFile(join(dir, "src", "Unsafe.hs"), UNSAFE_MODULE);
    await writeFile(join(dir, "src", "Decode.hs"), DECODER_MODULE);
    await writeFile(join(dir, "src", "Partial.hs"), PARTIAL_MODULE);
    await writeFile(join(dir, "src", "Arith.hs"), ARITH_MODULE);
    await writeFile(join(dir, "src", "Lazy.hs"), LAZY_MODULE);
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("emits seeds in the SemgrepFinding shape", () => {
    const seeds = generateHaskellSeeds(dir);
    expect(seeds.length).toBeGreaterThan(0);
    for (const s of seeds) {
      expect(typeof s.ruleId).toBe("string");
      expect(s.ruleId.startsWith("haskell-seed.")).toBe(true);
      expect(typeof s.path).toBe("string");
      expect(s.startLine).toBeGreaterThan(0);
      expect(typeof s.snippet).toBe("string");
      expect(typeof s.message).toBe("string");
      expect(s.metadata?.source).toBe("haskell-seed");
    }
  });

  it("uses tree-relative paths", () => {
    const seeds = generateHaskellSeeds(dir);
    for (const s of seeds) {
      expect(s.path.startsWith("/")).toBe(false);
      expect(s.path.startsWith("src/")).toBe(true);
    }
  });

  function classes(seeds: ReturnType<typeof generateHaskellSeeds>): Set<string> {
    return new Set(seeds.map((s) => String(s.metadata?.bugClass)));
  }
  function rules(seeds: ReturnType<typeof generateHaskellSeeds>): Set<string> {
    return new Set(seeds.map((s) => String(s.metadata?.rule)));
  }

  it("covers FFI memory-safety (peekByteOff / foreign import / pointer ops)", () => {
    const seeds = generateHaskellSeeds(dir);
    expect(classes(seeds).has("ffi-memory-safety")).toBe(true);
    const r = rules(seeds);
    expect(r.has("foreign-import")).toBe(true);
    expect(r.has("peekByteOff")).toBe(true);
    expect(r.has("pokeByteOff")).toBe(true);
  });

  it("covers unsafe escapes (unsafePerformIO / unsafeCoerce)", () => {
    const seeds = generateHaskellSeeds(dir);
    expect(classes(seeds).has("unsafe-escape")).toBe(true);
    const r = rules(seeds);
    expect(r.has("unsafePerformIO")).toBe(true);
    expect(r.has("unsafeCoerce")).toBe(true);
  });

  it("covers deserialisation/CBOR (deserialise / unsafeFromBuiltinData / decodeFull)", () => {
    const seeds = generateHaskellSeeds(dir);
    expect(classes(seeds).has("deserialization-cbor")).toBe(true);
    const r = rules(seeds);
    expect(r.has("deserialise")).toBe(true);
    expect(r.has("unsafeFromBuiltinData")).toBe(true);
  });

  it("covers partial functions (head / fromJust / !!)", () => {
    const seeds = generateHaskellSeeds(dir);
    expect(classes(seeds).has("partial-function")).toBe(true);
    const r = rules(seeds);
    expect(r.has("head")).toBe(true);
    expect(r.has("fromJust")).toBe(true);
    expect(r.has("index-op")).toBe(true);
  });

  it("covers arithmetic (div / fromIntegral) and lazy-eval DoS (foldl)", () => {
    const seeds = generateHaskellSeeds(dir);
    expect(classes(seeds).has("arithmetic")).toBe(true);
    expect(classes(seeds).has("lazy-eval-dos")).toBe(true);
    const r = rules(seeds);
    expect(r.has("div-mod")).toBe(true);
    expect(r.has("lazy-foldl")).toBe(true);
  });

  it("does not flag strict foldl' as a lazy-eval seed", () => {
    const seeds = generateHaskellSeeds(dir);
    // Our LAZY_MODULE uses plain `foldl`; a strict `foldl'` must not match.
    const foldlSeeds = seeds.filter((s) => s.metadata?.rule === "lazy-foldl");
    for (const s of foldlSeeds) {
      expect(s.snippet).not.toMatch(/foldl'/);
    }
  });

  it("returns nothing for a tree with no Haskell files", async () => {
    const empty = await mkdtemp(join(tmpdir(), "hs-empty-"));
    try {
      await writeFile(join(empty, "main.rs"), "fn main() { let x = head(); }");
      const seeds = generateHaskellSeeds(empty);
      expect(seeds).toEqual([]);
    } finally {
      await rm(empty, { recursive: true, force: true });
    }
  });

  it("falls back to the in-process scanner when ripgrep is unavailable", () => {
    const seeds = generateHaskellSeeds(dir, { rgPath: "/definitely/missing/rg" });
    expect(seeds.length).toBeGreaterThan(0);
    expect(classes(seeds).has("ffi-memory-safety")).toBe(true);
    expect(classes(seeds).has("partial-function")).toBe(true);
  });
});
