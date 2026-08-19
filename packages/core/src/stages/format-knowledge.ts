/**
 * Binary-format "preseed" knowledge for the craft stage.
 *
 * SOTA CyberGym crafters (Crystalline, MDASH) keep a curated knowledge base of
 * the binary formats common in OSS-Fuzz targets so the agent can build a valid
 * minimal container ON THE FIRST TRY rather than rediscovering the byte layout
 * by trial and error against the oracle. This module is that knowledge — concise
 * per-format primers (magic, structure, the minimal skeleton, and the gotchas
 * that usually block a PoC from reaching the parser). The craft agent pulls a
 * primer via the `format_reference` tool when it identifies the input format.
 *
 * Keep each entry SHORT and ACTIONABLE — byte layout + a minimal valid skeleton
 * + the "what usually blocks you" note. This is a lever for strict pass@1.
 */

export interface FormatPrimer {
  /** Canonical key. */
  id: string;
  /** Aliases / fuzzer-name hints that should resolve to this primer. */
  match: string[];
  primer: string;
}

const PRIMERS: FormatPrimer[] = [
  {
    id: "png",
    match: ["png", "libpng", "apng"],
    primer:
      "PNG: 8-byte sig 89 50 4E 47 0D 0A 1A 0A, then chunks [4B BE length][4B type][data][4B CRC32 of type+data]. " +
      "Required order: IHDR (13B: width4,height4,bitdepth1,colortype1,compression1,filter1,interlace1) → optional → IDAT (zlib stream) → IEND (empty). " +
      "Many readers validate CRC — compute it (zlib.crc32 over type+data). Minimal: sig+IHDR(1x1,8,0)+IDAT(empty zlib '78 9c 03 00 00 00 00 01')+IEND.",
  },
  {
    id: "mng",
    match: ["mng", "jng"],
    primer:
      "MNG: 8-byte sig 8A 4D 4E 47 0D 0A 1A 0A, then PNG-style chunks [4B BE length][4B type][data][4B CRC]. " +
      "First chunk MHDR (28B: frame_w4,frame_h4,ticks4,layer4,frame4,playtime4,profile4). Then animation chunks (LOOP,ENDL,DEFI,FRAM,…), end with MEND (empty). " +
      "GraphicsMagick's MNG reader does NOT validate the CRC word (reads + discards), so any 4 CRC bytes work — crafting is easy.",
  },
  {
    id: "gif",
    match: ["gif"],
    primer:
      "GIF: 'GIF89a' (6B), Logical Screen Descriptor (7B: w2,h2,packed1,bg1,aspect1), optional Global Color Table, then blocks: " +
      "0x2C Image Descriptor (10B) [+ Local CT] + LZW data (sub-blocks: [len][bytes]…00), extensions 0x21, trailer 0x3B.",
  },
  {
    id: "jpeg",
    match: ["jpeg", "jpg", "libjpeg", "turbojpeg"],
    primer:
      "JPEG: markers FF xx. SOI FFD8, then segments [FF marker][2B BE length incl. the 2 length bytes][payload]. " +
      "Key: APPn FFE0…, DQT FFDB, SOF0 FFC0 (frame: prec1,h2,w2,ncomp1,[id,samp,qtab]×n), DHT FFC4, SOS FFDA, entropy data, EOI FFD9.",
  },
  {
    id: "tiff",
    match: ["tiff", "tif", "libtiff"],
    primer:
      "TIFF: header 8B = byte-order ('II'=LE 0x4949 / 'MM'=BE), 42, 4B offset to first IFD. " +
      "IFD: 2B entry-count, then entries (12B each: tag2,type2,count4,value/offset4), 4B next-IFD-offset. " +
      "Crashes often hinge on a tag whose count/offset points out of bounds or a StripOffsets/StripByteCounts mismatch.",
  },
  {
    id: "webp",
    match: ["webp", "libwebp"],
    primer:
      "WebP = RIFF: 'RIFF'[4B LE filesize]'WEBP' then chunks [4B FourCC][4B LE size][data][pad to even]. " +
      "VP8 (lossy 'VP8 '), VP8L (lossless 'VP8L'), VP8X (extended, flags for alpha/anim), ANMF/ALPH. Size fields drive the parser.",
  },
  {
    id: "heif",
    match: ["heif", "heic", "libheif", "avif", "isobmff", "mp4", "bmff", "box"],
    primer:
      "ISO-BMFF (HEIF/AVIF/MP4): a tree of boxes [4B BE size][4B type][payload]; size includes the 8B header (size=1 → 8B largesize follows; size=0 → to EOF). " +
      "HEIF top: ftyp, then meta (hdlr,pitm,iloc,iinf,iprp(ipco/ipma),iref), mdat. " +
      "MUTATE A SEED — building HEIF from scratch is error-prone. Bugs hide in iloc extents, ipco property indices, mismatched item sizes.",
  },
  {
    id: "font",
    match: ["ttf", "otf", "cff", "freetype", "harfbuzz", "hb-shape", "sfnt", "woff", "glyph"],
    primer:
      "SFNT (TTF/OTF): header (sfnt_version4: 0x00010000 TTF / 'OTTO' CFF, numTables2, searchRange2, entrySelector2, rangeShift2), " +
      "then table dir entries (16B: tag4,checksum4,offset4,length4). Required: cmap,head,hhea,hmtx,maxp,name,OS/2,post (+glyf,loca for TTF / CFF for OTF). " +
      "CFF: INDEX structures (count2, offSize1, offsets, data) + DICTs (operand…operator); blend/charstring ops are a classic crash surface. " +
      "HarfBuzz hb-shape takes a font + a text/buffer — the harness usually splits the input into font bytes + shaping text; read the fuzzer to see the split.",
  },
  {
    id: "av1",
    match: ["av1", "aom", "libaom", "dav1d", "obu"],
    primer:
      "AV1 (OBU stream / IVF): OBU = [header: forbidden1 type4 ext1 has_size1 reserved1][optional ext byte][LEB128 size][payload]. " +
      "Sequence: temporal delimiter (type 2), sequence header (type 1), frame/tile (type 6/4/3). IVF container: 'DKIF' 32B header + frames [4B size][8B pts][data]. " +
      "VERY hard to build by hand — MUTATE a seed/corpus frame and perturb sequence-header / tile params.",
  },
  {
    id: "riff",
    match: ["riff", "wav", "avi", "wave"],
    primer:
      "RIFF: 'RIFF'[4B LE size]'WAVE'|'AVI ' then chunks [4B id][4B LE size][data][pad even]. " +
      "WAV: 'fmt ' (16B: fmt2,ch2,rate4,byterate4,align2,bits2) + 'data'. Bugs: size larger than data, odd block-align, huge channel count.",
  },
  {
    id: "zip",
    match: ["zip", "minizip", "libzip", "jar"],
    primer:
      "ZIP: local file headers (PK\\x03\\x04, 30B fixed + name + extra + data), central directory (PK\\x01\\x02), EOCD (PK\\x05\\x06, 22B). " +
      "Parsers read EOCD first (scan from end for PK0506) → central dir offset/count. Mismatched sizes/offsets + zip-bomb fields are classic.",
  },
  {
    id: "pdf",
    match: ["pdf", "poppler", "mupdf", "pdfium"],
    primer:
      "PDF: '%PDF-1.x', body = objects 'N G obj … endobj' (dict <<…>>, streams 'stream\\n…endstream'), xref table, trailer <<… /Root … /Size …>> 'startxref' offset '%%EOF'. " +
      "Many parsers are lenient (scan for objects), so a minimal hand-built doc often works. Bugs: malformed /Length, recursive refs, bad xref offsets.",
  },
  {
    id: "elf",
    match: ["elf", "binutils", "readelf", "libbfd", "objdump"],
    primer:
      "ELF: e_ident (7F 'ELF' class1 data1 ver1 abi1 pad), then header (type2,machine2,ver4,entry,phoff,shoff,flags4,ehsize2,phentsize2,phnum2,shentsize2,shnum2,shstrndx2). " +
      "Section headers (shoff) + program headers (phoff). Bugs: shoff/phoff/sh_offset out of bounds, sh_size overflow, bogus shstrndx, overlapping sections.",
  },
  {
    id: "xml",
    match: ["xml", "libxml", "expat", "html"],
    primer:
      "XML (text): '<?xml version=\"1.0\"?>' optional, elements <tag attr=\"v\">…</tag>, entities &x;, CDATA, DOCTYPE/DTD. " +
      "Bugs: deeply nested elements (stack), billion-laughs entity expansion, malformed/unclosed tags, namespace edge cases.",
  },
  {
    id: "json",
    match: ["json", "jansson", "rapidjson", "cjson"],
    primer:
      "JSON (text): objects {\"k\":v}, arrays [v,…], strings, numbers, true/false/null. " +
      "Bugs: deep nesting (stack overflow), huge/precise numbers, unicode/surrogate escapes, trailing data.",
  },
];

/** Resolve a free-text format/fuzzer hint to the best primer, or undefined. */
export function lookupFormatPrimer(query: string): FormatPrimer | undefined {
  const q = query.toLowerCase();
  // exact id, then alias substring, then token overlap.
  for (const p of PRIMERS) if (p.id === q) return p;
  for (const p of PRIMERS) if (p.match.some((m) => q.includes(m) || m.includes(q))) return p;
  return undefined;
}

/** The catalogue of known format ids, for the tool description + a fallback list. */
export function knownFormatIds(): string[] {
  return PRIMERS.map((p) => p.id);
}
