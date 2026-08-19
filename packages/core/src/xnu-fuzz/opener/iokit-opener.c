/*
 * xnu-fuzz in-guest opener (§3.2 of docs/0sec-iokit-fuzzer.md).
 *
 * The thin C harness that runs INSIDE the disposable macOS VM. The fuzzer brain
 * (enumeration model, generation, mutation, sequencing) stays on the host; this
 * opener only:
 *   1. polls the host-shared folder for a length-prefixed program (program.bin),
 *   2. IOServiceOpen()s the target user client,
 *   3. replays each call via IOConnectCallMethod(),
 *   4. writes per-call kern_return + output back (result.bin).
 *
 * Keeping generation on the host means a guest panic never loses fuzzer state.
 *
 * Wire format — MUST stay in sync with ../program.ts (encodeProgram/decodeProgram):
 *   u32 magic   = 'PKXF' (0x46584b50)   u32 version = 1   u32 callCount
 *   per call: u32 selector; u32 scalarInCount; u64[..] scalars;
 *             u32 structInSize; u8[..] structIn; u32 scalarOutCount; u32 structOutSize
 *
 * Build inside the guest:
 *   clang -O2 -framework IOKit -framework CoreFoundation -o iokit-opener iokit-opener.c
 *
 * Privilege context (§3.2) is chosen by HOW this is launched: under an App
 * Sandbox profile / non-root user (sandbox-reachable LPE = the high-value class)
 * or as root (wider surface, lower per-bug severity). The opener itself is
 * context-agnostic; the launcher records which context produced a crash.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The matching IOService name is supplied by the host (argv[2]); the user
 * client class is bound implicitly by IOServiceOpen's type argument. */
static io_connect_t open_target(const char *service_name, uint32_t connect_type) {
  io_service_t svc = IOServiceGetMatchingService(
      kIOMainPortDefault, IOServiceMatching(service_name));
  if (svc == IO_OBJECT_NULL) {
    fprintf(stderr, "[opener] no matching service: %s\n", service_name);
    return IO_OBJECT_NULL;
  }
  io_connect_t conn = IO_OBJECT_NULL;
  kern_return_t kr = IOServiceOpen(svc, mach_task_self(), connect_type, &conn);
  IOObjectRelease(svc);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[opener] IOServiceOpen(%s) failed: 0x%x\n", service_name, kr);
    return IO_OBJECT_NULL;
  }
  return conn;
}

static uint32_t rd_u32(const uint8_t **p) {
  uint32_t v;
  memcpy(&v, *p, 4);
  *p += 4;
  return v; /* host + guest are both arm64 little-endian */
}
static uint64_t rd_u64(const uint8_t **p) {
  uint64_t v;
  memcpy(&v, *p, 8);
  *p += 8;
  return v;
}

int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr, "usage: %s <program.bin> <IOServiceName> <connectType>\n", argv[0]);
    return 2;
  }
  const char *prog_path = argv[1];
  const char *service = argv[2];
  uint32_t connect_type = (uint32_t)strtoul(argv[3], NULL, 0);

  FILE *f = fopen(prog_path, "rb");
  if (!f) { perror("fopen"); return 2; }
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  uint8_t *blob = (uint8_t *)malloc(sz);
  if (!blob || fread(blob, 1, sz, f) != (size_t)sz) { perror("read"); return 2; }
  fclose(f);

  const uint8_t *p = blob;
  if (rd_u32(&p) != 0x46584b50u) { fprintf(stderr, "[opener] bad magic\n"); return 2; }
  if (rd_u32(&p) != 1u) { fprintf(stderr, "[opener] bad version\n"); return 2; }
  uint32_t call_count = rd_u32(&p);

  io_connect_t conn = open_target(service, connect_type);
  if (conn == IO_OBJECT_NULL) return 1;

  for (uint32_t i = 0; i < call_count; i++) {
    uint32_t selector = rd_u32(&p);
    uint32_t scalar_in_cnt = rd_u32(&p);
    uint64_t scalars[64];
    if (scalar_in_cnt > 64) scalar_in_cnt = 64; /* gate caps are tiny in practice */
    for (uint32_t j = 0; j < scalar_in_cnt; j++) scalars[j] = rd_u64(&p);

    uint32_t struct_in_size = rd_u32(&p);
    const uint8_t *struct_in = p;
    p += struct_in_size;

    uint32_t scalar_out_cnt = rd_u32(&p);
    uint32_t struct_out_size = rd_u32(&p);

    uint64_t scalar_out[64];
    uint32_t scalar_out_cnt_io = scalar_out_cnt > 64 ? 64 : scalar_out_cnt;
    uint8_t *struct_out = struct_out_size ? (uint8_t *)malloc(struct_out_size) : NULL;
    size_t struct_out_sz = struct_out_size;

    /* The one call that matters — every generated input lands here, inside the
     * real handler, because §1 sized it to pass the marshalling gate. */
    kern_return_t kr = IOConnectCallMethod(
        conn, selector,
        scalars, scalar_in_cnt,
        struct_in, struct_in_size,
        scalar_out, &scalar_out_cnt_io,
        struct_out, &struct_out_sz);

    printf("[opener] call %u sel=%u kr=0x%x outScalars=%u outBytes=%zu\n",
           i, selector, kr, scalar_out_cnt_io, struct_out_sz);
    if (struct_out) free(struct_out);
  }

  IOServiceClose(conn);
  free(blob);
  return 0;
}
