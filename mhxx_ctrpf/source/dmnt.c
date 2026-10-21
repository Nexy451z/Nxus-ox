#include "dmnt.h"

#include <string.h>

static Service g_Cht;
static bool    g_Open;

Result mhxxDmntInit(void) {
    if (g_Open) return 0;
    Result rc = smGetService(&g_Cht, "dmnt:cht");
    if (R_SUCCEEDED(rc)) g_Open = true;
    return rc;
}

void mhxxDmntExit(void) {
    if (!g_Open) return;
    serviceClose(&g_Cht);
    memset(&g_Cht, 0, sizeof(g_Cht));
    g_Open = false;
}

Result mhxxDmntHasProcess(bool *out) {
    u8 value = 0;
    Result rc = serviceDispatchOut(&g_Cht, 65000, value);
    if (R_SUCCEEDED(rc) && out != NULL) *out = value != 0;
    return rc;
}

Result mhxxDmntForceOpen(void)  { return serviceDispatch(&g_Cht, 65003); }
Result mhxxDmntForceClose(void) { return serviceDispatch(&g_Cht, 65006); }

Result mhxxDmntMetadata(MhxxMetadata *out) {
    if (out == NULL) return MAKERESULT(Module_Libnx, LibnxError_BadInput);
    memset(out, 0, sizeof(*out));
    return serviceDispatchOut(&g_Cht, 65002, *out);
}

Result mhxxDmntRead(u64 address, void *buffer, size_t size) {
    return serviceDispatchIn(&g_Cht, 65102, address,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers      = { { buffer, size } },
    );
}

Result mhxxDmntWrite(u64 address, const void *buffer, size_t size) {
    return serviceDispatchIn(&g_Cht, 65103, address,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_In },
        .buffers      = { { buffer, size } },
    );
}

Result mhxxDmntMappingCount(u64 *out) {
    u64 count = 0;
    Result rc = serviceDispatchOut(&g_Cht, 65100, count);
    if (R_SUCCEEDED(rc) && out != NULL) *out = count;
    return rc;
}

Result mhxxDmntMappings(MhxxMemInfo *out, size_t max, size_t offset, size_t *out_count) {
    u64 in_offset = (u64)offset;
    u64 count = 0;
    Result rc = serviceDispatchInOut(&g_Cht, 65101, in_offset, count,
        .buffer_attrs = { SfBufferAttr_HipcMapAlias | SfBufferAttr_Out },
        .buffers      = { { out, max * sizeof(MhxxMemInfo) } },
    );
    if (R_SUCCEEDED(rc) && out_count != NULL) *out_count = (size_t)count;
    return rc;
}

Result mhxxDmntFreeze(u64 address, u64 width, u64 *out_value) {
    struct { u64 addr; u64 width; } in = { address, width };
    u64 value = 0;
    Result rc = serviceDispatchInOut(&g_Cht, 65303, in, value);
    if (R_SUCCEEDED(rc) && out_value != NULL) *out_value = value;
    return rc;
}

Result mhxxDmntUnfreeze(u64 address) {
    return serviceDispatchIn(&g_Cht, 65304, address);
}
