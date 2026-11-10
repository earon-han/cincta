#include "json.h"
#include <stddef.h>

void json_string(FILE *f, const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    fputc('"', f);
    while (*p) {
        if (*p == '"' || *p == '\\') { fprintf(f, "\\%c", *p++); continue; }
        if (*p < 32) { fprintf(f, "\\u%04x", *p++); continue; }
        if (*p < 128) { fputc(*p++, f); continue; }
        unsigned count = *p >= 0xc2 && *p <= 0xdf ? 2 : *p >= 0xe0 && *p <= 0xef ? 3 : *p >= 0xf0 && *p <= 0xf4 ? 4 : 0;
        unsigned codepoint = count ? *p & ((1u << (7 - count)) - 1) : 0;
        for (unsigned i = 1; i < count; ++i) {
            if (!p[i] || (p[i] & 0xc0) != 0x80) { count = 0; break; }
            codepoint = (codepoint << 6) | (p[i] & 0x3f);
        }
        if (!count || (count == 3 && codepoint < 0x800) || (count == 4 && codepoint < 0x10000) ||
            codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff)) fprintf(f, "\\u%04x", *p++);
        else { fwrite(p, 1, count, f); p += count; }
    }
    fputc('"', f);
}
