#ifndef CINCTA_JSON_H
#define CINCTA_JSON_H
#include <stdio.h>
/* Preserve valid UTF-8; escape malformed individual bytes into valid JSON. */
void json_string(FILE *file, const char *text);
#endif
