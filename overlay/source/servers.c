#include "servers.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SlpNxServer g_servers[SLPNXCFG_MAX_SERVERS];
static int g_count = 0;

static void trim(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
}

/* Parse one line into a server entry. Returns 1 on success, 0 to skip. */
static int parse_line(char *line, SlpNxServer *srv) {
    char *comment = strchr(line, '#');
    if (comment != NULL)
        *comment = '\0';
    trim(line);
    if (line[0] == '\0')
        return 0;

    char name[SLPNXCFG_NAME_MAX];
    char host[SLPNXCFG_HOST_MAX];
    char portstr[8];
    long port = 11451;

    if (sscanf(line, "%31s %127s %7s", name, host, portstr) == 3) {
        port = strtol(portstr, NULL, 10);
    } else if (sscanf(line, "%31s %127s", name, host) == 2) {
        char *colon = strrchr(host, ':');
        if (colon != NULL) {
            *colon = '\0';
            port = strtol(colon + 1, NULL, 10);
        }
    } else {
        return 0;
    }

    if (port < 1 || port > 65535)
        return 0;

    memset(srv, 0, sizeof(*srv));
    strncpy(srv->name, name, sizeof(srv->name) - 1);
    strncpy(srv->host, host, sizeof(srv->host) - 1);
    srv->port = (unsigned short)port;
    return 1;
}

static int slpnxServersParse(const char *text, size_t len) {
    int n = 0;
    const char *p = text;
    const char *end = text + len;

    while (n < SLPNXCFG_MAX_SERVERS && p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t linelen = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);

        char line[SLPNXCFG_NAME_MAX + SLPNXCFG_HOST_MAX + 8];
        size_t copy = linelen < sizeof(line) - 1 ? linelen : sizeof(line) - 1;
        memcpy(line, p, copy);
        line[copy] = '\0';

        SlpNxServer srv;
        if (parse_line(line, &srv))
            g_servers[n++] = srv;

        if (nl == NULL)
            break;
        p = nl + 1;
    }

    g_count = n;
    return g_count;
}

int slpnxServersLoad(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return 0;

    static char buf[SLPNXCFG_MAX_SERVERS * (SLPNXCFG_NAME_MAX + SLPNXCFG_HOST_MAX + 8)];
    size_t used = 0;
    size_t chunk;

    while (used < sizeof(buf) - 1 && (chunk = fread(buf + used, 1, sizeof(buf) - 1 - used, f)) > 0)
        used += chunk;

    fclose(f);
    buf[used] = '\0';
    return slpnxServersParse(buf, used);
}

int slpnxServersCount(void) {
    return g_count;
}

const SlpNxServer *slpnxServersGet(int index) {
    if (index < 0 || index >= g_count)
        return NULL;
    return &g_servers[index];
}
