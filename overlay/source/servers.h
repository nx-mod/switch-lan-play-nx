#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * servers.h -- relay server list. Kept in sync BY HAND with the sysmodule's
 * own copy at ../../source/cfg/servers.h -- two separate builds, so it
 * can't be a single shared file without restructuring both Makefiles.
 */

#define SLPNXCFG_MAX_SERVERS 10
#define SLPNXCFG_NAME_MAX 32
#define SLPNXCFG_HOST_MAX 128

typedef struct {
    char name[SLPNXCFG_NAME_MAX];
    char host[SLPNXCFG_HOST_MAX];
    unsigned short port;
} SlpNxServer;

/* Load servers from `path` (this is the overlay: stdio is fine here). Up to
 * SLPNXCFG_MAX_SERVERS entries are read; returns the number loaded. */
int slpnxServersLoad(const char *path);

/* Number of servers in the last loaded list. */
int slpnxServersCount(void);

/* Pointer to the server at `index`, or NULL if out of range. */
const SlpNxServer *slpnxServersGet(int index);

#ifdef __cplusplus
}
#endif
