#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * servers.h -- relay server list.
 *
 * No username/password fields: RelayBridge::Connect() (relay_bridge.hpp)
 * has no login/auth support.
 */

#define SLPNXCFG_MAX_SERVERS 10
#define SLPNXCFG_NAME_MAX 32
#define SLPNXCFG_HOST_MAX 128

typedef struct {
    char name[SLPNXCFG_NAME_MAX];
    char host[SLPNXCFG_HOST_MAX];
    unsigned short port;
} SlpNxServer;

/*
 * Load servers from `path` via stdio (used by the overlay). Up to
 * SLPNXCFG_MAX_SERVERS entries are read; excess lines are ignored. Returns
 * the number of servers loaded (0 on open/parse failure). Any previous
 * list is replaced.
 */
int slpnxServersLoad(const char *path);

/*
 * Parse servers from an in-memory buffer (used by the sysmodule, which must
 * not use stdio in a boot2 context). Up to SLPNXCFG_MAX_SERVERS entries are
 * read; returns the number loaded.
 */
int slpnxServersParse(const char *text, size_t len);

/* Number of servers in the last loaded list. */
int slpnxServersCount(void);

/* Pointer to the server at `index`, or NULL if out of range. */
const SlpNxServer *slpnxServersGet(int index);

/* Index of the first server whose name matches, or -1. */
int slpnxServersFindByName(const char *name);

#ifdef __cplusplus
}
#endif
