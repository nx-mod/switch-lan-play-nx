#!/bin/bash
# Builds switch-lan-play-nx (bsd:u mitm bridge + config overlay) inside the
# devkitPro MSYS2 shell. Invoked by build.bat in this same folder (and usable
# standalone from msys2):
#   bash build.sh [target] [jobs] [--dryrun]
#     target  all (default) | dist | clean
#
# Builds against the vendored atmosphere-libs submodule as a nightly (no
# libstratosphere version is pinned) -- see this project's own README.

source /etc/profile.d/devkit-env.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

# Point at the flat-cloned libnx fork, not devkitPro's stock system libnx --
# the latter is stale and lacks API additions this repo's projects rely on
# (e.g. NacpStruct::lang_data). Matches the root Makefile's own override.
export LIBNX="$SCRIPT_DIR/../libnx/nx"

TARGET="${1:-all}"
JOBS="${2:-2}"
DRYRUN=""
[ "${3}" = "--dryrun" ] && DRYRUN="-n"

echo "DEVKITPRO=$DEVKITPRO"
echo "Target=$TARGET Jobs=$JOBS DryRun=${DRYRUN:-no} CWD=$(pwd)"

if [ "$TARGET" = "clean" ]; then
    make clean
    (cd overlay && make clean)
    exit $?
fi

MAKE_TARGET="$TARGET"
[ "$TARGET" = "dist" ] && MAKE_TARGET="all"

make $DRYRUN -j"$JOBS" "$MAKE_TARGET" && \
( cd overlay && make $DRYRUN -j"$JOBS" "$MAKE_TARGET" )
STATUS=$?

if [ $STATUS -eq 0 ] && [ -z "$DRYRUN" ]; then
    echo "== Build ok: switch-lan-play-nx.nsp + overlay/overlay.ovl =="
    ls -la switch-lan-play-nx.nsp overlay/overlay.ovl 2>/dev/null

    # No Makefile dist target -- stage the SD-card-relative layout ourselves:
    # atmosphere/contents/<tid>/ (from res/toolbox.json's "tid") + boot2.flag
    # (requires_reboot in toolbox.json) + switch/.overlays/ for the config
    # overlay. See PACKAGING.md at the switch-cfw root.
    if [ "$TARGET" = "dist" ] && [ -f switch-lan-play-nx.nsp ]; then
        TID="$(grep -oP '"tid":\s*"\K[0-9A-Fa-f]+' res/toolbox.json)"
        ZIPS_DIR="$SCRIPT_DIR/../_ZIPS_"
        SDCARD_DIR="$SCRIPT_DIR/../_SDCARD_/switch-lan-play-nx"
        mkdir -p "$ZIPS_DIR"
        rm -rf "$SDCARD_DIR"
        mkdir -p "$SDCARD_DIR/atmosphere/contents/$TID/flags" "$SDCARD_DIR/switch/.overlays"
        cp switch-lan-play-nx.nsp "$SDCARD_DIR/atmosphere/contents/$TID/exefs.nsp"
        cp res/toolbox.json "$SDCARD_DIR/atmosphere/contents/$TID/toolbox.json"
        touch "$SDCARD_DIR/atmosphere/contents/$TID/flags/boot2.flag"
        cp overlay/overlay.ovl "$SDCARD_DIR/switch/.overlays/switch-lan-play-nx-overlay.ovl"
        (cd "$SDCARD_DIR" && zip -rq "$ZIPS_DIR/switch-lan-play-nx-release.zip" ./*)
        echo "== Packaged: $ZIPS_DIR/switch-lan-play-nx-release.zip =="
        echo "== Extracted: $SDCARD_DIR =="
    fi
fi

exit $STATUS
