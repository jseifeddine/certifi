#!/usr/bin/env bash
# Fail if a Windows .exe depends on something a bare Windows install lacks.
#
#   check-windows-exe.sh <exe>...          every exe: no Visual C++ runtime
#   check-windows-exe.sh --legacy <exe>... also: no Windows 10-only APIs
#
# The C runtime is linked statically (.cargo/config.toml), so no exe may
# import VCRUNTIME140.dll or the Universal CRT (api-ms-win-crt-*.dll); a
# machine without the VC++ Redistributable refuses to start it. The legacy
# build must also stay off ProcessPrng (bcryptprimitives.dll), which only
# exists on Windows 10 / Server 2016 and later.
#
# Import names are plain ASCII in the PE import table, so grep -a is enough.
set -euo pipefail

legacy=0
if [ "${1:-}" = "--legacy" ]; then
  legacy=1
  shift
fi

status=0
for exe in "$@"; do
  forbidden='vcruntime140[_0-9]*\.dll|msvcp140\.dll|api-ms-win-crt-[a-z-]+-l1-1-0\.dll'
  if [ "$legacy" = 1 ]; then
    forbidden="$forbidden|ProcessPrng|bcryptprimitives\.dll"
  fi
  found=$(grep -aoiE "$forbidden" "$exe" | sort -uf | tr '\n' ' ' || true)
  if [ -n "$found" ]; then
    echo "::error::$exe imports $found"
    status=1
  else
    echo "$exe: OK"
  fi
done
exit $status
