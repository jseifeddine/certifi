#!/usr/bin/env bash
# Fail if a Windows .exe depends on something a bare Windows install lacks.
#
#   check-windows-exe.sh <exe>...          every exe: no Visual C++ runtime
#   check-windows-exe.sh --legacy <exe>... also: no Windows 10-only APIs
#
# The C runtime is linked statically (.cargo/config.toml), so no exe may
# import VCRUNTIME140.dll or the Universal CRT (api-ms-win-crt-*.dll); a
# machine without the VC++ Redistributable refuses to start it. The legacy
# build must also stay off bcryptprimitives.dll (ProcessPrng), which only
# exists on Windows 10 / Server 2016 and later.
#
# Reads the real import table (pe-imports.py), not strings in the file.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
py=$(command -v python3 || command -v python)

legacy=0
if [ "${1:-}" = "--legacy" ]; then
  legacy=1
  shift
fi

forbidden='^(vcruntime140(_[0-9]+)?|msvcp140(_[0-9]+)?|api-ms-win-crt-[a-z-]+-l1-1-0)\.dll$'
if [ "$legacy" = 1 ]; then
  forbidden="$forbidden|^bcryptprimitives\.dll$"
fi

status=0
for exe in "$@"; do
  dlls=$("$py" "$here/pe-imports.py" "$exe")
  found=$(printf '%s\n' "$dlls" | grep -iE "$forbidden" | sort -uf | tr '\n' ' ' || true)
  if [ -n "$found" ]; then
    echo "::error::$exe imports $found"
    # Which functions come from them points at the dependency responsible.
    "$py" "$here/pe-imports.py" --functions "$exe" \
      | grep -iF -f <(printf '%s!\n' $found) | sed 's/^/    /' || true
    status=1
  else
    echo "$exe: OK ($(printf '%s\n' "$dlls" | sort -uf | tr '\n' ' '))"
  fi
done
exit $status
