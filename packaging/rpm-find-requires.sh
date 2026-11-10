#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Requires generator for cargo-generate-rpm (--auto-req / auto-req): like
# rpm's find-requires, but lists only the shared libraries each binary links
# directly (DT_NEEDED). The builtin ldd-based generator lists the whole
# ldd closure, which pulls in libraries such as libpxbackend that have no
# providing package on some systems (rpm-ostree then refuses the RPM).
#
# Reads file paths on stdin, prints RPM capabilities on stdout.
while read -r file; do
    readelf -d "$file" 2>/dev/null |
        sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1()(64bit)/p'
done | sort -u
