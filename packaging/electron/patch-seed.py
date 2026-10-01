#!/usr/bin/env python3
"""Patch the staged payload's seed.js so the demo fixture uses dynamic ports.

The repo's seed.js hardcodes fixture ports 8081/8082 in the seeded asset
records and monitors. The desktop shell picks FREE ports at runtime (the
user's machine may already run another instance — e.g. the console edition —
on 8081/8082), so the payload staging applies this patch: every port
reference follows FIXTURE_HTTP_PORT / FIXTURE_TLS_PORT.

Every replacement is exact-string and asserted, so upstream drift fails the
build instead of silently mis-seeding.
"""
import sys

path = sys.argv[1]
src = open(path, encoding='utf-8').read()

REPLACEMENTS = [
    # 1. runtime port constants (right after the dataDir line)
    (
        "const dataDir = path.resolve(process.env.MERIDIAN_DATA || './data');",
        "const dataDir = path.resolve(process.env.MERIDIAN_DATA || './data');\n"
        "const FIXTURE_HTTP = Number(process.env.FIXTURE_HTTP_PORT || 8081);\n"
        "const FIXTURE_TLS = Number(process.env.FIXTURE_TLS_PORT || 8082);",
    ),
    # 2. startFixture args
    (
        "httpPort: Number(process.env.FIXTURE_HTTP_PORT || 8081), tlsPort: Number(process.env.FIXTURE_TLS_PORT || 8082)",
        "httpPort: FIXTURE_HTTP, tlsPort: FIXTURE_TLS",
    ),
    # 3. log line
    (
        "console.log('[seed] fixture target started on 127.0.0.1:8081 (DELIBERATELY VULNERABLE, loopback only)');",
        "console.log(`[seed] fixture target started on 127.0.0.1:${FIXTURE_HTTP} (DELIBERATELY VULNERABLE, loopback only)`);",
    ),
    # 4. asset / monitor port fields
    ("port: 8081,", "port: FIXTURE_HTTP,"),
    ("port: 8082,", "port: FIXTURE_TLS,"),
    ("ports: [8081, 8082]", "ports: [FIXTURE_HTTP, FIXTURE_TLS]"),
    ("ports: [8081]", "ports: [FIXTURE_HTTP]"),
    # 5. identifiers
    (
        "identifier: 'https://localhost:8082'",
        "identifier: `https://localhost:${FIXTURE_TLS}`",
    ),
    (
        "identifier: 'http://localhost:8081/promo'",
        "identifier: `http://localhost:${FIXTURE_HTTP}/promo`",
    ),
    # 6. monitor URLs
    ("url: 'http://127.0.0.1:8081/'", "url: `http://127.0.0.1:${FIXTURE_HTTP}/`"),
]

for old, new in REPLACEMENTS:
    n = src.count(old)
    assert n >= 1, f"patch anchor not found: {old[:60]!r}"
    src = src.replace(old, new)

open(path, 'w', encoding='utf-8').write(src)

# no hardcoded fixture-port literals may remain (other than in the new constants)
import re
leftovers = [
    m for m in re.finditer(r'\b808[12]\b', src)
    if 'FIXTURE_HTTP_PORT' not in src[max(0, m.start() - 40):m.start()]
    and 'FIXTURE_TLS_PORT' not in src[max(0, m.start() - 40):m.start()]
]
assert not leftovers, f"unpatched port literals remain: {len(leftovers)}"
print(f"seed.js patched: {len(REPLACEMENTS)} rules applied")
