#!/usr/bin/python3 -I
"""Reads Ubuntu's list of known security problems (`pro cves`) for the nightly security check.

    pro cves --unfixable | cves.py unfixable STATE_DIR
    pro cves --fixable   | cves.py fixable STATE_DIR WAIT_DAYS

`pro cves` prints one row per (package, CVE): "package priority origin CVE-…". The same CVE is
listed once for every package it affects, and every installed kernel version brings its own
packages (linux-image-…, linux-modules-…), so the number of rows is much higher than the number of
problems. This script counts each CVE once and works out what's new since the last run – in one
pass (the rows can be tens of thousands).

Prints KEY=value lines for dk-security-check (lists separated by "; ") and keeps its memory
in STATE_DIR (known-cves, fixable-seen, cve-summary, accepted).
Installed by install.sh to /usr/local/lib/dk-srv/cves.py.
"""
import datetime
import os
import re
import sys

FACING = re.compile(r"^(nginx|nginx-.*|libnginx-mod-.*|openssl|libssl[0-9].*)$")
PRIORITIES = ["critical", "high", "medium", "low", "negligible"]
RANK = PRIORITIES + ["unrated"]  # Ubuntu hasn't rated it yet ("needs-triage" …)
SEVERE = {"critical", "high"}
KERNEL = re.compile(r"^linux(-|$)")
KERNEL_VERSION = re.compile(r"(\d+\.\d+\.\d+-\d+)")
SHOW = 10  # at most this many CVEs named in a message


def rows():
    for line in sys.stdin:
        parts = line.split()
        if len(parts) >= 4 and re.match(r"^(CVE|USN)-", parts[3]):
            yield parts[0], parts[1], parts[2], parts[3]


def group(pkg):
    return "kernel" if KERNEL.match(pkg) else pkg


def read_set(path):
    try:
        with open(path, encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except OSError:
        return set()


def write_lines(path, lines):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")
    os.replace(tmp, path)


def out(key, value):
    print(f"{key}={value}")


def join(items, limit=SHOW):
    items = list(items)
    text = "; ".join(items[:limit])
    return text + (f"; … and {len(items) - limit} more" if len(items) > limit else "")


def unfixable(state):
    known_path = os.path.join(state, "known-cves")
    known = read_set(known_path)
    if not os.path.exists(known_path):
        # earlier versions remembered "cve <package> <CVE>" in "reported": start from those
        known |= {l.split()[-1] for l in read_set(os.path.join(state, "reported")) if l.startswith("cve ")}
    first_run = not known  # nothing known yet: the problems found now are the starting point
    accepted = {l.split(" ", 1)[1] for l in read_set(os.path.join(state, "accepted")) if l.startswith("cve ")}

    worst = {}       # CVE -> its highest priority
    packages = {}    # CVE -> set of package groups
    lockdown, unrated, ssh, other = {}, {}, {}, {}
    kernels = set()
    total_rows = 0
    for pkg, prio, _origin, cve in rows():
        total_rows += 1
        g = group(pkg)
        packages.setdefault(cve, set()).add(g)
        rated = prio if prio in PRIORITIES else "unrated"
        if cve not in worst or RANK.index(rated) < RANK.index(worst[cve]):
            worst[cve] = rated
        if g == "kernel":
            m = KERNEL_VERSION.search(pkg)
            if m:
                kernels.add(m.group(1))
        if FACING.match(pkg):
            if prio in SEVERE and cve not in accepted:
                lockdown.setdefault(cve, f"{pkg} {cve} ({prio})")
            elif prio not in PRIORITIES:
                unrated.setdefault(cve, f"{pkg} {cve} ({prio})")
        elif pkg.startswith("openssh") and prio in SEVERE:
            ssh.setdefault(cve, f"{pkg} {cve} ({prio})")
        elif prio in SEVERE:
            other.setdefault(cve, (g, prio))

    counts = {p: 0 for p in RANK}
    for prio in worst.values():
        counts[prio] += 1
    severe_by_group = {}
    for cve, prio in worst.items():
        if prio in SEVERE:
            for g in packages[cve]:
                severe_by_group[g] = severe_by_group.get(g, 0) + 1
    top = sorted(severe_by_group.items(), key=lambda kv: -kv[1])

    new_ssh = [v for c, v in ssh.items() if c not in known]
    new_unrated = [v for c, v in unrated.items() if c not in known]
    new_other = sorted(((c, g, p) for c, (g, p) in other.items() if c not in known),
                       key=lambda t: (PRIORITIES.index(t[2]), t[1], t[0]))
    known |= set(ssh) | set(unrated) | set(other)
    write_lines(known_path, sorted(known))

    summary = [
        f"ROWS={total_rows}",
        f"UNIQUE={len(worst)}",
        "BY_PRIORITY=" + ", ".join(f"{counts[p]} {p}" for p in RANK if counts[p]),
        "SEVERE_TOP=" + ", ".join(f"{g} {n}" for g, n in top[:5]),
        "KERNEL_VERSIONS=" + ",".join(sorted(kernels)),
    ]
    write_lines(os.path.join(state, "cve-summary"), summary)
    for line in summary:
        print(line)
    out("FIRST_RUN", "yes" if first_run else "no")
    out("LOCKDOWN", join(lockdown.values(), 50))
    out("UNRATED_NEW", join(new_unrated))
    out("SSH_NEW", join(new_ssh))
    out("OTHER_NEW_COUNT", len(new_other))
    # by package: a new package (e.g. installed by the hardening) brings all its known problems at
    # once – the counts show where a big number comes from
    by_pkg = {}
    for c, _g, _p in new_other:
        for g in packages[c]:
            by_pkg[g] = by_pkg.get(g, 0) + 1
    out("OTHER_NEW_BY_PACKAGE", ", ".join(f"{g} {n}" for g, n in sorted(by_pkg.items(), key=lambda kv: (-kv[1], kv[0]))[:8]))
    out("OTHER_NEW", join(f"{c} ({g}, {p})" for c, g, p in new_other))


def fixable(state, wait_days):
    seen_path = os.path.join(state, "fixable-seen")
    today = datetime.date.today()
    seen = {}
    for line in read_set(seen_path):
        parts = line.split()  # "CVE date" (earlier versions: "package CVE date")
        if len(parts) >= 2:
            seen[parts[-2]] = parts[-1]
    reported = read_set(os.path.join(state, "reported"))
    now, waiting, new_reported = {}, [], []
    for pkg, prio, origin, cve in rows():
        if origin != "standard" or prio not in SEVERE:
            continue  # esm-…: only with Ubuntu Pro; lower priorities wait for the normal updates
        since = seen.get(cve, today.isoformat())
        now[cve] = since
        age = (today - datetime.date.fromisoformat(since)).days
        key = f"waiting {cve}"
        if age >= wait_days and key not in reported and cve not in [w[0] for w in waiting]:
            waiting.append((cve, f"{group(pkg)} {cve} ({prio})"))
            new_reported.append(key)
    write_lines(seen_path, sorted(f"{c} {d}" for c, d in now.items()))
    if new_reported:
        with open(os.path.join(state, "reported"), "a", encoding="utf-8") as f:
            for key in new_reported:
                f.write(key + "\n")
    out("FIXABLE", len(now))
    out("WAITING_COUNT", len(waiting))
    out("WAITING", join(text for _, text in waiting))


if __name__ == "__main__":
    os.makedirs(sys.argv[2], exist_ok=True)
    if sys.argv[1] == "unfixable":
        unfixable(sys.argv[2])
    elif sys.argv[1] == "fixable":
        fixable(sys.argv[2], int(sys.argv[3]))
    else:
        sys.exit(__doc__)
