"""TrustDrift v0.4 scorer (POST-HOC revision of v0.2; see README). v0.2 text follows.
TrustDrift v0.2 scorer (metadata only; never downloads or runs package code).
Improvements over v0.1:
 1. Rolling baseline (last 20 releases on the same release line) instead of only the previous release -> no 'echo' after one odd release.
 2. Per-account history: an email change is judged against that account's own earlier email, not against a bot's email.
 3. Dependency features: new dependency pointing to a git/URL spec, brand-new (young) dependency, young dependency with install scripts.
 4. Two sub-scores (path_score, content_score) and an alert tier instead of one number.
Usage: python collector_v2.py axios -o releases_v2.csv
"""
import argparse, csv, json, re, sys, time, urllib.parse, urllib.request
from datetime import datetime
LIFE = ("preinstall", "install", "postinstall")
WIN, PUBWIN, YOUNG_DAYS = 20, 50, 30
URL_SPEC = re.compile(r"^(git|git\+\w+|github|gitlab|bitbucket|https?|file)[:]|^[\w.-]+/[\w.-]+(#.*)?$")
_dep_cache = {}

VERBOSE = False

def fetch(name, tries=4, timeout=120):
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    req = urllib.request.Request(url, headers={"User-Agent": "trustdrift-research/0.2"})
    for k in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r: return json.load(r)
        except Exception:
            if k == tries - 1: raise
            time.sleep(3 * (k + 1))

def ts(t): return datetime.fromisoformat(t.replace("Z", "+00:00"))

DEP_ARCHIVE = None  # optional hook: function(name, at_datetime) -> bool|None (did the dependency have an install script at that time?)

def dep_info(name, at=None):
    """(first-publish datetime or None, has_install_script bool or None).
    Uses the registry 'time' map, which keeps publish times of removed versions, to repair 'created'
    (npm resets 'created' when a package is replaced by a security placeholder). If the dependency has removed versions
    and an archive hook is set, install scripts are judged from the archive as of the release time."""
    if name not in _dep_cache:
        try:
            if VERBOSE: print(f"      dependency lookup: {name}", flush=True)
            d = fetch(name, tries=1, timeout=40); tm = d.get("time", {}); vs = d.get("versions", {})
            keys = [k for k in tm if k not in ("created", "modified")]
            stamps = [ts(tm[k]) for k in keys]
            created = min(stamps) if stamps else (ts(tm["created"]) if tm.get("created") else None)
            life = any(set(LIFE) & set((v.get("scripts") or {}).keys()) for v in vs.values())
            _dep_cache[name] = (created, life, any(k not in vs for k in keys))
        except Exception:
            _dep_cache[name] = (None, None, False)
    created, life, removed = _dep_cache[name]
    if removed and DEP_ARCHIVE and at is not None:
        try:
            arch = DEP_ARCHIVE(name, at)
            if arch is not None: life = bool(life) or bool(arch)
        except Exception:
            pass
    return created, life

def snapshot(ver, meta, t):
    u = meta.get("_npmUser") or {}; dist = meta.get("dist") or {}; sc = meta.get("scripts") or {}
    deps = dict(meta.get("dependencies") or {}); deps.update(meta.get("optionalDependencies") or {})
    return {"version": ver, "time": t, "publisher": u.get("name"), "email": u.get("email"),
            "tp": bool(u.get("trustedPublisher")), "att": "attestations" in dist,
            "maint": set(m.get("name", "") for m in meta.get("maintainers", [])),
            "life": set(k for k in LIFE if k in sc), "deps": deps}

def line_key(v):
    p = v.split("-")[0].split(".")
    try: return (int(p[0]),) if int(p[0]) > 0 else (0, int(p[1]))
    except Exception: return ("?",)

def rows(name, dep_checks=True, extra=None, deps_attack_only=False):
    """extra: optional list of snapshot dicts (with s['attack']=True) to score against this package's live history.
    Attack snapshots are scored but never added to the baseline (a publish-time check would have blocked them)."""
    d = fetch(name); times = d.get("time", {})
    snaps = [snapshot(v, m, times.get(v)) for v, m in d.get("versions", {}).items() if times.get(v)]
    if extra: snaps += extra
    snaps.sort(key=lambda s: s["time"])
    hist, acct_email, out, ghist = {}, {}, [], []
    for s in snaps:
        h = hist.setdefault(line_key(s["version"]), [])
        w = h[-WIN:]; pw = h[-PUBWIN:]; basis = "line"
        if len(w) < 3:  # new release line (e.g. a minor/major bump): fall back to the package's recent releases overall
            w = ghist[-WIN:]; pw = ghist[-PUBWIN:]; basis = "overall"
        r = {"package": name, "version": s["version"], "label": "attack" if s.get("attack") else "normal", "time": s["time"], "publisher": s["publisher"], "trusted_publisher": s["tp"], "attestation": s["att"]}
        f = dict(tp_dropped=0, att_dropped=0, publisher_new=0, email_changed_acct=0, new_lifecycle=0, new_url_dep=0, young_dep=0, young_dep_lifecycle=0, maint_added=0)
        if len(w) >= 3:
            if sum(x["tp"] for x in w) / len(w) >= 0.8 and not s["tp"]: f["tp_dropped"] = 1
            if sum(x["att"] for x in w) / len(w) >= 0.8 and not s["att"]: f["att_dropped"] = 1
            if s["publisher"] not in {x["publisher"] for x in pw}: f["publisher_new"] = 1
            if s["life"] - set().union(*[x["life"] for x in w]): f["new_lifecycle"] = 1
            if s["maint"] - set().union(*[x["maint"] for x in w]): f["maint_added"] = 1
            seen = set().union(*[set(x["deps"]) for x in w])
            for dn, spec in s["deps"].items():
                if dn in seen: continue
                if URL_SPEC.match(str(spec)): f["new_url_dep"] = 1; continue
                if dep_checks and (s.get("attack") or not deps_attack_only):
                    created, life = dep_info(dn, ts(s["time"]))
                    if created and (ts(s["time"]) - created).days < YOUNG_DAYS:
                        f["young_dep"] = 1
                        if life: f["young_dep_lifecycle"] = 1
        prev_email = acct_email.get(s["publisher"])
        if prev_email is not None and s["email"] != prev_email and len(w) >= 3: f["email_changed_acct"] = 1
        if s["publisher"] and not s.get("attack"): acct_email[s["publisher"]] = s["email"]
        path = 3 * (f["tp_dropped"] + f["att_dropped"] + f["publisher_new"] + f["email_changed_acct"])
        content = 3 * f["new_lifecycle"] + 4 * f["new_url_dep"] + 2 * f["young_dep"] + 3 * f["young_dep_lifecycle"] + f["maint_added"]
        if len(w) < 3: basis = "none"
        tier = "NO-BASELINE" if basis == "none" else "CRITICAL" if (path >= 3 and content >= 3) else "HIGH" if content >= 3 else "REVIEW" if path >= 6 else "OK"
        r.update(f); r["baseline"] = basis; r["path_score"] = path; r["content_score"] = content; r["tier"] = tier
        out.append(r)
        if not s.get("attack"): h.append(s); ghist.append(s)
    return out

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("packages", nargs="+"); ap.add_argument("-o", default="releases_v2.csv")
    a = ap.parse_args(); allr = []
    for p in a.packages:
        try: rs = rows(p); allr += rs; print(f"{p}: {len(rs)} releases")
        except Exception as e: print(f"{p}: ERROR {e}", file=sys.stderr)
    if allr:
        with open(a.o, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(allr[0].keys())); w.writeheader(); w.writerows(allr)
        print("wrote", a.o)
