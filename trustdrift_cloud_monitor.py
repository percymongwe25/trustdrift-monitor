"""TrustDrift cloud monitor: ONE polling round per run (built for a scheduled GitHub Actions job). Standard library only.
Each round it asks npm for the tiny 'dist-tags' of every watched package. A changed tag set means a new release: the package history is fetched, the new release
is scored with the frozen v0.4 scorer (collector_v4.py), and the result is logged. Everything is written under --data-dir:
  tags.tsv              one line per package: name, hash of its dist-tags, newest release time already handled (small and stable, so git stays small)
  live_log.csv          one row per new release scored (publish time, detection time, lag, tier, signals, publisher, round gap)
  live_rounds.csv       one row per round (time, gap since previous round, packages checked, unreachable, releases scored)
  snapshots/YYYY-MM.jsonl   our OWN archive: the trimmed manifest of every new release at detection time, kept even if npm later removes it
  alerts_new.md         written only when CRITICAL / HIGH / REVIEW releases were found this round (the workflow turns it into a GitHub issue)
Only public registry metadata is read; no package code is run. A flag is a prompt to look, not proof of an attack."""
import argparse, collections, concurrent.futures as cf, csv, hashlib, importlib, json, os, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timedelta, timezone
UA = {"User-Agent": "trustdrift-cloud-monitor/0.1 (student research; github.com/percymongwe25)"}
FIELDS = ["detected_utc", "published_utc", "lag_minutes", "package", "version", "tier", "baseline", "path_score", "content_score", "signals", "publisher", "trusted_publisher", "attestation", "round_gap_min"]
SIGS = ["tp_dropped", "att_dropped", "publisher_new", "email_changed_acct", "new_lifecycle", "new_url_dep", "young_dep", "young_dep_lifecycle", "maint_added"]
KEEP = ["name", "version", "gitHead", "_npmUser", "maintainers", "dist", "scripts", "dependencies", "optionalDependencies", "peerDependencies", "repository", "deprecated", "_npmVersion", "_nodeVersion"]
def now(): return datetime.now(timezone.utc)
def iso(d): return d.strftime("%Y-%m-%dT%H:%M:%SZ")
def parse(t): return datetime.fromisoformat(t.replace("Z", "+00:00"))
def get(url, timeout=40): return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout)
def enc(n): return urllib.parse.quote(n, safe="@")
def tags_hash(t): return hashlib.sha1(json.dumps(t, sort_keys=True).encode()).hexdigest()[:10]
def fetch_tags(name, tries=3):
    last = "failed"
    for k in range(tries):
        try: return json.load(get("https://registry.npmjs.org/-/package/" + enc(name) + "/dist-tags"))
        except urllib.error.HTTPError as e:
            if e.code == 404: return None
            last = f"HTTP {e.code}"
            if e.code == 429: time.sleep(10 * (k + 1)); continue
        except Exception as e: last = type(e).__name__
        time.sleep(2 * (k + 1))
    raise RuntimeError(last)
def snapshot(pkg, ver, pub):
    """Trimmed manifest of one release, taken now. Returns a dict (never raises)."""
    try:
        m = json.load(get("https://registry.npmjs.org/" + enc(pkg) + "/" + urllib.parse.quote(ver), timeout=60))
        s = {k: m[k] for k in KEEP if k in m}
    except Exception as e:
        s = {"name": pkg, "version": ver, "snapshot_error": type(e).__name__}
    s["published_utc"] = pub; s["snapshot_utc"] = iso(now())
    txt = json.dumps(s, separators=(",", ":"))
    if len(txt) > 30000: s = {k: s[k] for k in ("name", "version", "gitHead", "_npmUser", "dist", "published_utc", "snapshot_utc") if k in s}; s["truncated"] = True
    return s
def read_tags(path):
    st = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) == 3: st[p[0]] = (p[1], p[2])
    return st
def write_tags(path, st):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for k in sorted(st): f.write(f"{k}\t{st[k][0]}\t{st[k][1]}\n")
    os.replace(tmp, path)
def append_csv(path, header, row):
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if new: w.writerow(header)
        w.writerow(row)
def run_round(a):
    D = a.data_dir; os.makedirs(os.path.join(D, "snapshots"), exist_ok=True)
    names = [l.strip() for l in open(a.watch, encoding="utf-8") if l.strip()]
    scorer = importlib.import_module(a.scorer); st = read_tags(os.path.join(D, "tags.tsv"))
    t0 = now(); hb = os.path.join(D, "heartbeat.json")
    prev = json.load(open(hb))["last_round_utc"] if os.path.exists(hb) else None
    gap = (t0 - parse(prev)).total_seconds() / 60 if prev else None
    tags, errs = {}, collections.Counter()
    def one(p):
        try: return p, fetch_tags(p), None
        except Exception as e: return p, None, str(e)
    with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
        for p, t, err in ex.map(one, names):
            if err: errs[err] += 1
            elif t is not None: tags[p] = t
    first = scored = 0; alerts = []
    for p in names:
        if p not in tags: continue
        h = tags_hash(tags[p])
        if p not in st: st[p] = (h, iso(t0 - timedelta(minutes=2))); first += 1; continue
        if st[p][0] == h: continue
        det = now(); last = parse(st[p][1]); newest = last
        try: rows = {r["version"]: r for r in scorer.rows(p)}
        except Exception as e: print(f"could not score {p} ({str(e)[:50]}); will retry next round", flush=True); continue
        for v, r in sorted(rows.items(), key=lambda kv: kv[1]["time"]):
            try: pub = parse(r["time"])
            except Exception: continue
            if pub <= last: continue
            lag = (det - pub).total_seconds() / 60; sig = [k for k in SIGS if str(r.get(k)) in ("1", "True")]
            append_csv(os.path.join(D, "live_log.csv"), FIELDS, [iso(det), iso(pub), round(lag, 1), p, v, r["tier"], r.get("baseline", ""), r["path_score"], r["content_score"], ";".join(sig), r.get("publisher"), r.get("trusted_publisher"), r.get("attestation"), "" if gap is None else round(gap, 1)])
            if a.snapshots:
                with open(os.path.join(D, "snapshots", det.strftime("%Y-%m") + ".jsonl"), "a", encoding="utf-8") as f: f.write(json.dumps(snapshot(p, v, iso(pub)), separators=(",", ":")) + "\n")
            newest = max(newest, pub); scored += 1
            print(f"  {iso(det)}  {p}@{v}  {r['tier']}  (lag {lag:.0f} min)", flush=True)
            if r["tier"] in ("CRITICAL", "HIGH", "REVIEW"):
                alerts.append(f"### {r['tier']}: [{p}@{v}](https://www.npmjs.com/package/{p}/v/{v})\n- published {iso(pub)}, detected {iso(det)} (lag {lag:.0f} min)\n- path score {r['path_score']}, content score {r['content_score']}; signals: {', '.join(sig) or 'none'}; publisher: {r.get('publisher')}\n- A flag is a prompt to look, not proof of an attack. Review the release on npm and record the outcome in the incident log.\n")
        st[p] = (h, iso(newest))
    write_tags(os.path.join(D, "tags.tsv"), st)
    json.dump({"last_round_utc": iso(t0)}, open(hb, "w"))
    append_csv(os.path.join(D, "live_rounds.csv"), ["round_start_utc", "gap_since_previous_round_min", "packages", "unreachable", "new_scored", "first_seen"], [iso(t0), "" if gap is None else round(gap, 1), len(names), sum(errs.values()), scored, first])
    af = a.alerts_file
    if alerts and af: open(af, "w", encoding="utf-8").write("# TrustDrift alert(s)\n\n" + "\n".join(alerts))
    msg = f"{iso(now())} round done: {len(names)} packages checked, {scored} new release(s) scored, {first} recorded for the first time, {len(alerts)} alert(s)"
    if errs: msg += f"; unreachable {sum(errs.values())} ({', '.join(f'{k} x{v}' for k, v in errs.items())})"
    print(msg, flush=True)
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-dir", default="data"); ap.add_argument("--watch", default="watchlist.txt"); ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--snapshots", action="store_true", help="also keep our own archive of each new release's manifest"); ap.add_argument("--alerts-file", default=""); ap.add_argument("--scorer", default="collector_v4")
    run_round(ap.parse_args())
