# TrustDrift monitor

An automated research monitor that watches about 6,000 popular npm packages and scores every new release with the frozen TrustDrift v0.4 rules (`collector_v4.py`). It is part of an interim, non-peer-reviewed student research project (Perseverance Sandile Mongwe, Eduvos, South Africa) on detecting update-based compromise of npm packages from registry metadata.

> **Important.** The output is automated and unverified. A flag means "an unusual release pattern worth a human look", **not** an accusation and not proof of an attack. Most flags are expected to be ordinary events (a maintainer change, a new tool dependency, a manual publish). Flags are reviewed by hand, and the outcome is recorded.

## What it does
Every 30 minutes (GitHub Actions) it asks npm for the tiny `dist-tags` of each watched package. If they changed, a new release exists: the monitor scores it, logs it, and saves a trimmed copy of that release's manifest (our own archive, kept even if npm later removes the release). Only public registry metadata is read; no package code is run.

## Where the data is
The branch **`monitor-data`** holds: `live_log.csv` (every new release scored), `live_rounds.csv` (monitor uptime), `snapshots/YYYY-MM.jsonl` (the archive), `tags.tsv` (the monitor's memory) and `alerts_history.md`.

## Status and limits
- Run period and rules are fixed by the confirmatory protocol (see the main TrustDrift repository). Rules are frozen: nothing is tuned during the run.
- The watchlist is a convenience sample of popular packages, not a random sample of npm.
- Scheduled runs can be delayed by GitHub, so detection lag is minutes, not seconds.
- A short run may contain no attack at all; that is a valid result and will be reported as such.

## Responsible use
If a release is confirmed malicious it is reported through npm's security process before any public discussion. This repository does not publish exploit details.
