"""Refit short-horizon strategy choices using human-authored calls only."""

import hashlib
import html
import json
import csv
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path

import numpy as np

from repeat_call_dataset import load_repeat_dataset, load_repeat_seconds
from research_dataset import DAY, sha256, write_json
from second_engine import SecondExit, paths, portfolio, simulate_seconds
from second_lab import search, verify_ledger


ROOT = Path(__file__).resolve().parent
CAP_EDGES = (0, 3_000, 6_000, 10_000, 25_000, 50_000, 100_000, 250_000, 1_000_000, float("inf"))
DELAYS = (1, 3, 5, 10, 30, 60)


def read(path):
    return json.loads(Path(path).read_text())


def caller_history(dataset, data):
    """Use only prior-day, distinct-token outcomes from human authors."""
    a, n = dataset.arrays, dataset.n
    human = ~a["bot"]
    path = paths(data, a["entry_time"] + 5_000, horizon=200)
    outcome = simulate_seconds(data, path, SecondExit(hold=180))
    net = np.clip(outcome["gross"] * .9 - 1, -1., 1.)
    finished = np.maximum(outcome["exit_time"], outcome["admit_end"])
    valid = human & np.isfinite(net)
    count, mean, robust = np.zeros(n, np.int16), np.full(n, np.nan), np.full(n, np.nan)

    def earliest_distinct(indices):
        ordered = indices[np.argsort(a["posted"][indices], kind="stable")]
        seen, selected = set(), []
        for index in ordered:
            asset = int(a["asset"][index])
            if asset not in seen:
                seen.add(asset)
                selected.append(index)
        return selected

    for i in np.flatnonzero(human):
        prior = valid & (finished < int(a["day"][i]) * DAY) & (a["asset"] != a["asset"][i])
        own = earliest_distinct(np.flatnonzero(prior & (a["author"] == a["author"][i])))[-20:]
        peers = earliest_distinct(np.flatnonzero(prior & (a["author"] != a["author"][i])))
        peer_mean = float(np.mean(net[peers])) if peers else 0.
        count[i] = len(own)
        mean[i] = (float(np.sum(net[own])) + 10 * peer_mean) / (len(own) + 10)
        if len(own) >= 2:
            robust[i] = (float(np.sum(net[own]) - np.max(net[own])) + 10 * peer_mean) / (len(own) + 9)
    return {"count": count, "mean": mean, "robustMean": robust,
            "reference": "180-second observed exit after a five-second quote delay; 10% proceeds haircut; frozen before each UTC day"}


def catalog(dataset, history):
    a, n = dataset.arrays, dataset.n
    human = ~a["bot"]
    first_human = np.zeros(n, bool)
    seen = set()
    for i in np.argsort(a["posted"], kind="stable"):
        asset = int(a["asset"][i])
        if human[i] and asset not in seen:
            seen.add(asset)
            first_human[i] = True
    chains = np.array([call["chainId"] for call in dataset.meta["calls"]])
    filters = {
        "human_all": human,
        "human_known_text": human & a["message_known"],
        "human_first_per_token": first_human,
        "human_direct_post": human & ~a["forwarded"],
        "human_quote_under_1m_old": human & (a["quote_age"] <= 1),
        "human_token_under_1h_old": human & (a["age"] <= 60),
        "human_solana": human & (chains == "solana:solana"),
        "human_evm": human & (chains != "solana:solana"),
        "human_prior_positive": human & (history["count"] >= 3) & (history["robustMean"] > 0),
        "human_prior_nonnegative": human & (history["count"] >= 3) & (history["mean"] >= 0),
        "human_prior_negative": human & (history["count"] >= 3) & (history["mean"] < 0),
    }
    cap = a["cap"]
    ranges = [(0, float("inf"))]
    ranges += list(zip(CAP_EDGES[:-1], CAP_EDGES[1:]))
    ranges += [(0, edge) for edge in CAP_EDGES[1:-1]]
    ranges += [(edge, float("inf")) for edge in CAP_EDGES[1:-1]]
    entries, used = [], set()
    for lower, upper in ranges:
        cap_mask = np.isfinite(cap) & (cap >= lower) & (cap < upper)
        for name, source in filters.items():
            mask = cap_mask & source
            if int(mask.sum()) < 20:
                continue
            signature = np.packbits(mask).tobytes()
            if signature in used:
                continue
            used.add(signature)
            entries.append({"spec": {"minCapUSD": lower, "maxCapUSD": upper if np.isfinite(upper) else None,
                                     "filter": name}, "mask": mask})
    exits = [SecondExit(hold=h) for h in (5, 10, 15, 30, 45, 60, 90, 120, 180)]
    exits += [SecondExit(hold=h, stop=s) for h in (15, 30, 60, 120, 180) for s in (.1, .25, .5)]
    exits += [SecondExit(hold=h, stop=s, target=t) for h in (60, 180)
              for s in (.1, .25, .5) for t in (1.1, 1.2, 1.5, 2., 3.)]
    exits += [SecondExit(hold=h, trail_at=t, trail_gap=g) for h in (60, 180)
              for t, g in ((1.1, .1), (1.2, .2), (1.5, .2), (1.5, .3), (2., .3))]
    assert entries and all(not (entry["mask"] & a["bot"]).any() for entry in entries)
    return entries, exits


def replay_selected(dataset, data, entries, exits, leaders, cost, omitted_assets=(), omitted_days=(),
                    size_scale=1., daily_budget=.04):
    a = dataset.arrays
    cutoffs = [1792281600000, 1792368000000, 1792454400000]
    keys = np.array([call["assetKey"] for call in dataset.meta["calls"]])
    state, ledger, drawdown = None, [], 0.
    cached = {}
    for cutoff, leader in zip(cutoffs, leaders[:3]):
        if leader is None:
            continue
        delay, exit_id, entry_id = leader["delay"], leader["exitId"], leader["entryId"]
        if delay not in cached:
            cached[delay] = paths(data, a["entry_time"] + delay * 1000, horizon=180)
        path = cached[delay]
        outcome = simulate_seconds(data, path, exits[exit_id])
        mask = entries[entry_id]["mask"] & ~np.isin(keys, omitted_assets)
        if omitted_days:
            mask &= ~np.isin(outcome["entry_time"] // DAY, omitted_days)
        result = portfolio(dataset, path, outcome, mask, fraction=leader["fraction"] * size_scale,
                           daily_budget=daily_budget, cost=cost, start=cutoff, end=cutoff + DAY,
                           initial_state=state, trace=True)
        state = result["state"]
        drawdown = min(drawdown, result["drawdownBound"])
        ledger.extend(result["ledger"])
    cash = state["cash"] if state else 100.
    verify_ledger(ledger, cash)
    assert all(not a["bot"][trade["index"]] for trade in ledger)
    return {"return": cash / 100 - 1, "drawdownBound": drawdown, "trades": len(ledger), "ledger": ledger}


def concentration(dataset, data, entries, exits, leaders):
    base = replay_selected(dataset, data, entries, exits, leaders, .1)
    assets, days = defaultdict(float), defaultdict(float)
    for trade in base["ledger"]:
        assets[trade["assetKey"]] += trade["pnl"]
        days[trade["entryTime"] // DAY] += trade["pnl"]
    best_assets = sorted(assets, key=lambda asset: (-assets[asset], asset))[:2]
    best_day = [max(days, key=lambda day: (days[day], -day))] if days else []
    return {"base": base,
            "withoutTwoBestTokens": replay_selected(dataset, data, entries, exits, leaders, .1, best_assets),
            "withoutBestDay": replay_selected(dataset, data, entries, exits, leaders, .1, omitted_days=best_day),
            "removedTokens": best_assets, "removedDays": best_day}


def robust_selection(dataset, data, directory, entries, exits):
    """Select using earlier account returns after both concentration removals."""
    a = dataset.arrays
    asset_keys = np.array([call["assetKey"] for call in dataset.meta["calls"]])
    cutoffs = [1792281600000, 1792368000000, 1792454400000]
    with (directory / "portfolios.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    leaders, diagnostics = [], []
    cached_paths, cached_outcomes = {}, {}
    for stage, cutoff in enumerate(cutoffs):
        choice, examined, passed = None, 0, 0
        for row in rows:
            if (int(row["stage"]) != stage or int(row["trades"]) < 8 or
                    float(row["return10pct"]) <= 0 or float(row["drawdown5pct"]) < -.05):
                continue
            delay, exit_id, entry_id = (int(row[key]) for key in ("delay", "exitId", "entryId"))
            fraction = float(row["fraction"])
            if delay not in cached_paths:
                cached_paths[delay] = paths(data, a["entry_time"] + delay * 1000, horizon=180)
            path = cached_paths[delay]
            outcome_key = delay, exit_id
            if outcome_key not in cached_outcomes:
                cached_outcomes[outcome_key] = simulate_seconds(data, path, exits[exit_id])
            outcome = cached_outcomes[outcome_key]
            mask = entries[entry_id]["mask"]
            base = portfolio(dataset, path, outcome, mask, fraction=fraction, cost=.1, end=cutoff, trace=True)
            if base["trades"] < 8 or base["contracts"] < 8:
                continue
            examined += 1
            assets, days = defaultdict(float), defaultdict(float)
            for trade in base["ledger"]:
                assets[trade["assetKey"]] += trade["pnl"]
                days[trade["entryTime"] // DAY] += trade["pnl"]
            best_assets = sorted(assets, key=lambda asset: (-assets[asset], asset))[:2]
            best_day = [max(days, key=lambda day: (days[day], -day))] if days else []
            without_assets = portfolio(dataset, path, outcome, mask & ~np.isin(asset_keys, best_assets),
                                       fraction=fraction, cost=.1, end=cutoff)
            without_day = portfolio(dataset, path, outcome,
                                    mask & ~np.isin(outcome["entry_time"] // DAY, best_day),
                                    fraction=fraction, cost=.1, end=cutoff)
            minimum = min(base["return"], without_assets["return"], without_day["return"])
            if minimum <= 0 or base["drawdownBound"] < -.03:
                continue
            passed += 1
            score = minimum + .25 * base["drawdownBound"]
            candidate = {"delay": delay, "exitId": exit_id, "entryId": entry_id, "fraction": fraction,
                         "entry": entries[entry_id]["spec"], "exit": asdict(exits[exit_id]),
                         "trainingReturn": base["return"], "trainingDrawdownBound": base["drawdownBound"],
                         "trainingMinimumAfterRemovals": minimum, "score": score}
            if choice is None or (score, base["return"]) > (choice["score"], choice["trainingReturn"]):
                choice = candidate
        leaders.append(choice)
        diagnostics.append({"stage": stage, "examined": examined, "passed": passed})
    daily = [replay_selected(dataset, data, entries, exits, leaders, cost) for cost in (.05, .1, .15)]
    return {"leaders": leaders, "training": diagnostics, "dailyReplay": daily,
            "concentration": concentration(dataset, data, entries, exits, leaders),
            "selection": "At least eight prior trades and contracts, positive 10% haircut account return after either two-best-token or best-day removal, at most 3% training drawdown bound; rank by the lowest return after removals minus one-quarter of drawdown."}


def sizing_sensitivity(dataset, data, entries, exits, procedures):
    rows = []
    for name, leaders in procedures.items():
        for scale in (0., .25, .5, 1.):
            for budget in (.01, .02, .04):
                outcome = replay_selected(dataset, data, entries, exits, leaders, .1,
                                          size_scale=scale, daily_budget=budget)
                rows.append({"procedure": name, "sizeScale": scale, "dailyBudget": budget,
                             **{key: outcome[key] for key in ("return", "drawdownBound", "trades")}})
    return rows


def bucket_sensitivity(dataset, data):
    a = dataset.arrays
    human = ~a["bot"]
    path = paths(data, a["entry_time"] + 5_000, horizon=180)
    rows = []
    ranges = list(zip(CAP_EDGES[:-1], CAP_EDGES[1:]))
    ranges += [(0, 6_000), (0, 10_000), (1_000_000, float("inf"))]
    for hold in (15, 30, 60, 180):
        outcome = simulate_seconds(data, path, SecondExit(hold=hold))
        for lower, upper in ranges:
            mask = human & (a["cap"] >= lower) & (a["cap"] < upper)
            replay = portfolio(dataset, path, outcome, mask, fraction=.01, cost=.1, daily_budget=.04)
            rows.append({"minCapUSD": lower, "maxCapUSD": upper if np.isfinite(upper) else None,
                         "holdSeconds": hold, "humanCalls": int(mask.sum()),
                         **{key: replay[key] for key in
                            ("return", "drawdownBound", "trades", "writeoffs", "wins")}})
    return rows


def ranking(dataset, history):
    a = dataset.arrays
    latest = int(np.max(a["day"]))
    representatives = {}
    for i in np.flatnonzero((~a["bot"]) & (a["day"] == latest)):
        actor = int(a["author"][i])
        if actor not in representatives or a["posted"][i] > a["posted"][representatives[actor]]:
            representatives[actor] = i
    rows = [{"authorKey": dataset.meta["authors"][actor], "priorTokens": int(history["count"][i]),
             "mean": float(history["mean"][i]), "withoutBest": float(history["robustMean"][i])}
            for actor, i in representatives.items() if history["count"][i] >= 5]
    rows.sort(key=lambda row: row["withoutBest"], reverse=True)
    for number, row in enumerate(rows, 1):
        row["publicLabel"] = f"Caller {number:02d}"
    return rows


def report(directory, result):
    def cap_label(value):
        return "∞" if value is None else f"${value:,.0f}"

    search_result = result["search"]
    daily = "".join(f"<tr><td>{row['cost']:.0%}</td><td>{row['return']:+.2%}</td>"
                    f"<td>{abs(row['drawdownBound']):.2%}</td><td>{row['trades']}</td></tr>"
                    for row in search_result["dailyReplay"])
    stress = "".join(f"<tr><td>{label}</td><td>{row['return']:+.2%}</td>"
                     f"<td>{abs(row['drawdownBound']):.2%}</td><td>{row['trades']}</td></tr>"
                     for label, row in (("Unchanged", result["concentration"]["base"]),
                                        ("Remove two best tokens", result["concentration"]["withoutTwoBestTokens"]),
                                        ("Remove best entry day", result["concentration"]["withoutBestDay"])))
    guarded = "".join(f"<tr><td>{cost:.0%}</td><td>{row['return']:+.2%}</td>"
                      f"<td>{abs(row['drawdownBound']):.2%}</td><td>{row['trades']}</td></tr>"
                      for cost, row in zip((.05, .1, .15), result["robustSelection"]["dailyReplay"]))
    buckets = "".join(f"<tr><td>{cap_label(row['minCapUSD'])}–{cap_label(row['maxCapUSD'])}</td>"
                      f"<td>{row['humanCalls']}</td><td>{row['return']:+.2%}</td>"
                      f"<td>{abs(row['drawdownBound']):.2%}</td><td>{row['trades']}</td>"
                      f"<td>{row['writeoffs']}</td></tr>"
                      for row in result["bucketSensitivity"] if row["holdSeconds"] == 30)
    sizes = "".join(f"<tr><td>{row['procedure']}</td><td>{row['sizeScale']:.2f}×</td>"
                    f"<td>{row['dailyBudget']:.0%}</td><td>{row['return']:+.2%}</td>"
                    f"<td>{abs(row['drawdownBound']):.2%}</td><td>{row['trades']}</td></tr>"
                    for row in result["sizingSensitivity"] if row["dailyBudget"] == .01)
    decider = result.get("decider")
    decider_section = ""
    if decider:
        decider_section = (f"<h2>Human-only Decider check</h2><p>{decider['queried']} human calls received "
                           f"fresh market-only model scores. Among {decider['laterCases']} later-period combinations, "
                           f"{decider['laterProfitable']} had a positive account return. "
                           f"<a href=\"../../{html.escape(decider['report'])}\">Detailed gates, sizes and exits</a>.</p>")
    fixed = result.get("fixedControl")
    fixed_section = ""
    if fixed:
        best = max(fixed["summaries"], key=lambda row: row["minimumReturn"])
        fixed_section = (f"<h2>Inherited fixed-rule sensitivity</h2>"
                         f"<p>An earlier fixed 3× target with a five-minute limit was replayed using only human "
                         f"entry calls and earlier human reference calls. Its best of four post hoc reference and "
                         f"size variants returned at least {best['minimumReturn']:+.2%} across "
                         f"{fixed['scenarios']} saved execution scenarios and two human-entry populations, with "
                         f"at least {best['minimumTrades']} trades. Its worst return after removing the two best "
                         f"tokens was {best['minimumWithoutTwoBest']:+.2%}; after removing the best entry day, "
                         f"{best['minimumWithoutBestDay']:+.2%}. The entry settings came from an earlier "
                         f"broader historical search, so this control is not a fresh human-only fit or independent "
                         f"validation. <a href=\"../../{html.escape(fixed['report'])}\">All four variants and "
                         f"scenario results</a>.</p>")
    callers = "".join(f"<tr><td>{row['publicLabel']}</td><td>{row['priorTokens']}</td>"
                      f"<td>{row['mean']:+.2%}</td><td>{row['withoutBest']:+.2%}</td></tr>"
                      for row in result["callerRanking"])
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Optimal strategy for trading on telegram group calls</title><style>
body{{font:16px/1.65 system-ui;margin:40px auto;max-width:1150px;padding:0 24px;color:#172231;background:#fff}}
h1,h2{{line-height:1.2}}h1{{font-size:2.2rem}}.note{{border-left:4px solid #c99221;background:#fff8e8;padding:16px 22px}}
table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #d6dfe9}}
th{{background:#eef3f8}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6fa;padding:16px}}
a{{color:#1459ac}}.scroll{{overflow-x:auto}}li{{margin:7px 0}}</style>
<h1>Optimal strategy for trading on telegram group calls</h1>
<h2>Scope of analysis</h2>
<p>One unnamed Telegram group, October 16–21, 2026. The primary refit uses {result['humanCalls']} human-authored
calls among {result['allCalls']} saved eligible calls. Automated posts and scanner replies are excluded from
its entry signals, caller history, training and account replays. Prices come from saved one-second market data.
An inherited fixed-rule control also restricts entries and reference histories to human calls, but uses settings
selected in earlier research. All results are retrospective simulations, and no live return is measured.</p>
<p>The search compares {search_result['entries']} distinct human-only entry masks, including market-cap bands below
$6k and $10k and above $1m, chain, quote freshness, token age and earlier caller outcomes. It tests
{len(search_result['delays'])} entry delays from one to sixty seconds and {search_result['exits']} exit rules,
including 5–180-second holds, fixed stops, 1.1×–3× targets and trailing exits. Position sizes of 1%, 2% and 5%
are evaluated on shortlisted policies. The full screen covers {search_result['combinations']:,} combinations.</p>
<div class="note"><strong>Interpretation:</strong> Selection and evaluation reuse dates already examined in prior
research. The separately frozen later windows have produced no qualifying trades. The figures below do not establish
an independently validated profitable strategy.</div>
<h2>Retrospective daily selection</h2>
<p>Each day chooses from earlier completed outcomes. Proceeds haircuts apply to every sale; drawdown uses observed
one-second price lows while a position is open. A missing entry fill is skipped; a missing exit fill is written to zero.
The same selection procedure is replayed under three haircut levels.</p>
<div class="scroll"><table><tr><th>Sale haircut</th><th>Return</th><th>Drawdown bound</th><th>Trades</th></tr>{daily}</table></div>
<h2>Concentration check at a 10% sale haircut</h2>
<p>Removing winners replays admissions, cash and position sizing. It does not subtract their PnL from a fixed ledger.</p>
<div class="scroll"><table><tr><th>Account replay</th><th>Return</th><th>Drawdown bound</th><th>Trades</th></tr>{stress}</table></div>
<h2>Selection guarded by earlier concentration checks</h2>
<p>This second procedure requires earlier account returns to stay positive after removing the two best tokens
or best entry day and limits earlier drawdown to 3%. When no candidate passes, it holds cash.</p>
<div class="scroll"><table><tr><th>Sale haircut</th><th>Return</th><th>Drawdown bound</th><th>Trades</th></tr>{guarded}</table></div>
{fixed_section}
<h2>Cap buckets and position size</h2>
<p>Each cap row uses every eligible human call in that bucket, a five-second entry delay, a 30-second hold,
a 1% base allocation, a 4% daily loss budget and a 10% sale haircut. These are full-sample descriptions,
not selected forward policies. A missing sale is written down to zero.</p>
<div class="scroll"><table><tr><th>Market cap</th><th>Human calls</th><th>Return</th><th>Drawdown bound</th><th>Trades</th><th>Missing sales</th></tr>{buckets}</table></div>
<p>The next rows resize the two daily selection procedures at a 1% daily loss budget and 10% sale haircut.
The full saved size grid also includes 2% and 4% budgets.</p>
<div class="scroll"><table><tr><th>Selection</th><th>Size</th><th>Daily budget</th><th>Return</th><th>Drawdown bound</th><th>Trades</th></tr>{sizes}</table></div>
{decider_section}
<h2>Historical caller ranking</h2>
<p>Anonymous labels rank human authors with at least five prior distinct tokens at the final day's start.
Outcomes use a three-minute observed exit, a 10% haircut, and shrinkage toward earlier peer returns. The
last column removes each caller's best prior outcome. These are returns after calls, not members' own PnL.</p>
<div class="scroll"><table><tr><th>Caller</th><th>Prior tokens</th><th>Shrunken mean</th><th>Mean without best</th></tr>{callers}</table></div>
<h2>Limits and files</h2>
<p>This is a searched historical sample. Profit is sensitive to execution assumptions, scarce independent
trades and concentration. Recorded bars do not establish executable size, price impact, transaction success,
gas or MEV. Public artifacts use anonymous caller labels.</p>
<p><a href="results.json">Results and ledgers</a> · <a href="settings.json">Settings and input hashes</a> ·
<a href="catalog.json">Entry and exit catalog</a> · <a href="portfolios.csv">Shortlist evaluations</a> ·
<a href="baseline_horizons.csv">Human-only hold baselines</a> · <a href="../../human_only_lab.py">Replay code</a></p></html>"""
    (directory / "report.html").write_text(page)
    (directory / "report.html").chmod(0o600)


def main():
    source = Path(read(ROOT / "repeat_call_datasets/latest.json")["path"])
    dataset = load_repeat_dataset(source)
    data = load_repeat_seconds(dataset)
    history = caller_history(dataset, data)
    entries, exits = catalog(dataset, history)
    settings = {"sourceDataset": str(source), "datasetManifestSha256": sha256(source / "manifest.json"),
                "secondResponseSetSha256": data["audit"]["responseSetSha256"],
                "codeHashes": {name: sha256(ROOT / name) for name in
                               ("human_only_lab.py", "second_lab.py", "second_engine.py", "repeat_call_dataset.py")},
                "definition": "Only Telegram messages whose saved authorIsBot flag is false can enter, train a caller score, or appear in an account replay.",
                "callCount": dataset.n, "humanCalls": int((~dataset.arrays["bot"]).sum()),
                "entryMasks": len(entries), "exitRules": len(exits), "entryDelaysSeconds": list(DELAYS),
                "saleHaircuts": [.05, .1, .15], "minimumTrainingCalls": 20,
                "concentration": ["two_best_tokens", "best_entry_day"]}
    identity = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]
    directory = ROOT / "human_only_runs" / identity
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory / "settings.json", settings)
    result = search(dataset, data, directory, entry_catalog=lambda _: (entries, exits),
                    baseline_mask=~dataset.arrays["bot"])
    stress = concentration(dataset, data, entries, exits, result["leaders"])
    guarded = robust_selection(dataset, data, directory, entries, exits)
    sizing = sizing_sensitivity(dataset, data, entries, exits,
                                {"mean-screen": result["leaders"], "concentration-guarded": guarded["leaders"]})
    buckets = bucket_sensitivity(dataset, data)
    decider = None
    decider_pointer = ROOT / "human_decider_runs/latest.json"
    if decider_pointer.exists():
        decider_directory = Path(read(decider_pointer)["path"])
        decider_results = read(decider_directory / "results.json")
        later = [row for row in decider_results["rows"] if row["period"] == "later"]
        decider = {"report": (decider_directory / "report.html").relative_to(ROOT).as_posix(),
                   "queried": decider_results["humanResponses"], "laterCases": len(later),
                   "laterProfitable": sum(row["return"] > 0 for row in later)}
    fixed = None
    fixed_pointer = ROOT / "human_fixed_control_runs/latest.json"
    if fixed_pointer.exists():
        fixed_directory = Path(read(fixed_pointer)["path"])
        fixed_results = read(fixed_directory / "results.json")
        fixed = {"report": (fixed_directory / "report.html").relative_to(ROOT).as_posix(),
                 "scenarios": fixed_results["scenarios"], "summaries": fixed_results["summaries"]}
    for row in result["dailyReplay"]:
        assert all(not dataset.arrays["bot"][trade["index"]] for trade in row["ledger"])
    output = {"path": str(directory), "settingsSha256": sha256(directory / "settings.json"),
              "allCalls": dataset.n, "humanCalls": int((~dataset.arrays["bot"]).sum()),
              "humanKnownTextCalls": int(((~dataset.arrays["bot"]) & dataset.arrays["message_known"]).sum()),
              "callerHistory": history["reference"], "callerRanking": ranking(dataset, history),
              "search": result, "concentration": stress, "robustSelection": guarded,
              "sizingSensitivity": sizing, "bucketSensitivity": buckets, "decider": decider,
              "fixedControl": fixed,
              "scope": "Retrospective human-authored calls only. Prior research examined these dates; no independent profitability claim."}
    write_json(directory / "results.json", output)
    report(directory, output)
    write_json(ROOT / "human_only_runs/latest.json", {"path": str(directory)})
    print(json.dumps({"path": str(directory), "humanCalls": output["humanCalls"],
                      "combinations": result["combinations"], "daily10pct": result["dailyReplay"][1]["return"],
                      "guarded10pct": guarded["dailyReplay"][1]["return"],
                      "concentration": {key: stress[key]["return"] for key in
                                        ("base", "withoutTwoBestTokens", "withoutBestDay")}}))


if __name__ == "__main__":
    main()
