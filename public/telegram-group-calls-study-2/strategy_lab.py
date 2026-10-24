"""Reproduce human-call strategy comparisons from frozen quotes and one-second bars."""

import csv
import hashlib
import html
import json
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path

import numpy as np

from research_dataset import DAY, load_dataset, sha256, stamp, write_json
from second_engine import SecondExit, load_seconds, paths, portfolio, simulate_seconds
from trade_flow_lab import view as flow_view


ROOT = Path(__file__).resolve().parent
CUTOFF = stamp("2026-10-01T00:00:00Z")
DELAYS = (1, 5, 15, 30)
HOLDS = (5, 10, 15, 30, 45, 60, 90, 120, 180)
CAP_EDGES = (0, 6_000, 10_000, 25_000, 50_000, 100_000, 250_000, 1_000_000, float("inf"))


def load():
    dataset_id = json.loads((ROOT / "datasets/latest.json").read_text())["datasetId"]
    dataset = load_dataset(str(ROOT / "datasets" / dataset_id))
    pointer = dataset.path / "trade_flow/features_latest.json"
    if not pointer.exists():
        return dataset, load_seconds(dataset), None, None
    directory = Path(json.loads(pointer.read_text())["path"])
    with np.load(directory / "features.npz", allow_pickle=False) as saved:
        flow = saved["values"]
    return dataset, load_seconds(dataset), flow, json.loads((directory / "features.json").read_text())


def rules():
    items = [(f"hold_{seconds}s", SecondExit(hold=seconds)) for seconds in HOLDS]
    for hold in (60, 120, 180):
        items.extend((f"target_{target:g}x_{hold}s", SecondExit(hold=hold, target=target))
                     for target in (1.1, 1.25, 1.5, 2., 3.))
        items.extend((f"stop_{stop:g}_{hold}s", SecondExit(hold=hold, stop=stop))
                     for stop in (.1, .25, .5))
    for hold in (120, 180):
        items.extend((f"stop_{stop:g}_target_{target:g}x_{hold}s",
                      SecondExit(hold=hold, stop=stop, target=target))
                     for stop in (.25, .5) for target in (1.25, 1.5, 2., 3.))
        items.extend((f"trail_{at:g}_{gap:g}_{hold}s",
                      SecondExit(hold=hold, trail_at=at, trail_gap=gap))
                     for at, gap in ((1.2, .2), (1.5, .3), (2., .3)))
    return items


def masks(dataset, train, flow=None):
    a = dataset.arrays
    cap = a["cap"]
    items = {"all human calls": np.ones(dataset.n, bool)}
    for lower, upper in zip(CAP_EDGES[:-1], CAP_EDGES[1:]):
        label = f"cap ${lower:,.0f}–${upper:,.0f}" if np.isfinite(upper) else "cap $1m+"
        items[label] = (cap >= lower) & (cap < upper)
    for edge in (6_000, 10_000, 25_000, 50_000, 100_000, 250_000, 1_000_000):
        items[f"cap under ${edge:,.0f}"] = cap < edge
        items[f"cap at least ${edge:,.0f}"] = cap >= edge
    for seconds in (1, 5, 10):
        items[f"quote age ≤{seconds}s"] = a["quote_age"] <= seconds
    items["direct post"] = ~a["forwarded"]
    chains = np.array([call["chainId"] for call in dataset.meta["calls"]])
    items["Solana"] = chains == "solana:solana"
    items["EVM"] = chains != "solana:solana"
    chain_names = {"evm:4663": "Robinhood Chain", "evm:56": "BSC", "evm:5042": "Arc",
                   "evm:1": "Ethereum", "evm:8453": "Base"}
    for chain, name in chain_names.items():
        if int(((chains == chain) & train).sum()) >= 8:
            items[name] = chains == chain
    if flow is not None:
        recent = flow_view(flow, 5, 60)
        for field, label, edges in (
                ("economic_volume_usd", "pre-call volume", (100, 500, 1000, 3000, 10000)),
                ("swap_count", "pre-call swaps", (5, 15, 40)),
                ("wallet_count", "pre-call wallets", (5, 10, 25)),
                ("volume_to_cap", "volume/cap", (.01, .05, .1))):
            for edge in edges:
                items[f"{label} ≥{edge:g}"] = recent[field] >= edge
        items["last pre-call swap ≤10s"] = recent["last_trade_age_seconds"] <= 10
        items["pre-call buy share ≥50%"] = recent["buy_volume_share"] >= .5
        items["pre-call wallet concentration ≤20%"] = recent["wallet_hhi"] <= .2
    counts = Counter(int(author) for author in a["author"][train])
    ranked = sorted({int(author) for author in a["author"]},
                    key=lambda author: (-counts[author], author))
    aliases = {author: f"Caller {rank:02d}" for rank, author in enumerate(ranked, 1)}
    for author in ranked:
        if counts[author] >= 8:
            items[aliases[author]] = a["author"] == author
    return items, aliases


def cross_section(outcome, mask, cost):
    valid = mask & np.isfinite(outcome["gross"])
    net = np.clip(outcome["gross"][valid] * (1 - cost) - 1, -1, 2)
    return {"calls": int(mask.sum()), "scorable": int(valid.sum()),
            "meanReturn": float(np.mean(net)) if len(net) else None,
            "medianReturn": float(np.median(net)) if len(net) else None,
            "positiveShare": float(np.mean(net > 0)) if len(net) else None,
            "writeoffs": int((outcome["gross"][valid] == 0).sum())}


def account(dataset, path, outcome, mask, cost, factor=None, excluded=()):
    if excluded:
        assets = np.array([call["assetKey"] for call in dataset.meta["calls"]])
        mask = mask & ~np.isin(assets, excluded)
    replay = portfolio(dataset, path, outcome, mask, fraction=.01, factor=factor,
                       cost=cost, daily_budget=.04, trace=True)
    return {"return": replay["return"], "drawdownBound": replay["drawdownBound"],
            "trades": replay["trades"], "wins": replay["wins"],
            "writeoffs": replay["writeoffs"],
            "totalStake": sum(trade["positionSize"] for trade in replay["ledger"]),
            "ledger": replay["ledger"]}


def public_account(replay):
    return {key: replay[key] for key in ("return", "drawdownBound", "trades", "wins", "writeoffs", "totalStake")}


def score_history(dataset, outcome):
    a = dataset.arrays
    first = []
    seen = set()
    for index in np.argsort(a["posted"], kind="stable"):
        asset = int(a["asset"][index])
        if asset not in seen:
            seen.add(asset)
            first.append(index)
    finish = np.maximum(outcome["exit_time"], outcome["admit_end"])
    score = np.full(dataset.n, np.nan)
    count = np.zeros(dataset.n, dtype=np.int16)
    for index in range(dataset.n):
        earlier = [prior for prior in first if int(a["asset"][prior]) != int(a["asset"][index])
                   and np.isfinite(outcome["gross"][prior])
                   and finish[prior] < a["entry_time"][index]]
        earlier.sort(key=lambda prior: (finish[prior], prior))
        earlier = earlier[-10:]
        count[index] = len(earlier)
        if len(earlier) >= 5:
            score[index] = float(np.mean(np.clip(outcome["gross"][earlier] - 1, -1, 1)))
    return count, score


def save_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    path.chmod(0o600)


def report(directory, result):
    def pct(value):
        return "—" if value is None else f"{value:+.2%}"

    baseline = "".join(
        f"<tr><td>{row['holdSeconds']}s</td><td>{row['earlier']['scorable']}</td>"
        f"<td>{row['later']['scorable']}</td><td>{pct(row['laterZero']['meanReturn'])}</td>"
        f"<td>{pct(row['later']['meanReturn'])}</td><td>{pct(row['laterZeroAccount']['return'])}</td>"
        f"<td>{pct(row['laterAccount']['return'])}</td></tr>"
        for row in result["baseline"])
    buckets = "".join(
        f"<tr><td>{html.escape(row['label'])}</td><td>{row['earlier']['scorable']}</td>"
        f"<td>{pct(row['earlier']['meanReturn'])}</td><td>{row['later']['scorable']}</td>"
        f"<td>{pct(row['later']['meanReturn'])}</td><td>{row['later']['writeoffs']}</td></tr>"
        for row in result["capBuckets"])
    chains = "".join(
        f"<tr><td>{html.escape(row['label'])}</td><td>{row['earlier']['scorable']}</td>"
        f"<td>{pct(row['earlier']['meanReturn'])}</td><td>{row['later']['scorable']}</td>"
        f"<td>{pct(row['later']['meanReturn'])}</td></tr>"
        for row in result["chains"])
    callers = "".join(
        f"<tr><td>{row['alias']}</td><td>{row['earlier']['scorable']}</td>"
        f"<td>{pct(row['earlier']['meanReturn'])}</td><td>{row['later']['scorable']}</td>"
        f"<td>{pct(row['later']['meanReturn'])}</td><td>{pct(row['laterAccount']['return'])}</td></tr>"
        for row in result["callers"])
    flow_rows = "".join(
        f"<tr><td>{html.escape(row['label'])}</td><td>{row['earlier']['scorable']}</td>"
        f"<td>{pct(row['earlier']['meanReturn'])}</td><td>{row['later']['scorable']}</td>"
        f"<td>{pct(row['later']['meanReturn'])}</td></tr>"
        for row in result["flowFilters"])
    sizes = "".join(
        f"<tr><td>{html.escape(row['name'])}</td><td>{pct(row['laterZero']['return'])}</td>"
        f"<td>{pct(row['laterTen']['return'])}</td><td>{abs(row['laterTen']['drawdownBound']):.2%}</td>"
        f"<td>{row['laterTen']['totalStake']:.2f}</td><td>{row['laterTen']['trades']}</td></tr>"
        for row in result["recentSizing"])
    selected = result["trainingChoice"]
    probe = result["topTrainingCandidate"]
    choice_text = "cash" if selected is None else html.escape(selected["label"])
    top_text = (f"{html.escape(probe['mask'])}, {probe['delaySeconds']}s delay, "
                f"{html.escape(probe['exit'])}") if probe else "none"
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Optimal strategy for trading on Telegram group calls</title><style>
body{{font:16px/1.6 system-ui;max-width:1150px;margin:40px auto;padding:0 24px;color:#172231}}
h1,h2{{line-height:1.25}}table{{border-collapse:collapse;width:100%}}td,th{{padding:9px 11px;text-align:left;border-bottom:1px solid #d6dfe9}}
th{{background:#eef3f8}}.scroll{{overflow-x:auto}}a{{color:#1459ac}}</style>
<h1>Optimal strategy for trading on Telegram group calls</h1>
<h2>Scope</h2>
<p>Accessible history: August 22–October 23, 2026. The archive contains {result['scope']['messages']:,} messages;
{result['scope']['tokenMessages']:,} mention a token, ticker or token link. Of those,
{result['scope']['humanTokenMessages']} came from non-bot user accounts. Mobula identified
{result['scope']['candidateTokens']} candidate tokens and {result['scope']['marketCalls']} human call signals.
Another {result['scope']['unresolvedHumanTokenMessages']} human token-related messages had no unique contract
identity, mainly ticker-only or multi-address posts.
The execution study uses {result['scope']['eligibleCalls']} first sender-token calls with a fresh historical quote,
market cap and saved price series. Later repeats by the same sender about the same token are counted but not
treated as new entries. With a five-second entry delay, {result['scope']['scorable60']} calls have the
observations needed for a 60-second sale.</p>
<p>The comparison uses August–September to select a rule and October as a later replay. Calls overlap in time,
so the account holds at most one position and never buys the same token twice. Entry and sale need an observed
one-second print within ten seconds. A missing sale is a writeoff. Trade size starts at 1% of a $100 account,
with a 4% daily full-loss budget. The 10% sale haircut is a stress assumption, not a measured fee.</p>
<h2>Fixed holds, all human calls</h2>
<p>Five-second entry delay. Mean call returns are clipped to −100%/+200% for this descriptive table.
Account return uses the observed exit price without clipping.</p>
<div class="scroll"><table><tr><th>Hold</th><th>Earlier scorable</th>
<th>October scorable</th><th>October mean, 0%</th><th>October mean, 10%</th>
<th>October account, 0%</th><th>October account, 10%</th></tr>{baseline}</table></div>
<h2>Market cap</h2>
<p>Same five-second entry and 60-second hold, with a 10% sale haircut. These are descriptive buckets;
the groups are too small to treat the highest row as a validated filter.</p>
<div class="scroll"><table><tr><th>Call-time cap</th><th>Earlier calls</th><th>Earlier mean</th>
<th>October calls</th><th>October mean</th><th>October writeoffs</th></tr>{buckets}</table></div>
<h2>Chain</h2>
<p>Same five-second entry and 60-second hold, with a 10% sale haircut.</p>
<div class="scroll"><table><tr><th>Chain</th><th>Earlier calls</th><th>Earlier mean</th>
<th>October calls</th><th>October mean</th></tr>{chains}</table></div>
<h2>Caller comparison</h2>
<p>Aliases hide identities. The same fixed 60-second rule applies to each caller. Rows require at least
five scorable calls across the archive; later outcomes did not affect which aliases entered the strategy grid.</p>
<div class="scroll"><table><tr><th>Caller</th><th>Earlier calls</th><th>Earlier mean</th>
<th>October calls</th><th>October mean</th><th>October account</th></tr>{callers}</table></div>
<h2>Pre-call trade flow</h2>
<p>Only swaps completed at least five seconds before the post contribute. The fixed rule waits five seconds
and holds for 60 seconds; the table applies a 10% sale haircut. Volume is the net target-token value within
each transaction and recipient. It is a screening proxy, not guaranteed executable depth.</p>
<div class="scroll"><table><tr><th>Entry filter</th><th>Earlier calls</th><th>Earlier mean</th>
<th>October calls</th><th>October mean</th></tr>{flow_rows}</table></div>
<h2>Rule selection</h2>
<p>The grid compares {result['grid']['rules']} exit rules, {result['grid']['delays']} entry delays and
{result['grid']['entryMasks']} entry filters. It includes 5–180-second holds, 1.1–3× targets,
stops, trailing exits, call-time cap bands, chains, quote age, pre-call trade flow and callers with
at least eight earlier calls.
Training requires eight scorable calls on eight distinct tokens and ranks the 10%-haircut mean after
subtracting one estimated standard error. A rule is selected only if that score is positive.
Training selected <strong>{choice_text}</strong>. The highest training score belonged to {top_text}.</p>
<p>The top training candidate returned {pct(result['topEvaluation']['earlierTen']['return'])} on the earlier
account and {pct(result['topEvaluation']['laterTen']['return'])} on the October account at the 10% haircut.
At zero haircut those returns were {pct(result['topEvaluation']['earlierZero']['return'])} and
{pct(result['topEvaluation']['laterZero']['return'])}. Removing October's two best token trades changes its
October return to {pct(result['topEvaluation']['laterWithoutTwoBestZero']['return'])} at zero haircut and
{pct(result['topEvaluation']['laterWithoutTwoBest']['return'])} with a 10% haircut.
The candidate was chosen from many correlated rules; October is the useful comparison here.</p>
<p>The October replay is sensitive to a small number of trades. Its measured no-haircut gain is small,
while the cost stress and the two-winner check both turn it negative. Cash had no simulated drawdown;
the selected rule's October drawdown bound was
{abs(result['topEvaluation']['laterZero']['drawdownBound']):.2%} at zero haircut and
{abs(result['topEvaluation']['laterTen']['drawdownBound']):.2%} with the haircut.</p>
<h2>Recent group performance and position size</h2>
<p>This fixed 60-second rule uses the last ten completed outcomes on other tokens, at least five observations,
and a score frozen before each call's first quote. A positive slope raises size after better prior outcomes;
a reversal slope raises it after worse outcomes. Factors are capped between 0.5× and 1.5×.
The table uses October calls and a five-second entry delay.</p>
<div class="scroll"><table><tr><th>Size rule</th><th>Return, 0%</th><th>Return, 10%</th>
<th>Drawdown bound, 10%</th><th>Stake, 10%</th><th>Trades</th></tr>{sizes}</table></div>
<p>These results use a short archive and sparse one-second observations. Only calls with fresh quotes enter
the execution study, so its outcomes may differ from the full message archive. Missing exit prints are penalized;
price prints do not establish fill capacity or account for gas and price impact. The full grid was searched
only on the earlier period. Individual bucket and caller tables describe small samples.</p>
<p><a href="results.json">Summary and policy definitions</a> · <a href="training_grid.csv">Training grid</a> ·
<a href="../../strategy_lab.py">Replay code</a></p></html>"""
    path = directory / "report.html"
    path.write_text(page)
    path.chmod(0o600)


def main():
    dataset, data, flow, flow_info = load()
    a = dataset.arrays
    assert not a["bot"].any()
    earlier, later = a["posted"] < CUTOFF, a["posted"] >= CUTOFF
    entry_masks, aliases = masks(dataset, earlier, flow)
    exit_rules = rules()
    settings = {"datasetManifestSha256": sha256(dataset.path / "manifest.json"),
                "secondResponseSetSha256": data["audit"]["responseSetSha256"],
                "flowResponseSetSha256": flow_info["coverage"]["responseSetSha256"] if flow_info else None,
                "codeSha256": sha256(Path(__file__)), "cutoffUTC": "2026-10-01T00:00:00Z",
                "delaysSeconds": DELAYS, "exits": {name: asdict(rule) for name, rule in exit_rules},
                "entryFilters": list(entry_masks), "scoring": "training mean 10%-cost clipped return minus standard error; minimum eight scorable calls and distinct tokens; select only positive score",
                "account": {"initialUSD": 100, "fraction": .01, "dailyFullLossBudget": .04,
                            "maxWaitSeconds": 10, "saleHaircuts": [0, .1]}}
    identity = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]
    directory = ROOT / "strategy_runs" / identity
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory / "settings.json", settings)
    write_json(ROOT / "strategy_runs/latest.json", {"path": str(directory)})

    all_mask = entry_masks["all human calls"]
    path5 = paths(data, a["entry_time"] + 5_000, horizon=180)
    baseline = []
    for hold in HOLDS:
        outcome = simulate_seconds(data, path5, SecondExit(hold=hold))
        baseline.append({"holdSeconds": hold,
                         "earlier": cross_section(outcome, earlier, .1),
                         "later": cross_section(outcome, later, .1),
                         "earlierZero": cross_section(outcome, earlier, 0.),
                         "laterZero": cross_section(outcome, later, 0.),
                         "laterAccount": public_account(account(dataset, path5, outcome, later, .1)),
                         "laterZeroAccount": public_account(account(dataset, path5, outcome, later, 0.))})
    reference = simulate_seconds(data, path5, SecondExit(hold=60))
    buckets = []
    for lower, upper in zip(CAP_EDGES[:-1], CAP_EDGES[1:]):
        label = f"${lower:,.0f}–${upper:,.0f}" if np.isfinite(upper) else "$1m+"
        mask = (a["cap"] >= lower) & (a["cap"] < upper)
        buckets.append({"label": label, "earlier": cross_section(reference, mask & earlier, .1),
                        "later": cross_section(reference, mask & later, .1),
                        "laterZero": cross_section(reference, mask & later, 0.)})
    chains = []
    chain_names = {"solana:solana": "Solana", "evm:4663": "Robinhood Chain",
                   "evm:56": "BSC", "evm:5042": "Arc", "evm:1": "Ethereum",
                   "evm:8453": "Base"}
    chain_values = np.array([call["chainId"] for call in dataset.meta["calls"]])
    main_chains = [chain for chain in chain_names if int((chain_values == chain).sum()) >= 3]
    chain_groups = [(chain_names[chain], chain_values == chain) for chain in main_chains]
    other = ~np.isin(chain_values, main_chains)
    if other.any():
        chain_groups.append(("Other EVM chains", other))
    for label, mask in chain_groups:
        chains.append({"label": label,
                       "earlier": cross_section(reference, mask & earlier, .1),
                       "later": cross_section(reference, mask & later, .1),
                       "laterZero": cross_section(reference, mask & later, 0.)})
    flow_rows = []
    for name, mask in entry_masks.items():
        if name.startswith(("pre-call", "volume/cap", "last pre-call")):
            flow_rows.append({"label": name, "earlier": cross_section(reference, mask & earlier, .1),
                              "later": cross_section(reference, mask & later, .1)})

    ranked_authors = sorted(aliases, key=lambda author: (-int((a["author"] == author).sum()), author))
    callers = []
    private = []
    for author in ranked_authors:
        mask = a["author"] == author
        past = cross_section(reference, mask & earlier, .1)
        future = cross_section(reference, mask & later, .1)
        private.append({"alias": aliases[author], "key": dataset.meta["authors"][author]})
        if past["scorable"] + future["scorable"] < 5:
            continue
        callers.append({"alias": aliases[author], "earlier": past, "later": future,
                        "earlierZero": cross_section(reference, mask & earlier, 0.),
                        "laterZero": cross_section(reference, mask & later, 0.),
                        "laterAccount": public_account(account(dataset, path5, reference, mask & later, .1))})
    callers.sort(key=lambda row: (row["earlier"]["meanReturn"] if row["earlier"]["scorable"] >= 5 else -2,
                                  row["earlier"]["scorable"]), reverse=True)
    write_json(directory / "caller_map_private.json", private)

    training_grid = []
    top = None
    candidate_masks = {name: mask for name, mask in entry_masks.items()
                       if int((mask & earlier).sum()) >= 8}
    for delay in DELAYS:
        path = paths(data, a["entry_time"] + delay * 1000, horizon=180)
        for exit_name, rule in exit_rules:
            outcome = simulate_seconds(data, path, rule)
            gross = outcome["gross"]
            for mask_name, mask in candidate_masks.items():
                selected = mask & earlier & np.isfinite(gross)
                indices = np.flatnonzero(selected)
                if len(indices) < 8 or len(np.unique(a["asset"][indices])) < 8:
                    continue
                net = np.clip(gross[indices] * .9 - 1, -1, 2)
                mean = float(np.mean(net))
                stderr = float(np.std(net, ddof=1) / np.sqrt(len(net)))
                score = mean - stderr
                row = {"mask": mask_name, "delaySeconds": delay, "exit": exit_name,
                       "trainingCalls": len(indices), "trainingTokens": len(np.unique(a["asset"][indices])),
                       "meanNet10": mean, "standardError": stderr, "score": score,
                       "trainingWriteoffs": int((gross[indices] == 0).sum())}
                training_grid.append(row)
                if top is None or (score, len(indices), mask_name, exit_name) > (
                        top["score"], top["trainingCalls"], top["mask"], top["exit"]):
                    top = row
    assert training_grid and top is not None
    save_csv(directory / "training_grid.csv", training_grid)
    choices = {name: rule for name, rule in exit_rules}
    top_path = paths(data, a["entry_time"] + top["delaySeconds"] * 1000, horizon=180)
    top_outcome = simulate_seconds(data, top_path, choices[top["exit"]])
    top_mask = entry_masks[top["mask"]]
    past_zero = account(dataset, top_path, top_outcome, top_mask & earlier, 0.)
    past_ten = account(dataset, top_path, top_outcome, top_mask & earlier, .1)
    future_zero = account(dataset, top_path, top_outcome, top_mask & later, 0.)
    future_ten = account(dataset, top_path, top_outcome, top_mask & later, .1)
    by_token = defaultdict(float)
    for trade in future_ten["ledger"]:
        by_token[trade["assetKey"]] += trade["pnl"]
    winners = sorted(by_token, key=lambda asset: (-by_token[asset], asset))[:2]
    without_winners = account(dataset, top_path, top_outcome, top_mask & later, .1, excluded=winners)
    without_winners_zero = account(dataset, top_path, top_outcome, top_mask & later, 0., excluded=winners)
    top_evaluation = {"earlierZero": public_account(past_zero), "earlierTen": public_account(past_ten),
                      "laterZero": public_account(future_zero), "laterTen": public_account(future_ten),
                      "laterWithoutTwoBest": public_account(without_winners),
                      "laterWithoutTwoBestZero": public_account(without_winners_zero),
                      "earlierCalls": cross_section(top_outcome, top_mask & earlier, .1),
                      "laterCalls": cross_section(top_outcome, top_mask & later, .1)}
    write_json(directory / "top_ledger_private.json", {"earlier": past_ten["ledger"],
                                                       "later": future_ten["ledger"],
                                                       "removedTokenKeys": winners})

    count, recent_score = score_history(dataset, reference)
    sizing = []
    size_maps = {"flat 1×": np.ones(dataset.n),
                 "follow trend, slope 1": np.clip(1 + np.nan_to_num(recent_score), .5, 1.5),
                 "reversal, slope 0.5": np.clip(1 - .5 * np.nan_to_num(recent_score), .5, 1.5),
                 "reversal, slope 1": np.clip(1 - np.nan_to_num(recent_score), .5, 1.5),
                 "reversal, slope 2": np.clip(1 - 2 * np.nan_to_num(recent_score), .5, 1.5)}
    for name, factor in size_maps.items():
        sizing.append({"name": name,
                       "laterZero": public_account(account(dataset, path5, reference, later, 0., factor)),
                       "laterTen": public_account(account(dataset, path5, reference, later, .1, factor)),
                       "earlierTen": public_account(account(dataset, path5, reference, earlier, .1, factor))})

    source = json.loads((ROOT / "token_mentions_all.json").read_text())
    market = json.loads((ROOT / "mobula_data.json").read_text())
    human_mentions = json.loads((ROOT / "token_mentions.json").read_text())["tokenMessages"]
    covered_message_ids = {row["messageId"] for row in market["callSignals"]}
    scope = {"messages": source["totalMessages"], "tokenMessages": len(source["tokenMessages"]),
             "humanTokenMessages": len(human_mentions),
             "unresolvedHumanTokenMessages": sum(row["messageId"] not in covered_message_ids
                                                  for row in human_mentions),
             "candidateTokens": len(market["tokens"]), "marketCalls": len(market["callSignals"]),
             "eligibleCalls": dataset.n, "scorable60": cross_section(reference, all_mask, .1)["scorable"],
             "sameCallerTokenRepeats": dataset.meta["coverage"]["repeatedCallerContractSignals"],
             "observedSeconds": data["audit"]["observedSeconds"],
             "emptyCalls": data["audit"]["emptyCalls"],
             "earlierCalls": int(earlier.sum()), "laterCalls": int(later.sum()),
             "secondBarResponseHash": data["audit"]["responseSetSha256"]}
    result = {"scope": scope, "baseline": baseline, "capBuckets": buckets,
              "chains": chains, "callers": callers, "flowFilters": flow_rows,
              "grid": {"rules": len(exit_rules), "delays": len(DELAYS), "entryMasks": len(candidate_masks),
                       "trainingRows": len(training_grid)},
              "topTrainingCandidate": top,
              "trainingChoice": ({"label": f"{top['mask']}, {top['delaySeconds']}s, {top['exit']}"}
                                 if top["score"] > 0 else None),
              "topEvaluation": top_evaluation,
              "recentSizing": sizing,
              "recentScoreCoverage": {"earlierAtLeastFive": int(np.isfinite(recent_score[earlier]).sum()),
                                      "laterAtLeastFive": int(np.isfinite(recent_score[later]).sum()),
                                      "laterMedianHistory": float(np.median(count[later]))}}
    write_json(directory / "results.json", result)
    report(directory, result)
    print(json.dumps({"path": str(directory), "scope": scope, "grid": result["grid"],
                      "top": top, "topEvaluation": top_evaluation,
                      "recentSizing": sizing}))


if __name__ == "__main__":
    main()
