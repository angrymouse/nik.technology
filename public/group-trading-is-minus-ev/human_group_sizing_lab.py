"""Replay saved human-call rules with causal recent-group sizing."""

import csv
import hashlib
import html
import json
from collections import defaultdict
from dataclasses import asdict
from itertools import product
from pathlib import Path

import numpy as np

from fixed_entry_replay import Replay
from human_only_lab import catalog, caller_history
from reference_filter_lab import build_features
from repeat_call_dataset import load_repeat_dataset, load_repeat_seconds
from research_dataset import DAY, sha256, write_json
from second_engine import SecondExit, paths, portfolio, simulate_seconds
from second_lab import verify_ledger


ROOT = Path(__file__).resolve().parent
CUTOFFS = (1792281600000, 1792368000000, 1792454400000)


def read(path):
    return json.loads(Path(path).read_text())


def references(dataset, data):
    a = dataset.arrays
    human = ~a["bot"]
    first = np.zeros(dataset.n, bool)
    seen = set()
    for i in np.argsort(a["posted"], kind="stable"):
        asset = int(a["asset"][i])
        if human[i] and asset not in seen:
            seen.add(asset)
            first[i] = True
    path = paths(data, a["entry_time"] + 5_000, horizon=180)
    output = {}
    for hold in (60, 180):
        outcome = simulate_seconds(data, path, SecondExit(hold=hold))
        finish = np.maximum(outcome["exit_time"], outcome["admit_end"])
        output[hold] = {"gross": outcome["gross"], "finish": finish,
                        "eligible": first & a["message_known"] & np.isfinite(outcome["gross"])}
    assert all(not (output[h]["eligible"] & a["bot"]).any() for h in output)
    return output, first


def history(dataset, reference, lookback, haircut):
    """Freeze each score at the target's first quote, after reference exits complete."""
    a, n = dataset.arrays, dataset.n
    count = np.zeros(n, np.int16)
    mean = np.full(n, np.nan)
    net = np.clip(reference["gross"] * (1 - haircut) - 1, -1, 1)
    for i in np.flatnonzero(~a["bot"]):
        at = int(a["entry_time"][i])
        eligible = reference["eligible"] & (reference["finish"] < at) & (a["asset"] != a["asset"][i])
        old = np.flatnonzero(eligible)
        old = old[np.argsort(reference["finish"][old], kind="stable")]
        if lookback.startswith("last_"):
            old = old[-int(lookback.split("_")[1]):]
        else:
            minutes = int(lookback.removesuffix("m"))
            old = old[reference["finish"][old] >= at - minutes * 60_000]
        count[i] = len(old)
        if len(old) >= 5:
            mean[i] = float(np.mean(net[old]))
    return count, mean


def factor(mean, style):
    available = np.isfinite(mean)
    if style == "linear_2":
        values = np.clip(1 + 2 * mean, .25, 1.5)
    elif style == "linear_4":
        values = np.clip(1 + 4 * mean, .1, 1.5)
    elif style == "step":
        values = np.select((mean < -.1, mean < 0, mean < .1), (.25, .5, 1.), default=1.5)
    elif style == "reverse_025":
        values = np.clip(1 - .25 * mean, .75, 1.25)
    elif style == "reverse_05":
        values = np.clip(1 - .5 * mean, .75, 1.25)
    elif style == "reverse_1":
        values = np.clip(1 - mean, .5, 1.5)
    elif style == "reverse_2":
        values = np.clip(1 - 2 * mean, .25, 1.5)
    elif style == "reverse_loss_05":
        values = np.clip(1 - .5 * np.minimum(mean, 0), 1., 1.25)
    elif style == "reverse_loss_1":
        values = np.clip(1 - np.minimum(mean, 0), 1., 1.5)
    else:
        raise ValueError(style)
    return np.where(available, values, 1.)


def fresh_stages(dataset, data, leaders, entries, exits):
    stages, cached_paths, cached_outcomes = [], {}, {}
    for cutoff, leader in zip(CUTOFFS, leaders[:3]):
        if leader is None:
            continue
        delay, exit_id = leader["delay"], leader["exitId"]
        if delay not in cached_paths:
            cached_paths[delay] = paths(data, dataset.arrays["entry_time"] + delay * 1000, horizon=180)
        key = delay, exit_id
        if key not in cached_outcomes:
            cached_outcomes[key] = simulate_seconds(data, cached_paths[delay], exits[exit_id])
        stages.append((cutoff, leader["fraction"], entries[leader["entryId"]]["mask"],
                       cached_paths[delay], cached_outcomes[key]))
    return stages


def replay_fresh(dataset, stages, sizes, cost):
    state, ledger, drawdown, by_day = None, [], 0., []
    for cutoff, fraction, mask, path, outcome in stages:
        replay = portfolio(dataset, path, outcome, mask, fraction=fraction, factor=sizes,
                           cost=cost, daily_budget=.04, start=cutoff, end=cutoff + DAY,
                           initial_state=state, trace=True)
        state = replay["state"]
        drawdown = min(drawdown, replay["drawdownBound"])
        ledger.extend(replay["ledger"])
        by_day.append({"cutoff": cutoff, "return": replay["return"], "trades": replay["trades"]})
    cash = state["cash"] if state else 100.
    verify_ledger(ledger, cash)
    assert all(not dataset.arrays["bot"][trade["index"]] for trade in ledger)
    return {"return": cash / 100 - 1, "drawdownBound": drawdown, "trades": len(ledger),
            "stake": sum(trade["positionSize"] for trade in ledger), "byDay": by_day}


def fixed_controls(settings, source):
    engine = Replay(settings["source"])
    specs = settings["references"]
    engine.features.update(build_features(engine, specs))
    human = ~engine.dataset.arrays["bot"]
    engine.groups.update({"original_human": engine.groups["original_all"] & human,
                          "combined_human": human})
    keys = [f"s{stage}_{spec['name']}_factor" for spec in specs for stage in range(3)]
    originals = {key: engine.features[key] for key in keys}
    cases = [(spec["name"], group, sid, scenario)
             for spec, group, (sid, scenario) in product(specs, settings["groups"],
                                                         enumerate(settings["scenarios"]))]
    assert len(cases) == 2 * 2 * len(settings["scenarios"])
    return engine, originals, cases


def replay_fixed(engine, originals, cases, sizes, cost, label):
    for key, original in originals.items():
        stage = int(key.split("_", 1)[0][1:])
        engine.features[key] = (original if label == "existing_group_size" or stage == 2 else sizes)
    rows = []
    for reference, group, scenario_id, scenario in cases:
        case = {"history": reference, "group": group, "target": 3., "scenario": scenario}
        replay = engine.replay(case, {"scale": .75, "budget": .01}, cost)
        assert all(not engine.dataset.arrays["bot"][trade["index"]] for trade in replay["ledger"])
        rows.append({"reference": reference, "group": group, "scenarioId": scenario_id,
                     "return": replay["return"], "drawdownBound": replay["drawdownBound"],
                     "trades": replay["trades"], "stake": sum(t["positionSize"] for t in replay["ledger"])})
    return rows


def fixed_concentration(engine, originals, cases, sizes, label):
    for key, original in originals.items():
        stage = int(key.split("_", 1)[0][1:])
        engine.features[key] = (original if label == "existing_group_size" or stage == 2 else sizes)
    rows = []
    for reference, group, scenario_id, scenario in cases:
        case = {"history": reference, "group": group, "target": 3., "scenario": scenario}
        base = engine.replay(case, {"scale": .75, "budget": .01}, .1)
        tokens, days = defaultdict(float), defaultdict(float)
        for trade in base["ledger"]:
            tokens[trade["assetKey"]] += trade["pnl"]
            days[trade["entryTime"] // DAY] += trade["pnl"]
        best_two = sorted(tokens, key=lambda token: (-tokens[token], token))[:2]
        best_day = [max(days, key=lambda day: (days[day], -day))] if days else []
        without_tokens = engine.replay(case, {"scale": .75, "budget": .01}, .1, excluded_tokens=best_two)
        without_day = engine.replay(case, {"scale": .75, "budget": .01}, .1, excluded_days=best_day)
        for replay in (base, without_tokens, without_day):
            assert all(not engine.dataset.arrays["bot"][trade["index"]] for trade in replay["ledger"])
        rows.append({"sizing": label, "reference": reference, "group": group, "scenarioId": scenario_id,
                     "return": base["return"], "withoutTwoBest": without_tokens["return"],
                     "withoutBestDay": without_day["return"]})
    return rows


def summarize(rows):
    return {"worstReturn": min(row["return"] for row in rows),
            "bestReturn": max(row["return"] for row in rows),
            "worstDrawdownBound": min(row["drawdownBound"] for row in rows),
            "fewestTrades": min(row["trades"] for row in rows),
            "leastStake": min(row["stake"] for row in rows),
            "mostStake": max(row["stake"] for row in rows)}


def save_csv(path, rows):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    path.chmod(0o600)


def predictive_quartiles(dataset, references_by_hold, first, score):
    a = dataset.arrays
    reference = references_by_hold[180]
    admitted = first & reference["eligible"] & np.isfinite(score)
    rows = []
    for period, period_mask in (("all", np.ones(dataset.n, bool)),
                                ("later", a["entry_time"] >= CUTOFFS[1])):
        indices = np.flatnonzero(admitted & period_mask)
        order = indices[np.argsort(score[indices], kind="stable")]
        for quartile, part in enumerate(np.array_split(order, 4), 1):
            net = np.clip(reference["gross"][part] * .9 - 1, -1, 1)
            rows.append({"period": period, "recentScoreQuartile": quartile,
                         "tokens": len(part), "meanRecentScore": float(np.mean(score[part])),
                         "meanNextTokenReturn": float(np.mean(net)),
                         "nextTokenWinRate": float(np.mean(net > 0))})
    return rows


def report(directory, result):
    def line(row):
        return (f"<tr><td>{html.escape(row['label'])}</td><td>{row['zeroHaircutReturn']:+.2%}</td>"
                f"<td>{row['return']:+.2%}</td>"
                f"<td>{abs(row['drawdownBound']):.2%}</td><td>{row['trades']}</td>"
                f"<td>{row['stake']:.2f}</td></tr>")

    fresh = result["fresh"]
    fixed = result["fixed"]
    body = "".join(line(row) for row in fresh["highlight"])
    fixed_body = "".join(f"<tr><td>{html.escape(row['label'])}</td>"
                         f"<td>{row['zeroHaircutWorstReturn']:+.2%}</td>"
                         f"<td>{row['worstReturn']:+.2%}</td>"
                         f"<td>{abs(row['worstDrawdownBound']):.2%}</td>"
                         f"<td>{row['fewestTrades']}</td>"
                         f"<td>{row['worstWithoutTwoBest']:+.2%}</td>"
                         f"<td>{row['worstWithoutBestDay']:+.2%}</td></tr>" for row in fixed["highlight"])
    quartiles = "".join(f"<tr><td>{row['period']}</td><td>{row['recentScoreQuartile']}</td>"
                        f"<td>{row['tokens']}</td><td>{row['meanRecentScore']:+.2%}</td>"
                        f"<td>{row['meanNextTokenReturn']:+.2%}</td></tr>"
                        for row in result["predictiveQuartiles"])
    stake_comparison = fixed["stakeComparison"]
    inverse = fixed["inverseComparison"]
    slopes = "".join(f"<tr><td>{html.escape(row['label'])}</td>"
                     f"<td>{row['dailyZeroReturn']:+.2%}</td><td>{row['dailyTenReturn']:+.2%}</td>"
                     f"<td>{row['guardedZeroReturn']:+.2%}</td><td>{row['guardedTenReturn']:+.2%}</td>"
                     f"<td>{row['fixedZeroWorstReturn']:+.2%}</td>"
                     f"<td>{row['fixedTenWorstReturn']:+.2%}</td>"
                     f"<td>{abs(row['fixedTenWorstDrawdown']):.2%}</td>"
                     f"<td>{row['fixedTenMedianStake']:.2f}</td></tr>"
                     for row in result["reversalSlopeComparison"])
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Recent group performance and trade size</title><style>
body{{font:16px/1.65 system-ui;margin:40px auto;max-width:1150px;padding:0 24px;color:#172231;background:#fff}}
h1,h2{{line-height:1.2}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #d6dfe9}}
th{{background:#eef3f8}}a{{color:#1459ac}}.scroll{{overflow-x:auto}}</style>
<h1>Recent group performance and trade size</h1>
<p>Scope: {result['humanCalls']} human-authored eligible calls across three replay days, with
{result['distinctHumanReferenceTokens']} distinct tokens first called by a human. A group score uses the
first eligible human call per other token, an observed
60- or 180-second sale, and at least five completed reference outcomes. It is frozen at the target call's
first quote; unfinished outcomes and the target token are excluded. Scores use the last 10 or 20 completed
tokens, or the preceding one or six hours. The replay varies the group score's sale haircut, size mapping,
and trade sale haircut. There are {fresh['recentPolicies']} score rules, including
{fresh['inversePolicies']} reversal rules. These dates were already examined, so the best variant is post hoc.</p>
<p>The next table groups first human calls by the last ten completed three-minute reference outcomes.
It measures whether a better recent group score preceded a better return on the next token. It is a
descriptive full-sample check, not a trade-sized account replay.</p>
<div class="scroll"><table><tr><th>Period</th><th>Recent-score quartile</th><th>Tokens</th>
<th>Mean recent score</th><th>Mean next-token return</th></tr>{quartiles}</table></div>
<h2>Reversal slope on one common score</h2>
<p>This table fixes the score to the last ten completed 180-second human-token returns, with no haircut
on those reference returns. A reversal slope of k multiplies size by 1 - k × mean recent return.
The 0.25 and 0.5 slopes are capped at 0.75–1.25×, slope 1 at 0.5–1.5×, and slope 2 at 0.25–1.5×.
Loss-only slopes leave size at 1× after a positive score and rise after a negative score, capped at
1.25× or 1.5×. Missing scores use 1×. Account return includes each procedure's loss budget.</p>
<div class="scroll"><table><tr><th>Size rule</th><th>Daily, 0%</th><th>Daily, 10%</th>
<th>Guarded, 0%</th><th>Guarded, 10%</th><th>Fixed worst, 0%</th><th>Fixed worst, 10%</th>
<th>Fixed drawdown bound, 10%</th><th>Fixed median stake, 10%</th></tr>{slopes}</table></div>
<h2>Fresh human-only daily rules</h2>
<p>The rows below show zero and 10% sale haircuts. Total stake is the sum of simulated position sizes from a $100
starting account; it helps distinguish signal timing from simply taking less risk. The two saved entry/exit
procedures stay fixed. Group scores change only position size.</p>
<div class="scroll"><table><tr><th>Rule and sizing</th><th>Return, 0%</th><th>Return, 10%</th>
<th>Drawdown bound, 10%</th><th>Trades, 10%</th><th>Total stake, 10%</th></tr>{body}</table></div>
<h2>Inherited five-minute fixed rule</h2>
<p>This rule already scales its first two days with recent human reference outcomes. The comparison keeps
its entry filters, stage-three volatility factor, 3× exit, and three-quarter allocation multiplier.
Each row is the worst of 25 execution scenarios and two human-entry populations for each of two human-only
reference definitions, at a 10% sale haircut. Replacing the existing group factor only changes the first
two days' size. The rule's settings were chosen in earlier research.</p>
<div class="scroll"><table><tr><th>Group sizing</th><th>Worst return, 0%</th><th>Worst return, 10%</th><th>Worst drawdown bound, 10%</th>
<th>Fewest trades</th><th>Worst without two best tokens</th><th>Worst without best day</th></tr>{fixed_body}</table></div>
<p>The post hoc best variant has higher account return than the inherited size rule in
{stake_comparison['higherAccountReturnCases']} of {stake_comparison['scenarios']} scenarios, but higher
profit per dollar staked in only {stake_comparison['higherProfitPerStakeCases']}.
Its median total stake is {stake_comparison['bestMedianStake']:.2f} against
{stake_comparison['existingMedianStake']:.2f}. Its profit advantage does not establish a better group signal.</p>
<p>The best reversal rule in this grid has median total stake {inverse['inverseMedianStake']:.2f}, close to
{inverse['flatMedianStake']:.2f} for a flat 1× size. Against that flat rule it has higher account return
in {inverse['flat_100']['higherAccountReturnCases']} of {inverse['scenarios']} matched execution cases
and higher profit per dollar staked in {inverse['flat_100']['higherProfitPerStakeCases']}.
Against the inherited group factor, it has higher account return in
{inverse['existing_group_size']['higherAccountReturnCases']} cases and higher profit per dollar staked in
{inverse['existing_group_size']['higherProfitPerStakeCases']}. The median absolute stake gap against the
flat rule is {inverse['medianAbsoluteStakeGapToFlat']:.2f} on the $100 starting account.</p>
<p><a href="results.json">Summary and policy definitions</a> · <a href="fresh_rows.csv">Fresh-rule grid</a> ·
<a href="fixed_rows.csv">Fixed-rule scenario grid</a> · <a href="fixed_concentration.csv">Winner-removal replays</a> ·
<a href="settings.json">Input hashes</a> ·
<a href="../../human_group_sizing_lab.py">Replay code</a></p></html>"""
    (directory / "report.html").write_text(page)
    (directory / "report.html").chmod(0o600)


def main():
    human_dir = Path(read(ROOT / "human_only_runs/latest.json")["path"])
    human_result = read(human_dir / "results.json")
    fixed_dir = Path(read(ROOT / "human_fixed_control_runs/latest.json")["path"])
    fixed_settings = read(fixed_dir / "settings.json")
    dataset_path = Path(read(ROOT / "repeat_call_datasets/latest.json")["path"])
    dataset = load_repeat_dataset(dataset_path)
    data = load_repeat_seconds(dataset)
    references_by_hold, first = references(dataset, data)
    assert int((~dataset.arrays["bot"]).sum()) == human_result["humanCalls"]
    entries, exits = catalog(dataset, caller_history(dataset, data))
    fresh = {name: fresh_stages(dataset, data, leaders, entries, exits)
             for name, leaders in (("daily", human_result["search"]["leaders"]),
                                   ("guarded", human_result["robustSelection"]["leaders"]))}
    specifications = []
    factors = {"existing_group_size": np.ones(dataset.n),
               "flat_025": np.full(dataset.n, .25),
               "flat_050": np.full(dataset.n, .5),
               "flat_075": np.full(dataset.n, .75),
               "flat_100": np.ones(dataset.n),
               "flat_125": np.full(dataset.n, 1.25),
               "flat_150": np.full(dataset.n, 1.5)}
    descriptions = {name: {"name": name, "kind": "control"} for name in factors}
    scores = {}
    for hold, lookback, reference_cost in product((60, 180), ("last_10", "last_20", "60m", "360m"), (0., .1)):
        count, mean = history(dataset, references_by_hold[hold], lookback, reference_cost)
        score_key = f"{hold}s_{lookback}_ref{int(reference_cost*100)}"
        scores[score_key] = {"count": count, "mean": mean}
        for style in ("linear_2", "linear_4", "step", "reverse_025", "reverse_05",
                      "reverse_1", "reverse_2", "reverse_loss_05", "reverse_loss_1"):
            name = score_key + "_" + style
            factors[name] = factor(mean, style)
            descriptions[name] = {"name": name, "kind": "recent_group", "referenceHoldSeconds": hold,
                                  "lookback": lookback, "referenceHaircut": reference_cost,
                                  "minimumCompletedTokens": 5, "sizeMapping": style,
                                  "scoredHumanCalls": int(np.isfinite(mean[~dataset.arrays["bot"]]).sum())}
            specifications.append(name)
    source_hashes = {"humanOnlyResults": sha256(human_dir / "results.json"),
                     "fixedControlSettings": sha256(fixed_dir / "settings.json"),
                     "datasetManifest": sha256(dataset_path / "manifest.json"),
                     "script": sha256(Path(__file__)),
                     "humanOnlyCode": sha256(ROOT / "human_only_lab.py"),
                     "referenceFilterCode": sha256(ROOT / "reference_filter_lab.py"),
                     "repeatDatasetCode": sha256(ROOT / "repeat_call_dataset.py"),
                     "secondSearchCode": sha256(ROOT / "second_lab.py"),
                     "researchDatasetCode": sha256(ROOT / "research_dataset.py"),
                     "secondEngine": sha256(ROOT / "second_engine.py"),
                     "fixedReplay": sha256(ROOT / "fixed_entry_replay.py")}
    settings = {"sourceHashes": source_hashes, "humanCalls": human_result["humanCalls"],
                "distinctHumanReferenceTokens": int(first.sum()),
                "scoreTime": "first quote; strictly completed earlier outcomes only",
                "scoreReturnsClipped": [-1, 1], "styles": descriptions,
                "freshProcedures": list(fresh), "fixedReferences": [s["name"] for s in fixed_settings["references"]],
                "fixedPolicy": {"scale": .75, "budget": .01}, "costs": [0., .1]}
    identity = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]
    directory = ROOT / "human_group_sizing_runs" / identity
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory / "settings.json", settings)

    fresh_rows = []
    for procedure, stages in fresh.items():
        for cost, (name, sizes) in product((0., .1), factors.items()):
            result = replay_fresh(dataset, stages, sizes, cost)
            fresh_rows.append({"procedure": procedure, "saleHaircut": cost, "sizing": name,
                               **{key: result[key] for key in ("return", "drawdownBound", "trades", "stake")}})
    save_csv(directory / "fresh_rows.csv", fresh_rows)

    engine, originals, cases = fixed_controls(fixed_settings, fixed_dir)
    fixed_rows, fixed_summary = [], []
    for name in factors:
        for cost in (0., .1):
            rows = replay_fixed(engine, originals, cases, factors[name], cost, name)
            for row in rows:
                fixed_rows.append({"sizing": name, "saleHaircut": cost, **row})
            fixed_summary.append({"sizing": name, "saleHaircut": cost, **summarize(rows)})
    save_csv(directory / "fixed_rows.csv", fixed_rows)

    def fresh_record(procedure, sizing, cost=.1):
        return next(row for row in fresh_rows if row["procedure"] == procedure and
                    row["sizing"] == sizing and row["saleHaircut"] == cost)

    def fixed_record(sizing, cost=.1):
        return next(row for row in fixed_summary if row["sizing"] == sizing and row["saleHaircut"] == cost)

    fresh_highlight = []
    inverse_names = [name for name in specifications if "_reverse_" in name]
    fresh_inverse = {}
    for procedure in fresh:
        choices = [row for row in fresh_rows if row["procedure"] == procedure and
                   row["saleHaircut"] == .1 and row["sizing"] in specifications]
        best = max(choices, key=lambda row: row["return"])
        inverse = max((row for row in choices if row["sizing"] in inverse_names),
                      key=lambda row: row["return"])
        fresh_inverse[procedure] = inverse
        for label, row in (("flat full", fresh_record(procedure, "flat_100")),
                           ("flat quarter", fresh_record(procedure, "flat_025")),
                           ("flat one-and-a-quarter", fresh_record(procedure, "flat_125")),
                           ("best reversal grid", inverse),
                           ("best recent-score grid", best)):
            fresh_highlight.append({"label": procedure + ": " + label, **row,
                                    "zeroHaircutReturn": fresh_record(procedure, row["sizing"], 0.)["return"]})
    fixed_choices = [row for row in fixed_summary if row["saleHaircut"] == .1 and
                     row["sizing"] in specifications]
    fixed_best = max(fixed_choices, key=lambda row: row["worstReturn"])
    fixed_inverse = max((row for row in fixed_choices if row["sizing"] in inverse_names),
                        key=lambda row: row["worstReturn"])
    concentration_rows = []
    concentration_names = tuple(dict.fromkeys(("existing_group_size", "flat_050", "flat_100",
                                               "flat_125", "flat_150", fixed_best["sizing"],
                                               fixed_inverse["sizing"])))
    for name in concentration_names:
        concentration_rows.extend(fixed_concentration(engine, originals, cases, factors[name], name))
    save_csv(directory / "fixed_concentration.csv", concentration_rows)
    concentration_summary = {name: {
        "worstWithoutTwoBest": min(row["withoutTwoBest"] for row in concentration_rows if row["sizing"] == name),
        "worstWithoutBestDay": min(row["withoutBestDay"] for row in concentration_rows if row["sizing"] == name)}
        for name in concentration_names}
    fixed_highlight = [{"label": label, **fixed_record(name),
                        "zeroHaircutWorstReturn": fixed_record(name, 0.)["worstReturn"],
                        **concentration_summary[name]} for label, name in
                       (("existing group score", "existing_group_size"),
                        ("no recent group factor", "flat_100"),
                        ("flat half factor", "flat_050"),
                        ("flat one-and-a-quarter factor", "flat_125"),
                        ("flat one-and-a-half factor", "flat_150"))]
    fixed_highlight.append({"label": "best reversal grid", **fixed_inverse,
                            "zeroHaircutWorstReturn": fixed_record(fixed_inverse["sizing"], 0.)["worstReturn"],
                            **concentration_summary[fixed_inverse["sizing"]]})
    fixed_highlight.append({"label": "best recent-score grid", **fixed_best,
                            "zeroHaircutWorstReturn": fixed_record(fixed_best["sizing"], 0.)["worstReturn"],
                            **concentration_summary[fixed_best["sizing"]]})
    pairs = defaultdict(dict)
    for row in fixed_rows:
        if row["saleHaircut"] == .1 and row["sizing"] in ("existing_group_size", fixed_best["sizing"]):
            key = row["reference"], row["group"], row["scenarioId"]
            pairs[key][row["sizing"]] = row
    assert len(pairs) == len(cases) and all(len(pair) == 2 for pair in pairs.values())
    best_name = fixed_best["sizing"]
    stake_comparison = {
        "scenarios": len(pairs),
        "higherAccountReturnCases": sum(pair[best_name]["return"] > pair["existing_group_size"]["return"]
                                        for pair in pairs.values()),
        "higherProfitPerStakeCases": sum(
            pair[best_name]["return"] / pair[best_name]["stake"] >
            pair["existing_group_size"]["return"] / pair["existing_group_size"]["stake"]
            for pair in pairs.values()),
        "bestMedianStake": float(np.median([pair[best_name]["stake"] for pair in pairs.values()])),
        "existingMedianStake": float(np.median([pair["existing_group_size"]["stake"]
                                                 for pair in pairs.values()]))}
    inverse_name = fixed_inverse["sizing"]
    inverse_pairs = defaultdict(dict)
    for row in fixed_rows:
        if row["saleHaircut"] == .1 and row["sizing"] in ("existing_group_size", "flat_100", inverse_name):
            inverse_pairs[row["reference"], row["group"], row["scenarioId"]][row["sizing"]] = row
    assert len(inverse_pairs) == len(cases) and all(len(pair) == 3 for pair in inverse_pairs.values())
    inverse_comparison = {"policy": inverse_name, "scenarios": len(cases),
                          "inverseMedianStake": float(np.median([
                              pair[inverse_name]["stake"] for pair in inverse_pairs.values()])),
                          "flatMedianStake": float(np.median([
                              pair["flat_100"]["stake"] for pair in inverse_pairs.values()])),
                          "existingMedianStake": float(np.median([
                              pair["existing_group_size"]["stake"] for pair in inverse_pairs.values()])),
                          "medianAbsoluteStakeGapToFlat": float(np.median([
                              abs(pair[inverse_name]["stake"] - pair["flat_100"]["stake"])
                              for pair in inverse_pairs.values()]))}
    for baseline in ("flat_100", "existing_group_size"):
        inverse_comparison[baseline] = {
            "higherAccountReturnCases": sum(pair[inverse_name]["return"] > pair[baseline]["return"]
                                            for pair in inverse_pairs.values()),
            "higherProfitPerStakeCases": sum(
                pair[inverse_name]["return"] / pair[inverse_name]["stake"] >
                pair[baseline]["return"] / pair[baseline]["stake"]
                for pair in inverse_pairs.values())}
    common_score = "180s_last_10_ref0_"
    slopes = [("flat full", "flat_100"),
              *((f"reversal slope {slope}", common_score + "reverse_" + suffix)
                for slope, suffix in (("0.25", "025"), ("0.5", "05"), ("1", "1"), ("2", "2"))),
              ("loss-only slope 0.5", common_score + "reverse_loss_05"),
              ("loss-only slope 1", common_score + "reverse_loss_1")]
    slope_comparison = []
    for label, name in slopes:
        slope_comparison.append({"label": label, "sizing": name,
                                 "dailyZeroReturn": fresh_record("daily", name, 0.)["return"],
                                 "dailyTenReturn": fresh_record("daily", name)["return"],
                                 "guardedZeroReturn": fresh_record("guarded", name, 0.)["return"],
                                 "guardedTenReturn": fresh_record("guarded", name)["return"],
                                 "fixedZeroWorstReturn": fixed_record(name, 0.)["worstReturn"],
                                 "fixedTenWorstReturn": fixed_record(name)["worstReturn"],
                                 "fixedTenWorstDrawdown": fixed_record(name)["worstDrawdownBound"],
                                 "fixedTenMedianStake": float(np.median([
                                     row["stake"] for row in fixed_rows if row["sizing"] == name and
                                     row["saleHaircut"] == .1]))})
    quartiles = predictive_quartiles(dataset, references_by_hold, first,
                                     scores["180s_last_10_ref10"]["mean"])
    output = {"path": str(directory), "sourceHashes": source_hashes,
              "humanCalls": settings["humanCalls"], "distinctHumanReferenceTokens": settings["distinctHumanReferenceTokens"],
              "predictiveQuartiles": quartiles,
              "reversalSlopeComparison": slope_comparison,
              "scoreCoverage": {key: {"atLeastFive": int(np.isfinite(value["mean"]).sum()),
                                      "medianCount": float(np.median(value["count"][~dataset.arrays["bot"]]))}
                                for key, value in scores.items()},
              "fresh": {"policies": len(factors), "recentPolicies": len(specifications),
                        "inversePolicies": len(inverse_names), "rows": len(fresh_rows), "highlight": fresh_highlight,
                        "bestInverse": fresh_inverse,
                        "best": {procedure: max((row for row in fresh_rows if row["procedure"] == procedure and
                                                row["saleHaircut"] == .1 and row["sizing"] in specifications),
                                                key=lambda row: row["return"])
                                 for procedure in fresh}},
              "fixed": {"policies": len(factors), "rows": len(fixed_rows),
                        "scenariosPerPolicyCost": len(cases), "highlight": fixed_highlight,
                        "best": fixed_best, "bestInverse": fixed_inverse,
                        "stakeComparison": stake_comparison,
                        "inverseComparison": inverse_comparison},
              "interpretation": "All recent-score maxima are post hoc over correlated sizing variants on previously examined dates. Flat-size controls expose risk reduction from trading less."}
    write_json(directory / "results.json", output)
    report(directory, output)
    write_json(ROOT / "human_group_sizing_runs/latest.json", {"path": str(directory)})
    print(json.dumps({"path": str(directory), "freshHighlight": fresh_highlight,
                      "fixedHighlight": fixed_highlight,
                      "scoreCoverage": output["scoreCoverage"]}))


if __name__ == "__main__":
    main()
