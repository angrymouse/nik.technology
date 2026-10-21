"""Replay inherited fixed rules with human entry calls and human reference calls."""

import hashlib
import html
import json
from collections import defaultdict
from itertools import product
from pathlib import Path

from fixed_entry_replay import Replay
from reference_filter_lab import build_features, catalog
from repeat_call_dataset import read
from research_dataset import DAY, sha256, write_json


ROOT = Path(__file__).resolve().parent


def replay(engine, case, policy, scenario_id):
    base = engine.replay(case, policy, .1)
    assert base["unknownTextTrades"] == 0
    assert all(not engine.dataset.arrays["bot"][trade["index"]] for trade in base["ledger"])
    tokens, days = defaultdict(float), defaultdict(float)
    for trade in base["ledger"]:
        tokens[trade["assetKey"]] += trade["pnl"]
        days[trade["entryTime"] // DAY] += trade["pnl"]
    best_two = sorted(tokens, key=lambda token: (-tokens[token], token))[:2]
    best_day = [max(days, key=lambda day: (days[day], -day))] if days else []
    without_tokens = engine.replay(case, policy, .1, excluded_tokens=best_two)
    without_day = engine.replay(case, policy, .1, excluded_days=best_day)
    for other in (without_tokens, without_day):
        assert all(not engine.dataset.arrays["bot"][trade["index"]] for trade in other["ledger"])
    return {"reference": case["history"], "group": case["group"],
            "policyScale": policy["scale"], "scenarioId": scenario_id,
            "return": base["return"], "drawdownBound": base["drawdownBound"],
            "trades": base["trades"], "withoutTwoBest": without_tokens["return"],
            "withoutBestDay": without_day["return"]}


def report(directory, result):
    names = {"reference_20": "All earlier human calls", "reference_21": "Earlier human calls on the same chain"}
    body = "".join(
        f"<tr><td>{html.escape(names[row['reference']])}</td><td>{row['policyScale']:.2f}×</td>"
        f"<td>{row['minimumReturn']:+.2%}</td><td>{abs(row['maximumDrawdownBound']):.2%}</td>"
        f"<td>{row['minimumTrades']}</td><td>{row['minimumWithoutTwoBest']:+.2%}</td>"
        f"<td>{row['minimumWithoutBestDay']:+.2%}</td></tr>"
        for row in result["summaries"])
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Human-call fixed-rule sensitivity</title><style>
body{{font:16px/1.65 system-ui;margin:40px auto;max-width:1150px;padding:0 24px;color:#172231;background:#fff}}
h1,h2{{line-height:1.2}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid #d6dfe9}}
th{{background:#eef3f8}}a{{color:#1459ac}}.scroll{{overflow-x:auto}}</style>
<h1>Human-call fixed-rule sensitivity</h1>
<p>This control replays earlier fixed entry settings using human-authored entry calls and human-authored,
recoverable reference calls only. Reference outcomes must finish before the later call and exclude its token.
The entry settings were chosen before this rerun from a broader historical analysis. This is a post hoc
comparison, not a newly fitted human-only strategy or an independent validation.</p>
<p>The exit aims for 3× within five minutes. Each row takes its worst account result across both human-entry
populations and {result['scenarios']} saved execution scenarios, using a 10% sale haircut. Removing winners
replays the whole account. The minimum trade count can come from a different scenario than the minimum return.</p>
<div class="scroll"><table><tr><th>Prior reference calls</th><th>Size multiplier</th><th>Worst return</th>
<th>Worst drawdown bound</th><th>Fewest trades</th><th>Worst without two best tokens</th>
<th>Worst without best entry day</th></tr>{body}</table></div>
<p>The small positive rows depend on seven or eight historical trades per scenario and choices already explored
on these dates. The fresh human-only short-horizon search and later-period model gates did not make a profit.</p>
<p><a href="results.json">All scenario results</a> · <a href="settings.json">Replay settings</a> ·
<a href="../../human_fixed_control.py">Replay code</a></p></html>"""
    (directory / "report.html").write_text(page)
    (directory / "report.html").chmod(0o600)


def main():
    earlier = Path(read(ROOT / "fixed_entry_source_runs/latest.json")["path"])
    previous = read(earlier / "settings.json")
    specs = [spec for spec in catalog() if spec["name"] in {"reference_20", "reference_21"}]
    assert len(specs) == 2 and all(spec["source"] == "non_bot" for spec in specs)
    policies = [previous["policies"][index] for index in (12, 17)]
    settings = {"source": previous["source"], "sourceSettingsSha256": sha256(earlier / "settings.json"),
                "sourceResultsSha256": sha256(earlier / "results.json"),
                "codeHashes": {name: sha256(ROOT / name) for name in
                               ("human_fixed_control.py", "fixed_entry_replay.py", "reference_filter_lab.py")},
                "references": specs, "groups": ["original_human", "combined_human"],
                "policies": policies, "scenarios": previous["scenarios"],
                "target": 3., "holdSeconds": 300, "saleHaircut": .1,
                "selectionProvenance": "Fixed daily entry settings inherited from a previously examined broader historical sample; no new fitting in this control."}
    identity = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]
    directory = ROOT / "human_fixed_control_runs" / identity
    directory.mkdir(parents=True, exist_ok=True)
    write_json(directory / "settings.json", settings)
    engine = Replay(settings["source"])
    engine.features.update(build_features(engine, specs))
    human = ~engine.dataset.arrays["bot"]
    engine.groups.update({"original_human": engine.groups["original_all"] & human,
                          "combined_human": human})
    rows = []
    for spec, group, policy, scenario_id in product(specs, settings["groups"], policies,
                                                     range(len(settings["scenarios"]))):
        scenario = settings["scenarios"][scenario_id]
        case = {"history": spec["name"], "group": group, "target": 3., "scenario": scenario}
        rows.append(replay(engine, case, policy, scenario_id))
    summaries = []
    for spec, policy in product(specs, policies):
        selected = [row for row in rows if row["reference"] == spec["name"]
                    and row["policyScale"] == policy["scale"]]
        assert len(selected) == 2 * len(settings["scenarios"])
        summaries.append({"reference": spec["name"], "policyScale": policy["scale"],
                          "minimumReturn": min(row["return"] for row in selected),
                          "maximumDrawdownBound": min(row["drawdownBound"] for row in selected),
                          "minimumTrades": min(row["trades"] for row in selected),
                          "minimumWithoutTwoBest": min(row["withoutTwoBest"] for row in selected),
                          "minimumWithoutBestDay": min(row["withoutBestDay"] for row in selected)})
    result = {"path": str(directory), "humanCalls": int(human.sum()),
              "scenarios": len(settings["scenarios"]), "basePortfolios": len(rows),
              "allHumanEntryTrades": True, "humanReferenceOnly": True,
              "summaries": summaries, "rows": rows}
    write_json(directory / "results.json", result)
    report(directory, result)
    write_json(ROOT / "human_fixed_control_runs/latest.json", {"path": str(directory)})
    print(json.dumps({"path": str(directory), "summaries": summaries}))


if __name__ == "__main__":
    main()
