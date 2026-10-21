"""Ask Decider about human calls with market-only context and replay saved scores."""

import argparse
import hashlib
import html
import json
from pathlib import Path

import numpy as np

from context_decider import MODEL, QUESTIONS, inputs, load_scores, records
from research_dataset import DAY, MINUTE, load_dataset, sha256, write_json
from second_engine import SecondExit, load_seconds, paths, portfolio, simulate_seconds


ROOT = Path(__file__).resolve().parent
POLICY = (
    "Judge only the supplied measurements for this human-authored speculative-token call. "
    "No token name, address, Telegram account, caller history, group cohort, or future target outcome is provided. "
    "State ends after the first completed minute; a market buy is intended one minute later. "
    "Use the supplied market cap, age, price movement, pre-call on-chain flow, stake and fees. "
    "A 5% sale-proceeds haircut and round-trip gas/MEV estimate apply. "
    "Missing values are unknown. Recorded flow is not guaranteed executable liquidity. "
    "A position that cannot be sold may lose the full stake. Return uncertainty when evidence is weak."
)


def read(path):
    return json.loads(Path(path).read_text())


def dataset():
    return load_dataset(read(ROOT / "research_progress.json")["correctedDataset"])


def folder_for(rows):
    identity = hashlib.sha256("".join(row["requestSha256"] for row in rows).encode()).hexdigest()[:20]
    return ROOT / "human_decider_runs" / identity


def prepare():
    saved = dataset()
    flow, history, provenance = inputs(saved)
    questions = {name: {**original, "instructions": POLICY + "\n" + original["instructions"].split("\n", 1)[1]}
                 for name, original in QUESTIONS.items()}
    rows = []
    for row in records(saved, flow, history):
        if saved.arrays["bot"][row["index"]]:
            continue
        original = json.loads(row["body"])
        state = original["state"]
        kept = {"market": state["market"],
                "message_context": {"forwarded": state["message_context"]["forwarded"]},
                "pre_call_flow": state["pre_call_flow"],
                "hypothetical_execution": state["hypothetical_execution"]}
        body = json.dumps({"model": MODEL, "state": kept, "questions": questions},
                          sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        rows.append({**row, "requestSha256": hashlib.sha256(body.encode()).hexdigest(), "body": body})
    directory = folder_for(rows)
    directory.mkdir(parents=True, exist_ok=True)
    request_file = directory / "requests.json"
    request_data = {"datasetId": saved.path.name, "records": rows}
    if request_file.exists():
        assert read(request_file) == request_data
    else:
        write_json(request_file, request_data)
    manifest = {"dataset": str(saved.path), "datasetManifestSha256": sha256(saved.path / "manifest.json"),
                "requestFileSha256": sha256(request_file), "model": MODEL, "questions": list(questions),
                "requests": len(rows), "uniqueRequests": len({row["requestSha256"] for row in rows}),
                "sourceHashes": {name: sha256(ROOT / name) for name in
                                 ("human_decider_lab.py", "context_decider.py", "second_engine.py")},
                "inputs": "Human-authored calls only; market, message-forwarding flag, pre-call on-chain flow and execution estimate. Caller, cohort and recurring-wallet histories omitted.",
                "sourceContext": provenance}
    write_json(directory / "manifest.json", manifest)
    write_json(ROOT / "human_decider_runs/latest.json", {"path": str(directory)})
    print(json.dumps({"path": str(directory), "requests": len(rows), "uniqueRequests": manifest["uniqueRequests"]}))


def analyze():
    saved = dataset()
    directory = Path(read(ROOT / "human_decider_runs/latest.json")["path"])
    scores, latency, model = load_scores(saved, directory)
    human = ~saved.arrays["bot"]
    if model["completed"] != model["requests"] or model["failures"]:
        raise RuntimeError("Human Decider cache is incomplete")
    bars = load_seconds(saved)
    path = paths(bars, saved.arrays["bar_start"] + 2 * MINUTE, horizon=200)
    cut = (int(np.min(saved.arrays["day"])) + 3) * DAY
    rules = {"hold_60s": SecondExit(hold=60), "hold_180s": SecondExit(hold=180),
             "target_2x_180s": SecondExit(hold=180, target=2.)}
    gates = {"all_human": human}
    for field, thresholds, direction in (("positive_ev_180s", (.25, .5, .75), "high"),
                                         ("profit_60s", (.25, .5, .75), "high"),
                                         ("loss_50pct_180s", (.25, .5), "low")):
        values = scores[field]
        for threshold in thresholds:
            key = f"{field}_{direction}_{threshold:.2f}"
            gates[key] = human & np.isfinite(values) & (
                (values >= threshold) if direction == "high" else (values <= threshold))
    rows = []
    for rule_name, rule in rules.items():
        outcome = simulate_seconds(bars, path, rule)
        for gate_name, mask in gates.items():
            for size_name, factor in (("fixed", None),
                                      ("model_scaled", np.clip(.25 + 1.25 * scores["positive_ev_180s"], .25, 1.5))):
                for period, start, end in (("earlier", None, cut), ("later", cut, None)):
                    result = portfolio(saved, path, outcome, mask, fraction=.01, factor=factor,
                                       cost=.1, daily_budget=.04, start=start, end=end)
                    rows.append({"exit": rule_name, "gate": gate_name, "size": size_name, "period": period,
                                 "eligibleHumanCalls": int(mask.sum()),
                                 **{key: result[key] for key in
                                    ("return", "drawdownBound", "trades", "wins", "writeoffs")}})
    output = {"path": str(directory), "requests": model["requests"], "completed": model["completed"],
              "model": model["model"], "reportedUsage": model["usage"], "latencyMs": model["latencyMs"],
              "humanCalls": int(human.sum()), "humanResponses": int(np.isfinite(latency[human]).sum()),
              "splitAtMs": cut, "rows": rows,
              "scope": "Only human-authored calls queried and traded. Model sees market-only context; caller and group histories are omitted. Historical dates were already examined."}
    write_json(directory / "results.json", output)
    summary_rows = [row for row in rows if row["exit"] == "hold_180s" and row["size"] == "fixed"
                    and row["gate"] in ("all_human", "positive_ev_180s_high_0.50", "profit_60s_high_0.50",
                                        "loss_50pct_180s_low_0.25")]
    table = "".join(f"<tr><td>{html.escape(row['gate'])}</td><td>{row['period']}</td>"
                    f"<td>{row['return']:+.2%}</td><td>{abs(row['drawdownBound']):.2%}</td>"
                    f"<td>{row['trades']}</td></tr>" for row in summary_rows)
    page = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Human-only Decider check</title>
<style>body{{font:16px/1.65 system-ui;margin:40px auto;max-width:1150px;padding:0 24px;color:#172231;background:#fff}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:10px 12px;text-align:left;border-bottom:1px solid #d6dfe9}}</style>
<h1>Human-only Decider check</h1>
<p>{output['humanResponses']} of {output['humanCalls']} human-authored historical calls had enough context to query.
Prompts contain numeric market measurements,
pre-call on-chain flow and execution estimates. Caller, group and recurring-wallet histories were omitted.
The first completed minute is observed before a further one-minute entry delay.</p>
<p>Rows below use a 10% sale haircut, 1% allocation and 4% daily loss budget. The earlier/later split is within
the repeatedly examined archive; it is not an independent holdout. Recorded prices do not prove executable fills.</p>
<table><tr><th>Entry gate</th><th>Period</th><th>Return</th><th>Drawdown bound</th><th>Trades</th></tr>{table}</table>
<p><a href="results.json">All gates, sizes and exits</a> · <a href="manifest.json">Request provenance</a> ·
<a href="../../human_decider_lab.py">Replay code</a></p></html>"""
    (directory / "report.html").write_text(page)
    print(json.dumps({"path": str(directory), "humanCalls": output["humanCalls"],
                      "rows": len(rows), "laterBase": next(row["return"] for row in rows
                      if row["exit"] == "hold_180s" and row["gate"] == "all_human"
                      and row["size"] == "fixed" and row["period"] == "later")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("prepare", "analyze"))
    args = parser.parse_args()
    prepare() if args.phase == "prepare" else analyze()
