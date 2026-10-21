"""Replay admissions and cash after volume-limited staged exits.

The original entry rules and 3x/300-second exit trigger are fixed. Only sale
execution, settlement time, fee reserve, and the resulting account state change.
"""

import argparse
import gzip
import hashlib
import json
import math
import shutil
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import product
from pathlib import Path

import numpy as np

from confirmed_target_engine import ConfirmedTarget
from delayed_flow_lab import load_view
from pool_route_engine import credits, initialize, route_inputs
from pool_route_lab import verify
from research_dataset import DAY, sha256, write_json
from staged_exit_capacity_lab import future_plan, load_extended
from trade_flow_features import load_rows, normalize, positive


ROOT = Path(__file__).resolve().parent
read = lambda path: json.loads(Path(path).read_text())


Caller 51(frozen=True)
class ExitPlan:
    source_index: int
    entry_time: int
    original_exit_time: int
    entry_price: float
    exit_price: float
    economic_volume_usd: float
    observed_exit_fee_usd: float | None
    later: tuple


Caller 51(frozen=True)
class Sale:
    recovered_usd: float
    extra_fee_usd: float
    settled_at: int
    remaining_fraction: float
    attempts: int
    fills: int


def prepare():
    source = Path(read(ROOT / "pool_route_runs/latest.json")["path"])
    nine = Path(read(ROOT / "staged_exit_flow_runs/latest.json")["path"])
    extra = Path(read(ROOT / "full_staged_exit_flow_runs/latest.json")["path"])
    assert read(source / "pool_route_audit.json")["resultsSha256"] == sha256(source / "results.json")
    assert Path(read(extra / "settings.json")["priorNineFlow"]) == nine
    for folder, total in ((nine, 9), (extra, 2)):
        collection = read(folder / "collection.json")
        assert collection["completed"] == collection["requested"] == total and not collection["errors"]
    responses = {f"{folder.name}/{row['id']}": sha256(folder / "responses" / f"{row['id']}.json.gz")
                 for folder in (nine, extra) for row in read(folder / "requests.json")["requests"]}
    settings = {"source": str(source), "nineFlow": str(nine), "extraFlow": str(extra),
                "sourceResultsSha256": sha256(source / "results.json"),
                "sourceLedgerSha256": sha256(source / "portfolios.jsonl.gz"),
                "nineRequestsSha256": sha256(nine / "requests.json"),
                "extraRequestsSha256": sha256(extra / "requests.json"),
                "responseHashes": responses,
                "sourceCodeSha256": sha256(Path(__file__)),
                "helperCodeSha256": {name: sha256(ROOT / name) for name in (
                    "pool_route_engine.py", "staged_exit_capacity_lab.py", "confirmed_target_engine.py")},
                "routeIds": [0, 1], "modes": ["entry_time", "conservative_both"],
                "cost": 0.1, "horizonsSeconds": [15, 30, 60],
                "feeModes": ["saved_per_order", "higher_prior_median"],
                "stepSeconds": 5, "informationLagSeconds": 5, "saleWaitSeconds": 10,
                "minimumTrades": 8,
                "model": "Replay every eligible call under the original fixed daily entry rules, cap and fee controls, price variants, 3x target and 300-second timeout. At the original exit sell up to participation times pre-exit 60-second economic volume ending five seconds earlier. Attempt additional sales at exit+10, +15, ... through the named horizon. Each attempt is limited to fresh nonoverlapping five-second economic volume ending five seconds before submission, uses the next recorded swap price within ten seconds, and pays an order fee. Unsold inventory is written to zero at horizon plus the sale wait. One position remains open until settlement; later admissions, sizes, budgets, winner removals and day removals are replayed. Reserve the maximum number of possible extra saved-fee half-orders from cash and daily budget at entry, using only its pre-entry fee estimate. The alternate exit fee uses the higher of that saved allowance and the pre-exit median gas plus MEV, which is observed only when selling. This is retrospective recorded-flow sensitivity, not an executable AMM quotation.",
                "scope": "Eleven historical candidate calls across repeatedly examined days, including two newly collected raw windows. Initial capacity and all later prices are market-data proxies. Closed-equity drawdown omits open-position lows; exposure and margin remain uncertain without executable reserves and prospective qualifying entries."}
    identity = hashlib.sha256(json.dumps(settings, sort_keys=True).encode()).hexdigest()[:16]
    folder = ROOT / "full_staged_account_runs" / identity
    if (folder / "declaration.json").exists():
        assert read(folder / "settings.json") == settings
    else:
        folder.mkdir(parents=True, exist_ok=False)
        write_json(folder / "settings.json", settings, 0o400)
        write_json(folder / "declaration.json", {"frozenAt": datetime.now(timezone.utc).isoformat(),
                                                 "settingsSha256": sha256(folder / "settings.json")}, 0o400)
        shutil.copyfile(Path(__file__), folder / Path(__file__).name)
        (folder / Path(__file__).name).chmod(0o400)
    write_json(ROOT / "full_staged_account_runs/latest.json", {"path": str(folder)})
    print(json.dumps({"prepared": str(folder), "settingsSha256": sha256(folder / "settings.json")}))
    return folder


def all_rows(settings, source_settings):
    nine = Path(settings["nineFlow"])
    first, overlap, previous_hash = load_extended({"flow": str(nine)}, source_settings)
    assert not overlap["missingOldIDs"] and not overlap["newOverlapIDs"] and not overlap["changedOverlapIDs"]
    price = Path(source_settings["priceSource"])
    trade = Path(read(price / "settings.json")["tradeSource"])
    original, coverage = load_rows(load_view(trade))
    assert coverage["responseSetSha256"] == previous_hash
    extra = Path(settings["extraFlow"])
    later = {}
    counts = {"priorNine": len(first), "priorNineOverlap": overlap["oldRows"],
              "priorNineLater": overlap["laterRows"], "extraOverlap": 0, "extraLater": 0}
    for item in read(extra / "requests.json")["requests"]:
        blob = json.loads(gzip.decompress((extra / "responses" / f"{item['id']}.json.gz").read_bytes()))
        assert blob["complete"] and blob["request"] == item["request"]
        assert blob["pages"][-1]["response"]["pagination"]["hasMore"] is False
        unique = {}
        for page in blob["pages"]:
            for raw in page["response"]["data"]:
                row = normalize(item["request"], raw)
                if item["request"]["chainId"].startswith("evm:"):
                    row["pool"] = row["pool"].lower()
                if row["id"] in unique:
                    assert unique[row["id"]] == row
                unique[row["id"]] = row
        old = original[item["localIndex"]]
        if item["request"]["chainId"].startswith("evm:"):
            for row in old:
                row["pool"] = row["pool"].lower()
        old_ids = {row["id"]: row for row in old}
        common = {key: row for key, row in unique.items() if row["date"] <= item["originalRequestTo"]}
        assert common == old_ids
        added = [row for row in unique.values() if row["date"] > item["originalRequestTo"]]
        counts["extraOverlap"] += len(common)
        counts["extraLater"] += len(added)
        later[item["parentIndex"]] = sorted([*old, *added], key=lambda row: (row["date"], row["id"]))
    assert not set(first) & set(later)
    merged = {**first, **later}
    assert len(merged) == 11
    return merged, counts, previous_hash


def source_accounts(source, settings):
    index = {}
    fields = ("routeId", "priceSource", "mode", "history", "group", "policyId", "scenarioId")
    with gzip.open(source / "portfolios.jsonl.gz", "rt") as stream:
        for line in stream:
            account = json.loads(line)
            if account["cost"] == settings["cost"] and account["removed"] == "none" and \
                    account["routeId"] in settings["routeIds"] and account["mode"] in settings["modes"]:
                key = tuple(account[k] for k in fields)
                assert key not in index
                index[key] = account
    assert len(index) == 1600
    return index, fields


def exit_plan(index, pool, price_source, data, outcome, raw, horizon, step, lag, wait):
    entry_time = int(outcome["entry_time"][index])
    exit_time = int(outcome["exit_time"][index])
    base = int(data["base"][index])
    entry_tick = (entry_time - base) // 1000
    exit_tick = (exit_time - base) // 1000
    entry_price = float(data["bars"][index, entry_tick, 0])
    exit_price = float(data["bars"][index, exit_tick, 0]) if outcome["gross"][index] > 0 else 0.0
    assert positive(entry_price)
    if exit_price:
        assert math.isclose(exit_price / entry_price, outcome["gross"][index], rel_tol=1e-9, abs_tol=1e-9)
    cutoff = exit_time - lag * 1000
    preceding = credits(raw, cutoff, 60)
    economic = sum(preceding.values()) if pool is None else preceding.get(pool, 0.0)
    swap_fees = {}
    for row in raw:
        if cutoff - 60000 <= row["date"] <= cutoff and (pool is None or row["pool"] == pool) and \
                row["type"] in ("buy", "sell") and positive(row["quantity"]) and positive(row["usd"]) and \
                row["gas_mev"] is not None:
            swap_fees[row["transaction"]] = max(swap_fees.get(row["transaction"], 0.0), row["gas_mev"])
    median_fee = float(np.median(list(swap_fees.values()))) if swap_fees else None
    stub = {"pool": pool, "exitTime": exit_time, "priceSource": price_source}
    later = tuple(future_plan(stub, raw, horizon, step, lag, wait))
    return ExitPlan(index, entry_time, exit_time, entry_price, exit_price, economic, median_fee, later)


def liquidate(plan, size_percent, fee_percent, scenario, horizon, fee_mode, settings):
    bankroll = scenario["bankrollUSD"]
    buy_usd = size_percent * bankroll / 100
    units = buy_usd / plan.entry_price
    initial_capacity = plan.economic_volume_usd * scenario["participation"]
    first_units = min(units, initial_capacity / plan.exit_price) if plan.exit_price > 0 else 0.0
    remaining = units - first_units
    recovered = first_units * plan.exit_price
    base_exit_fee = fee_percent * bankroll / 200
    observed = plan.observed_exit_fee_usd
    extra = 0.0 if fee_mode == "saved_per_order" or observed is None else max(0.0, observed - base_exit_fee)
    per_order = base_exit_fee if fee_mode == "saved_per_order" or observed is None else max(base_exit_fee, observed)
    attempts = fills = 0
    busy_until = plan.original_exit_time
    settle_at = plan.original_exit_time
    for event in plan.later:
        if event["submitTime"] > plan.original_exit_time + horizon * 1000 or remaining <= units * 1e-12:
            break
        if event["submitTime"] < busy_until or event["flowUSD"] <= 0:
            continue
        attempts += 1
        extra += per_order
        if event["price"] is None:
            busy_until = event["submitTime"] + settings["saleWaitSeconds"] * 1000
            settle_at = busy_until
            continue
        cap = event["flowUSD"] * scenario["participation"]
        sold = min(remaining, cap / event["price"])
        remaining -= sold
        recovered += sold * event["price"]
        fills += 1
        busy_until = event["fillTime"]
        settle_at = busy_until
    if remaining > units * 1e-12:
        settle_at = max(settle_at, plan.original_exit_time + (horizon + settings["saleWaitSeconds"]) * 1000)
    return Sale(recovered, extra, settle_at, max(0.0, remaining / units), attempts, fills)


def replay(engine, outcome, settings, case, policy, scenario, limits, fees, plan_for,
           horizon=0, fee_mode="saved_per_order", excluded_tokens=(), excluded_days=()):
    a = engine.dataset.arrays
    cash = peak = 100.0
    blocked = -1
    seen = set()
    day = -1
    day_start = 100.0
    ledger = []
    closed_dd = 0.0
    for stage, choice in enumerate(engine.settings["choices"]):
        prefix = f"s{stage}_{case['history']}_"
        mask = engine.features[prefix + "mask"] & engine.groups[case["group"]]
        factor = engine.features[prefix + "factor"]
        selected = mask & np.isfinite(outcome["gross"])
        selected &= outcome["entry_time"] >= choice["cutoff"]
        selected &= outcome["admit_end"] < choice["cutoff"] + DAY
        indices = np.flatnonzero(selected)
        indices = indices[np.lexsort((indices, a["posted"][indices], outcome["entry_time"][indices]))]
        fraction = choice["policy"]["fraction"] * policy["scale"]
        budget = choice["policy"]["daily_budget"] if policy["budget"] == "saved" else policy["budget"]
        for i in indices:
            at = int(outcome["entry_time"][i])
            asset = int(a["asset"][i])
            asset_key = engine.dataset.meta["calls"][i]["assetKey"]
            if at < blocked or asset in seen or asset_key in excluded_tokens or at // DAY in excluded_days:
                continue
            if not np.isfinite(factor[i]) or factor[i] <= 0:
                continue
            fee = float(fees[i])
            limit = float(limits[i])
            if not np.isfinite(fee) or fee < 0 or not np.isfinite(limit) or limit < 0:
                continue
            if at // DAY != day:
                day, day_start = at // DAY, cash
            extra_orders = 0 if horizon == 0 else horizon // settings["stepSeconds"] - 1
            reserve = fee * (1 + extra_orders / 2)
            size = min(cash * min(0.075, fraction * factor[i]), limit, max(0.0, cash - reserve))
            if budget is not None:
                size = min(size, max(0.0, day_start * budget + cash - day_start - reserve))
            if not np.isfinite(size) or size <= 0.001:
                continue
            size = float(size)
            if horizon == 0:
                gross = float(outcome["gross"][i])
                extra_fee_usd = 0.0
                settled = int(outcome["exit_time"][i])
                residual, attempts, fills = 1.0 if gross == 0 else 0.0, 0, 0
            else:
                sale = liquidate(plan_for(i), size, fee, scenario, horizon, fee_mode, settings)
                gross = sale.recovered_usd / (size * scenario["bankrollUSD"] / 100)
                extra_fee_usd = sale.extra_fee_usd
                settled = sale.settled_at
                residual, attempts, fills = sale.remaining_fraction, sale.attempts, sale.fills
            net = float(gross * (1 - settings["cost"]) - 1)
            pnl = float(size * net - fee - extra_fee_usd * 100 / scenario["bankrollUSD"])
            cash += pnl
            peak = max(peak, cash)
            closed_dd = min(closed_dd, cash / peak - 1)
            blocked = settled
            seen.add(asset)
            ledger.append({"index": int(i), "assetKey": asset_key, "entryTime": at,
                           "originalExitTime": int(outcome["exit_time"][i]), "exitTime": settled,
                           "positionSize": float(size), "fixedFee": fee,
                           "extraExitFeeUSD": extra_fee_usd, "netReturn": net, "pnl": pnl,
                           "equityAfter": cash, "unsoldQuantityFraction": residual,
                           "extraAttempts": attempts, "extraFills": fills})
    return {"return": cash / 100 - 1, "closedDrawdown": closed_dd, "trades": len(ledger),
            "ledger": ledger, "extraAttempts": sum(t["extraAttempts"] for t in ledger),
            "extraFills": sum(t["extraFills"] for t in ledger),
            "unsoldQuantityFractions": sum(t["unsoldQuantityFraction"] for t in ledger)}


def check_baseline(actual, original, fields):
    assert actual["trades"] == original["trades"]
    assert len(actual["ledger"]) == len(original["ledger"])
    assert math.isclose(actual["return"], original["return"], rel_tol=1e-10, abs_tol=1e-10)
    for got, packed in zip(actual["ledger"], original["ledger"]):
        saved = dict(zip(fields, packed, strict=True))
        for field in ("index", "entryTime", "exitTime"):
            assert got[field] == saved[field]
        for field in ("positionSize", "fixedFee", "netReturn", "pnl", "equityAfter"):
            assert math.isclose(got[field], saved[field], rel_tol=1e-10, abs_tol=1e-10), (field, got[field], saved[field])


def run(folder):
    settings = read(folder / "settings.json")
    assert read(folder / "declaration.json")["settingsSha256"] == sha256(folder / "settings.json")
    assert settings["sourceCodeSha256"] == sha256(Path(__file__)) == sha256(folder / Path(__file__).name)
    for name, digest in settings["helperCodeSha256"].items():
        assert sha256(ROOT / name) == digest
    if (folder / "complete.json").exists():
        for name, digest in read(folder / "complete.json").items():
            assert sha256(folder / name) == digest
        print(json.dumps({"path": str(folder), "cached": True}))
        return
    source = Path(settings["source"])
    ss = verify(source)
    assert sha256(source / "results.json") == settings["sourceResultsSha256"]
    assert sha256(source / "portfolios.jsonl.gz") == settings["sourceLedgerSha256"]
    nine, extra = Path(settings["nineFlow"]), Path(settings["extraFlow"])
    assert sha256(nine / "requests.json") == settings["nineRequestsSha256"]
    assert sha256(extra / "requests.json") == settings["extraRequestsSha256"]
    for folder_name, folder_path in ((nine.name, nine), (extra.name, extra)):
        for item in read(folder_path / "requests.json")["requests"]:
            assert sha256(folder_path / "responses" / f"{item['id']}.json.gz") == settings["responseHashes"][f"{folder_name}/{item['id']}"]
    extended, overlap, old_hash = all_rows(settings, ss)
    accounts, key_fields = source_accounts(source, settings)
    ps = read(Path(ss["priceSource"]) / "settings.json")
    engine, selected, values, baseline, trades, raw, checks = initialize(ps)
    assert checks["responseSetSha256"] == old_hash
    parent_to_local = {int(parent): local for local, parent in enumerate(selected)}
    assert set(extended) == set(map(int, selected))
    with np.load(source / "route_data.npz", allow_pickle=False) as z:
        stored = {name: z[name] for name in z.files if name.startswith("15_")}
    choices = read(source / "pool_choices.json")
    rule = ConfirmedTarget(3.)
    summaries = defaultdict(list)
    counts = defaultdict(int)
    with gzip.open(folder / "accounts.jsonl.gz", "wt", encoding="utf-8", compresslevel=6) as output:
        for route_id in settings["routeIds"]:
            route = ss["routes"][route_id]
            for lag in sorted({s["entryLagSeconds"] for s in ss["scenarios"]}):
                if route_id == 0:
                    data, route_values, decisions = trades, None, None
                else:
                    data = {**trades, "bars": trades["bars"].copy(), "next": trades["next"].copy()}
                    data["bars"][selected] = stored[f"15_{lag}_bars"]
                    data["next"][selected] = stored[f"15_{lag}_next"]
                    route_values = stored[f"15_{lag}_values"]
                    decisions = choices[f"15_{lag}"]
                for price_source in ss["priceSources"]:
                    engine.set_prices(price_source, baseline, data, selected)
                    for si, scenario in enumerate(ss["scenarios"]):
                        if scenario["entryLagSeconds"] != lag:
                            continue
                        outcome = engine.use_rule(rule, scenario)
                        for mode in settings["modes"]:
                            limits, fees = route_inputs(engine, selected, values, route_values, decisions,
                                                        route, mode, scenario)
                            plan_cache = {}
                            def plan_for(i):
                                if i not in plan_cache:
                                    parent = int(i)
                                    pool = None if route_id == 0 else decisions[parent_to_local[parent]]["selectedPool"]
                                    plan_cache[i] = exit_plan(parent, pool, price_source, engine.data, outcome,
                                        extended[parent], max(settings["horizonsSeconds"]), settings["stepSeconds"],
                                        settings["informationLagSeconds"], settings["saleWaitSeconds"])
                                    counts["builtExitPlans"] += 1
                                return plan_cache[i]
                            for history, group, pi in product(ss["histories"], ss["groups"], range(len(ss["policies"]))):
                                case, policy = {"history": history, "group": group}, ss["policies"][pi]
                                key = (route_id, price_source, mode, history, group, pi, si)
                                original = accounts[key]
                                control = replay(engine, outcome, settings, case, policy, scenario, limits, fees, plan_for)
                                check_baseline(control, original, ss["ledgerFields"])
                                counts["exactBaselineAccounts"] += 1
                                identity = dict(zip(key_fields, key, strict=True))
                                for horizon, fee_mode in product(settings["horizonsSeconds"], settings["feeModes"]):
                                    base_result = replay(engine, outcome, settings, case, policy, scenario,
                                                         limits, fees, plan_for, horizon, fee_mode)
                                    gains, daily = defaultdict(float), defaultdict(float)
                                    for trade in base_result["ledger"]:
                                        gains[trade["assetKey"]] += trade["pnl"]
                                        daily[trade["entryTime"] // DAY] += trade["pnl"]
                                    best_two = sorted(gains, key=lambda asset: (-gains[asset], asset))[:2]
                                    best_day = [max(daily, key=lambda day: (daily[day], -day))] if daily else []
                                    removed = replay(engine, outcome, settings, case, policy, scenario,
                                                     limits, fees, plan_for, horizon, fee_mode,
                                                     excluded_tokens=best_two)
                                    absent_day = replay(engine, outcome, settings, case, policy, scenario,
                                                        limits, fees, plan_for, horizon, fee_mode,
                                                        excluded_days=best_day)
                                    result = {**identity, "horizonSeconds": horizon, "feeMode": fee_mode,
                                              "baselineReturn": original["return"],
                                              **base_result, "withoutTwoBest": removed["return"],
                                              "withoutBestDay": absent_day["return"],
                                              "twoBestTokens": best_two, "bestDay": best_day,
                                              "withoutTwoBestTrades": removed["trades"],
                                              "withoutBestDayTrades": absent_day["trades"]}
                                    output.write(json.dumps(result, separators=(",", ":")) + "\n")
                                    summaries[route_id, pi, horizon, fee_mode].append(result)
                                    counts["fullAccounts"] += 1
                                    counts["exclusionAccounts"] += 2
                print(json.dumps({"routeId": route_id, "entryLagSeconds": lag,
                                  "fullAccounts": counts["fullAccounts"], "builtExitPlans": counts["builtExitPlans"]}), flush=True)
    (folder / "accounts.jsonl.gz").chmod(0o400)
    assert counts["exactBaselineAccounts"] == 1600 and counts["fullAccounts"] == 9600
    result = {"path": str(folder), "checks": dict(counts), "overlap": overlap,
              "oldResponseSetSha256": old_hash,
              "summary": [{"routeId": route, "policyId": policy, "horizonSeconds": horizon,
                           "feeMode": fee_mode, "accounts": len(rows),
                           "minimumReturn": min(row["return"] for row in rows),
                           "minimumTrades": min(row["trades"] for row in rows),
                           "worstClosedDrawdown": min(row["closedDrawdown"] for row in rows),
                           "minimumWithoutTwoBest": min(row["withoutTwoBest"] for row in rows),
                           "minimumWithoutBestDay": min(row["withoutBestDay"] for row in rows),
                           "negativeAccounts": sum(row["return"] < 0 for row in rows),
                           "positiveAfterBothRemovals": sum(row["withoutTwoBest"] > 0 and row["withoutBestDay"] > 0 for row in rows),
                           "activityChanges": sum(row["trades"] != 8 and row["trades"] != 9 for row in rows)}
                          for (route, policy, horizon, fee_mode), rows in summaries.items()],
              "scope": settings["scope"]}
    write_json(folder / "results.json", result, 0o400)
    write_json(folder / "complete.json", {name: sha256(folder / name) for name in (
        "settings.json", "declaration.json", "full_staged_account_lab.py", "accounts.jsonl.gz", "results.json")}, 0o400)
    print(json.dumps({"path": str(folder), "checks": dict(counts), "overlap": overlap}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "run"))
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    else:
        run(Path(read(ROOT / "full_staged_account_runs/latest.json")["path"]))
