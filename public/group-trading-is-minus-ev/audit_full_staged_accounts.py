"""Scalar raw-flow and double-entry cash audit of full staged-sale accounts."""

import gzip
import json
import math
import shutil
from collections import defaultdict
from pathlib import Path

import numpy as np

from audit_staged_exit_capacity import economic_flow, plan_for
from full_staged_account_lab import all_rows, source_accounts
from research_dataset import DAY, sha256, write_json


ROOT = Path(__file__).resolve().parent
read = lambda path: json.loads(Path(path).read_text())


def close(a, b):
    assert math.isclose(a, b, rel_tol=1e-10, abs_tol=1e-10), (a, b)


def observed_fee(rows, cutoff, pool):
    by_transaction = {}
    for row in rows:
        if cutoff - 60000 <= row["date"] <= cutoff and (pool is None or row["pool"] == pool) and \
                row["type"] in ("buy", "sell") and row["gas_mev"] is not None and \
                isinstance(row["usd"], (int, float)) and row["usd"] > 0 and \
                isinstance(row["quantity"], (int, float)) and row["quantity"] > 0:
            by_transaction[row["transaction"]] = max(by_transaction.get(row["transaction"], 0.0), row["gas_mev"])
    return float(np.median(list(by_transaction.values()))) if by_transaction else None


def main():
    folder = Path(read(ROOT / "full_staged_account_runs/latest.json")["path"])
    for name, digest in read(folder / "complete.json").items():
        assert sha256(folder / name) == digest
    settings = read(folder / "settings.json")
    source = Path(settings["source"])
    ss = read(source / "settings.json")
    old_accounts, fields = source_accounts(source, settings)
    rows, overlap, response_hash = all_rows(settings, ss)
    saved_results = read(folder / "results.json")
    assert response_hash == saved_results["oldResponseSetSha256"] and overlap == saved_results["overlap"]
    price_source = Path(ss["priceSource"])
    trade_source = Path(read(price_source / "settings.json")["tradeSource"])
    parents = read(trade_source / "settings.json")["parentIndices"]
    local_by_parent = {parent: local for local, parent in enumerate(parents)}
    choices = read(source / "pool_choices.json")
    with np.load(price_source / "trade_seconds.npz", allow_pickle=False) as original, np.load(
            source / "route_data.npz", allow_pickle=False) as routed:
        trade_seconds = {name: original[name] for name in original.files}
        pool_seconds = {name: routed[name] for name in routed.files if name.endswith("_bars")}
    plan_cache, summaries, counts = {}, defaultdict(list), defaultdict(int)
    with gzip.open(folder / "accounts.jsonl.gz", "rt") as stream:
        for line in stream:
            account = json.loads(line)
            key = tuple(account[field] for field in fields)
            original = old_accounts[key]
            close(account["baselineReturn"], original["return"])
            assert account["trades"] == len(account["ledger"])
            assert [t["index"] for t in account["ledger"]] == [t[0] for t in original["ledger"]]
            scenario = ss["scenarios"][account["scenarioId"]]
            route = ss["routes"][account["routeId"]]
            lag = scenario["entryLagSeconds"]
            cash = peak = scenario["bankrollUSD"]
            dd = unsold_total = 0.0
            attempts_total = fills_total = 0
            seen = set()
            prior_settlement = -1
            gains, daily = defaultdict(float), defaultdict(float)
            for trade, packed in zip(account["ledger"], original["ledger"]):
                old = dict(zip(ss["ledgerFields"], packed, strict=True))
                parent = trade["index"]
                assert trade["entryTime"] == old["entryTime"]
                assert trade["originalExitTime"] == old["exitTime"]
                assert trade["entryTime"] >= prior_settlement
                assert trade["assetKey"] not in seen
                seen.add(trade["assetKey"])
                local = local_by_parent[parent]
                pool = None if account["routeId"] == 0 else choices[f"15_{lag}"][local]["selectedPool"]
                bars = trade_seconds["bars"][local] if pool is None else pool_seconds[f"15_{lag}_bars"][local]
                base = int(trade_seconds["base"][local])
                entry_second = (trade["entryTime"] - base) // 1000
                exit_second = (trade["originalExitTime"] - base) // 1000
                adverse = account["priceSource"] == "adverse_prints"
                entry_price = float(bars[entry_second, 1 if adverse else 0])
                exit_price = float(bars[exit_second, 2 if adverse else 0])
                close(exit_price / entry_price, (old["netReturn"] + 1) / (1 - settings["cost"]))
                scheduled = trade["originalExitTime"]
                cutoff = scheduled - settings["informationLagSeconds"] * 1000
                volume = economic_flow(rows[parent], cutoff - 60001, cutoff, pool)
                median = observed_fee(rows[parent], cutoff, pool)
                plan_key = parent, pool, scheduled, account["priceSource"]
                if plan_key not in plan_cache:
                    plan_cache[plan_key] = plan_for(rows[parent], {"pool": pool, "exitTime": scheduled},
                        account["priceSource"], max(settings["horizonsSeconds"]),
                        settings["stepSeconds"], settings["informationLagSeconds"], settings["saleWaitSeconds"])
                buy_usd = trade["positionSize"] * scenario["bankrollUSD"] / 100
                units = buy_usd / entry_price
                first = min(units, volume * scenario["participation"] / exit_price)
                remaining = units - first
                recovered = first * exit_price
                saved_exit_fee = trade["fixedFee"] * scenario["bankrollUSD"] / 200
                additional = 0.0 if account["feeMode"] == "saved_per_order" or median is None else max(0.0, median - saved_exit_fee)
                per_order = saved_exit_fee if account["feeMode"] == "saved_per_order" or median is None else max(saved_exit_fee, median)
                attempts = fills = 0
                busy_until = scheduled
                settlement = scheduled
                for submitted, flow_usd, filled_at, price in plan_cache[plan_key]:
                    if submitted > scheduled + account["horizonSeconds"] * 1000 or remaining <= units * 1e-12:
                        break
                    if submitted < busy_until or flow_usd <= 0:
                        continue
                    attempts += 1
                    additional += per_order
                    if filled_at is None:
                        busy_until = submitted + settings["saleWaitSeconds"] * 1000
                        settlement = busy_until
                        continue
                    sold = min(remaining, flow_usd * scenario["participation"] / price)
                    remaining -= sold
                    recovered += sold * price
                    fills += 1
                    busy_until = filled_at
                    settlement = filled_at
                if remaining > units * 1e-12:
                    settlement = max(settlement, scheduled + (account["horizonSeconds"] + settings["saleWaitSeconds"]) * 1000)
                close(trade["netReturn"], recovered / buy_usd * (1 - settings["cost"]) - 1)
                close(trade["extraExitFeeUSD"], additional)
                close(trade["unsoldQuantityFraction"], max(0.0, remaining / units))
                assert trade["extraAttempts"] == attempts and trade["extraFills"] == fills
                assert trade["exitTime"] == settlement
                before = cash
                cash -= buy_usd + trade["fixedFee"] * scenario["bankrollUSD"] / 100 + additional
                cash += recovered * (1 - settings["cost"])
                close(trade["pnl"], (cash - before) * 100 / scenario["bankrollUSD"])
                close(trade["equityAfter"], cash * 100 / scenario["bankrollUSD"])
                peak = max(peak, cash)
                dd = min(dd, cash / peak - 1)
                prior_settlement = settlement
                unsold_total += trade["unsoldQuantityFraction"]
                attempts_total += attempts
                fills_total += fills
                gains[trade["assetKey"]] += trade["pnl"]
                daily[trade["entryTime"] // DAY] += trade["pnl"]
                counts["scalarSaleChecks"] += 1
            close(account["return"], cash / scenario["bankrollUSD"] - 1)
            close(account["closedDrawdown"], dd)
            close(account["unsoldQuantityFractions"], unsold_total)
            assert account["extraAttempts"] == attempts_total and account["extraFills"] == fills_total
            assert account["twoBestTokens"] == sorted(gains, key=lambda asset: (-gains[asset], asset))[:2]
            assert account["bestDay"] == ([max(daily, key=lambda day: (daily[day], -day))] if daily else [])
            summaries[account["routeId"], account["policyId"], account["horizonSeconds"], account["feeMode"]].append(account)
            counts["accountChecks"] += 1
    assert counts["accountChecks"] == 9600
    assert len(saved_results["summary"]) == len(summaries) == 24
    for row in saved_results["summary"]:
        bank = summaries[row["routeId"], row["policyId"], row["horizonSeconds"], row["feeMode"]]
        assert row["accounts"] == len(bank) == 400
        for name, expected in (("minimumReturn", min(t["return"] for t in bank)),
                               ("minimumTrades", min(t["trades"] for t in bank)),
                               ("worstClosedDrawdown", min(t["closedDrawdown"] for t in bank)),
                               ("minimumWithoutTwoBest", min(t["withoutTwoBest"] for t in bank)),
                               ("minimumWithoutBestDay", min(t["withoutBestDay"] for t in bank)),
                               ("negativeAccounts", sum(t["return"] < 0 for t in bank)),
                               ("positiveAfterBothRemovals", sum(t["withoutTwoBest"] > 0 and t["withoutBestDay"] > 0 for t in bank))):
            close(row[name], expected)
        counts["summaryChecks"] += 1
    audit = {"resultsSha256": sha256(folder / "results.json"),
             "accountsSha256": sha256(folder / "accounts.jsonl.gz"),
             "auditorSha256": sha256(Path(__file__)), "checks": dict(counts),
             "scope": "Recomputes every recorded sale with independently netted raw target-token flow and future trade prints; checks double-entry cash, settlement overlap, token uniqueness, winner/day selection, and summary extrema. Exact source-account baseline parity is checked by the lab itself. Exclusion-account admissions are not independently replayed by this audit."}
    write_json(folder / "full_staged_audit.json", audit, 0o400)
    shutil.copyfile(Path(__file__), folder / Path(__file__).name)
    (folder / Path(__file__).name).chmod(0o400)
    print(json.dumps(audit))


if __name__ == "__main__":
    main()
