# Offline strategy research

The research runner uses a frozen local dataset. It makes no Telegram or Mobula requests and needs no credentials. Python and NumPy are sufficient; the NumPy version is pinned in `requirements-research.txt`.

The original saved data covers the available group history from October 16 through October 21, 2026: 14,273 messages, 581 token candidates, 1,814 token calls before filtering, and 1,066 eligible first calls per sender and contract across 512 contracts and 44 senders. The corrected training dataset has 1,100 eligible calls. The latest combined archive has 14,440 messages and 1,130 eligible first calls across 534 contracts and 45 senders; later collections are kept separate from training. A separate repeated-call dataset preserves the 1,100 original training calls and adds 406 calls from those same historical dates, covering 547 contracts in total.

## Latest findings and finer execution data

Open `latest_research_report.html` for the current comparison and links to the detailed runs.

The public research page is [group-trading-is-minus-ev](https://nik.technology/group-trading-is-minus-ev).
Its Nuxt route lives in `~/nik.technology/app/pages/group-trading-is-minus-ev.vue`.
`publish_group_research.py ~/nik.technology` exports explicitly selected aggregate results, anonymous caller rows,
the baseline CSV and SVG figures. Update its dated source snapshot and the article together when publishing new findings.
The public page uses a separate snapshot from this continually updated local report.

### Pool execution, matched controls and sale capacity

`pool_route_runs/e66b2ccb15936ba6` adds **54,000 accounts**: 48,000 routing comparisons and 6,000 earlier controls. Twelve rules choose the largest economic-volume pool using a 15-, 30- or 60-second lookback ending five seconds before planned entry. Minimum pool shares are 0%, 75%, 90% and 95%. Positions stay in the chosen pool through the original 3× target or five-minute timeout. Capacity nets target quantities within each transaction and recipient across pools, then assigns the net volume to pools proportionally. Missing entry prices remain skipped; missing sales receive zero recovery.

All twelve three-quarter-allocation variants pass the initial concentration screen under the **two entry-time capacity modes**. Half allocation fails. The twelve passing variants share the same headline values. `pool_route_pair_runs/9983a565c6852c8b` subsequently checks **166,400 exhaustive pair removals across 5,200 opportunity universes**, including entries skipped by the original account:

| Allocation multiplier | Smallest return | Largest DD bound | Smallest return after any token pair |
| --- | ---: | ---: | ---: |
| 0.5× | +0.7970% | 0.6419% | −0.06487% |
| 0.75× | +1.1979% | 0.9414% | +0.02831% |

These are separate extrema over ordinary and unfavorable swap prices, both reference histories, both caller populations, execution delays, participation limits and bankrolls, at a 10% proceeds haircut plus fees. The declared risk ranking selects the 15-second/no-minimum-share rule at three-quarter allocation for drawdown ceilings of 1% or more. The 0.5% and 0.75% ceilings select no candidate. Only eight or nine historical trades support these results.

**Matching the control modes changes the interpretation.** The earlier all-pool comparison included an additional quote-time-only capacity estimate. `pool_matched_runs/37670c55140375aa` pairs all 48,000 new accounts with identical control modes. At three-quarter allocation, the matched all-pool minimum is **+1.1978759%**, versus **+1.1978560%** for the chosen pool; the initial winner-removal minima are **+0.0283285%** and **+0.0283087%**. Pool selection adds no improvement to these minima. The positive margin is already present when the all-pool comparison uses the same entry-time capacity estimates. Dropping a different control must not be mistaken for a benefit from routing.

The pair tester computes 30,700 accounts and reuses 135,700 exact input/path matches, avoiding 81.6% of duplicate account calculations. Equality covers potential opportunities, sizing, capacity, fees, exits and excluded tokens, plus the complete normalized-path digest. Comparing only realized base ledgers would miss trades made possible by removing a token.

`exit_capacity_runs/bda9d7cbbf30c386` checks the exit assumption separately. It inspects 10,800 original accounts, or 91,800 repeated trade usages, and stores 9,260 distinct sale cases. **161 chosen-pool sale cases exceed the entry model's volume-participation limit when measured again before the sale.** At a $1,000 bankroll, the largest chosen-pool sale is approximately 2.38 times that proxy limit; the three-quarter allocation has affected scenarios on two original opportunities. Another 656 chosen-pool cases have a higher exit-time gas/MEV estimate than half the modeled round-trip fee. This diagnostic does not filter entries using future information and does not compute an adjusted profit. Sale liquidity and fees must be modeled before the small positive margin can support a trading conclusion.

The second unchanged source-filter observation is complete and audited: **185 original message updates, 32 token signals, 22 eligible quotes and zero trades** across 24 paper accounts. Five quotes lacked valid prices and five violated timestamp rules. The first two source-filter windows now contain 47 eligible calls and no qualifying entries. A third unchanged protocol froze at **15:34:55 UTC on October 21**, carries all **1,194 audited context calls**, and began its 30-minute capture at **15:35:22 UTC**. Its automatic validator will wait nine minutes after closure for full price horizons. Observation gaps remain unobserved.

Reproduce the studies and report:

```sh
rtk python pool_route_lab.py run
rtk python audit_pool_routes.py
rtk python pool_route_pairs.py run
rtk python pool_route_pairs.py audit
rtk python pool_matched_controls.py
rtk python exit_capacity_diagnostics.py
rtk .plot-venv/bin/python plot_pool_routes.py
rtk python context_research_report.py
rtk python check_pool_research.py
rtk python audit_research_artifacts.py
```

### Full price-stressed exit grid and sizing response

Two further studies add **231,000 accounts**. Neither produces a setting that passes the declared joint price, sample and concentration checks.

`swap_target_runs/0b6bf67a999c9ecd` extends all 28 existing exit rules to both recorded-swap price models: **168,000 new accounts**, alongside the 84,000 audited vendor-price controls. Among the 56 rule/allocation combinations, 26 pass with vendor candles, 12 with ordinary swap candles, and **zero with unfavorable prints**. Every combination has a negative two-best-token removal in at least one control. The best such minimum is −0.0739%, so all five predeclared drawdown ceilings select no candidate. The explicit losing pair is sufficient to reject an all-pairs-positive claim for each setting.

The tester computed 55,372 accounts and safely reused 112,628 exact input matches, completing the sweep in 305.6 seconds. That avoids 67.0% of duplicate account computations; it is not a measured 67% reduction in wall-clock time. The separate audit checks every saved record, all 7,392 potential scalar sales and all 6,000 earlier swap-price control ledgers. Each price source has its own cache.

`allocation_strength_runs/9ac3b5267bfe5ab3` tests **63,000 accounts** with seven responses to the saved volatility/cohort sizing factor. A valid factor `f` becomes `clip(1 + a * (f - 1), 0.1, 1.5)`. Strength `a = 0` removes variation between valid factors; capacity and daily-budget limits still affect actual order sizes. Strength one preserves the previous formula exactly. Missing or invalid factors never become eligible. All entries, 3× exit triggers, five-minute timeouts, fee/capacity estimates and the 1% daily full-loss budget stay fixed.

Separate extrema across all 900 price/history/population/execution/flow controls at a 10% proceeds haircut plus fees are:

| Factor response | Allocation multiplier | Smallest return | Largest DD bound | After two best tokens |
| --- | ---: | ---: | ---: | ---: |
| Constant valid factor (`a = 0`) | 0.75× | +0.632% | 1.601% | −0.4532% |
| Previous formula (`a = 1`) | 0.75× | +1.080% | 0.943% | −0.0739% |
| Stronger response (`a = 1.5`) | 0.75× | +0.448% | 0.638% | −0.0468% |
| Stronger response (`a = 1.5`) | 0.5× | +0.306% | 0.426% | −0.0669% |

Stronger sizing can lower modeled drawdown, but it also reduces return and still fails concentration checks. None of the 14 strength/allocation combinations passes all price models. These remain comparisons on eight or nine historical trades, not independent evidence of a profitable edge.

A second unchanged source-filter protocol was frozen at **14:53:08 UTC on October 21**, using all 1,172 audited context calls. Its 30-minute capture began at **14:53:17 UTC** and is now complete: 22 eligible calls and zero entries. The earlier completed window remains separately reported: 25 eligible calls and zero entries. Gaps between windows remain unobserved.

Reproduce these studies from cache:

```sh
rtk python swap_target_lab.py run
rtk python audit_swap_targets.py
rtk python allocation_strength_lab.py run
rtk python audit_allocation_strength.py
rtk .plot-venv/bin/python plot_sizing_robustness.py
rtk python context_research_report.py
rtk python check_sizing_robustness.py
rtk python audit_research_artifacts.py
```

### Recorded swap prices weaken the concentration result

The preceding research added target confirmation, actual swap-price reconstruction, and a completed frozen receipt-time observation. The earlier favorable candle-price results below remain historical comparisons. **Neither tested allocation passes the adverse-price concentration check.**

`confirmed_target_runs/96694f20f95c2f74` contains **84,000 accounts** covering 2×/3×/4× targets, high/close/low confirmation for 1/3/5 consecutive seconds, and a 300-second timeout. Missing seconds reset confirmation. Sales use the next observed market price after a declared reaction delay. Longer confirmation does not improve the predeclared worst-case selection; the original 3× one-second-high trigger remains selected. Another **28,800 exhaustive token-pair removals** keep both original allocations and the strict five-second-low diagnostic. The strict diagnostic fails, reaching −0.0815% after a pair removal.

`execution_trade_runs/c086dd62f77f03fa` saves complete transaction pages for all eleven potentially eligible opportunities. All 171 distinct modeled entry/exit price points have a swap in the same second; 128 have a price within 1%, and 170 within 5%. The largest closest-price discrepancy is 5.85%. This establishes observed prices, not executable routes or size.

`execution_price_runs/8f1bef0d6d9c23e9` rebuilds 3,215 seconds from 17,087 valid swaps and runs **9,000 accounts**. Entry features stay fixed to isolate execution-price sensitivity. Each row below gives separate extrema across 300 history/population/execution/flow controls at a 10% proceeds haircut plus estimated fees. The multiplier applies to the saved daily allocation rules; every case uses a 1% daily full-loss budget.

| Price model | Allocation multiplier | Smallest return | Largest DD bound | After removing two best tokens |
| --- | ---: | ---: | ---: | ---: |
| Vendor candles | 0.5× | +0.972% | 0.630% | +0.0592% |
| Vendor candles | 0.75× | +1.364% | 0.943% | +0.1494% |
| Recorded swap candles | 0.5× | +0.919% | 0.629% | −0.0029% |
| Recorded swap candles | 0.75× | +1.362% | 0.941% | +0.0700% |
| Entry-second high / exit-second low | 0.5× | +0.732% | 0.642% | −0.1287% |
| Entry-second high / exit-second low | 0.75× | +1.080% | 0.862% | −0.0739% |

The last price model is a hindsight bound within each fill second, not a causal order-placement rule. Changing entry prices also changes target timing and later account decisions; a smaller drawdown in one row does not establish lower future risk. An additional exhaustive pair study covers both swap-price models and both allocations, including every failed setting. Its exact minima and every ledger are linked from the HTML report.

The independent price audit reconstructs raw target-leg prices and pagination, checks every stored bar and price-point comparison, verifies all 396 potential scalar sales, replays all 9,000 accounts, and reproduces all 3,000 prior vendor-price ledgers. Only eight or nine historical trades support these comparisons. Repeated parameter searches do not add independent observations.

The source-filter protocol frozen at **13:59:05 UTC on October 21** then observed **30 minutes** of new Telegram message versions. Its capture contains 108 original updates; 30 token signals produced 25 eligible quotes. Five quotes failed the frozen timestamp rules. All six candidates and 24 cost/execution comparisons made **zero trades**. Every eligible quote failed the unchanged market-condition gate: the mean of its last five completed reference returns ranged from −42.3% to −23.4%, below the required −10%. The final history snapshot covers only its last 100 messages, so its reconciliation is limited to that page. The capture and all paper accounts were audited; this window supplies no profitability evidence.

Reproduce the cached research and audits:

```sh
rtk python confirmed_target_lab.py
rtk python audit_confirmed_targets.py
rtk python confirmed_target_pairs.py run
rtk python confirmed_target_pairs.py audit
rtk python execution_price_lab.py
rtk python audit_execution_prices.py
rtk python execution_price_pairs.py run
rtk python execution_price_pairs.py audit
rtk .plot-venv/bin/python plot_execution_confirmation.py
rtk python context_research_report.py
rtk python check_execution_research.py
rtk python audit_research_artifacts.py
```

### Reference matching and transaction conditions before entry

The preceding follow-up added **49,000 accounts**: 30,000 reference-filter comparisons, 3,000 pre-entry flow comparisons and 16,000 exhaustive pair removals. Reference definitions cross account source, maximum outcome age, chain and fine market-cap buckets ($6k/$10k/$25k/$50k/$100k/$250k/$1m). Unrestricted global references from all recoverable calls or non-bot calls pass the full historical screen; freshness and cap matching do not. Same-chain histories sometimes improve return but fail the eight-trade sample requirement.

Measuring economic volume and fees five seconds before the scheduled entry gives a minimum +1.815% return and 0.943% drawdown bound at three-quarter allocation, across 100 controls with vendor prices and 10% proceeds cost plus fees. Requiring both call-time and entry-time estimates gives +1.364%. These earlier candle-price comparisons should be read alongside the swap-price sensitivity above. The frozen observation rules were not changed by either experiment.

### Caller categories and a common allocation across controls

`fixed_entry_source_runs/1cac24f915ec063b` adds **224,000 portfolio comparisons** using the same three saved daily entries, five-minute exits and cached market data. Four filters distinguish non-bot accounts, bots, bot replies linked to verified requests, and non-bot posts plus those requested scans. These cross four original/expanded and all/recoverable-text populations, two reference histories, 35 allocation/budget settings, 2×/3× targets and all 25 execution scenarios. The minimum sample threshold remains eight trades.

The result contains **205 passing policy/history/population combinations and 65 distinct observed ledger sets**. Non-bot accounts pass with both all-text and recoverable-text entry controls. Their executed trades happen to have recovered text, so an explicit recovery filter is unnecessary for those ledgers. The reference histories retain their own historical availability limitations. A non-bot account flag does not establish whether a person manually wrote the post.

Bot-only and requested-bot-only settings fail the combined sample, execution and concentration criteria. Some still have positive unablated returns; this does not prove that all future bot calls have negative expected value. The requested-scan union passes some recoverable-text cases but fails the all-text controls.

`fixed_source_pair_runs/939235639ea5e6ef` requires a **single target and allocation policy to pass both histories and both original/expanded non-bot call sets**. Twenty-one settings meet that joint requirement. Eight declared drawdown ceilings from 0.25% to 5% choose the greatest minimum return below each ceiling. The earlier half-size/1%-budget case is retained. No joint grid setting meets the 0.25% ceiling.

Six distinct policies remain, all with a 3× full-position target and a five-minute timeout. Separate extrema across all **100 history/population/execution combinations** at a 10% proceeds haircut plus estimated fees are:

| Multiplier on saved daily allocations | Daily full-loss budget | Smallest return | Largest DD bound | Smallest return after any token pair |
| --- | --- | ---: | ---: | ---: |
| 0.25× | Saved daily budgets | +0.489% | 0.345% | +0.0164% |
| 0.5× | 1% | +0.972% | 0.630% | +0.0592% |
| 0.75× | 1% | +1.373% | 0.943% | +0.1494% |
| 1.5× | 1% | +1.655% | 1.033% | +0.0485% |
| 1.5× | 2% | +2.404% | 1.876% | +0.0767% |
| 2× | 2% | +2.863% | 2.057% | +0.0097% |

The **0.75× allocation / 1% daily budget** has the highest worst-case return among grid settings below a 1% modeled drawdown bound. These bounds are not future guarantees or live stop rules. The multiplier applies to the three different saved daily sizing procedures; it is not the fraction of the account invested in each position.

All **19,200 exhaustive token-pair removals** remain positive, spanning 600 eligible universes with eight or nine contracts. The universe includes eligible signals skipped by the original account, so removals can change later admissions. Every pair account and stored minimum ledger is independently verified. The smallest margins remain thin, and the accounts contain only eight or nine trades from already examined dates. The new caller filter was investigated after the earlier outcomes were examined.

The source audit rebuilds all 1,506 sender flags and 602 accepted request associations, then verifies 24,096 source-membership values, all 224,000 ledgers, **1,476,782 trade calculations** and **19,688 complete admission replays**. It reconstructs all 2,240 scenario summaries and verifies complete planned price windows.

The tester now reuses portfolios whose possible entry masks and sizing factors match under conservative clock bounds. This avoids 77,000 repeated calculations and reduces runtime from **89.2 to 71.4 seconds**. All 112,000 base metric rows and all 224,000 complete portfolio records exactly match the unpruned run at `fixed_entry_source_runs/a55f74353d3a8e95`. The audit separately proves the clock bounds and all 21 equivalence classes. The exhaustive pair study runs in 20.5 seconds.

```sh
rtk python analysis/ayugram-token-strategy/fixed_entry_source_lab.py
rtk python analysis/ayugram-token-strategy/audit_fixed_entry_sources.py
rtk python analysis/ayugram-token-strategy/fixed_source_risk_pairs.py
rtk python analysis/ayugram-token-strategy/audit_fixed_source_pairs.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_fixed_source_risk.py
```

### Allocation size and exhaustive token-pair removal

`fixed_entry_size_runs/4bc799c236dfe4bf` adds **56,000 portfolios in 40.8 seconds**. Seven allocation multipliers from 0.125× to 2× combine with the saved daily budgets, no budget, or 1%/2%/4% daily full-loss budgets. The comparison retains two reference histories, four call populations, 2×/3× five-minute targets, 25 execution scenarios and 5%/10% proceeds haircuts plus estimated fees. Cached paths and outcomes are reused across portfolios.

Before caller-category filtering, nine policy/history combinations survive all 25 scenarios, two-winner removal and best-day removal at 10% cost. They represent six distinct observed ledger sets. **Every survivor in this earlier sizing study uses nine original calls with recoverable text and the 3× target. No unfiltered all-text or expanded-call setting passes every check.** The all-text controls include one traded KIM call from the scan bot whose original text is unavailable. Its inclusion changes robustness classifications; these controls do not establish whether its address was historically available.

Selected examples using recoverable reference history, all at 10% cost:

| Multiplier on saved daily allocations | Daily full-loss budget | Smallest return across 25 scenarios | Largest DD bound | Smallest return after any token pair | Smallest return without best day |
| --- | --- | ---: | ---: | ---: | ---: |
| 0.5× | 1% | +0.934% | 0.630% | +0.022% | +0.312% |
| 0.75× | 1% | +1.329% | 0.943% | +0.094% | +0.538% |
| 1× | 1% | +1.532% | 1.033% | +0.050% | +0.702% |

These are separate extrema across scenarios, not one account path. The multiplier applies to the three different saved daily policies described below. The daily budget limits the purchase amount that could be lost, rather than creating a price stop. The smallest remaining margins are thin, and all rows reuse the same examined dates.

`fixed_entry_pair_runs/01a385dd99ab400d` enumerates **all 36 token pairs in each of 225 eligible universes**, for **8,100 additional portfolios in 13.3 seconds**. It removes pairs from the entire eligible universe, so subsequent admissions can change with the account's remaining daily budget. All nine surviving combinations remain positive after every pair in every scenario. This remains a nine-trade historical comparison, not independent profit evidence.

`audit_fixed_entry_size.py` independently checks all 56,000 saved ledgers and 528,959 executed-trade calculations, plus 1,771 complete admission replays and every scenario summary. `audit_fixed_entry_pairs.py` reconstructs every eligible universe, verifies that each pair appears exactly once, and independently replays all 8,100 accounts. Every planned observation window is complete. Numeric figure data and PNG/SVG plots are saved with the sizing run.

Run sequentially from the repository root:

```sh
rtk python analysis/ayugram-token-strategy/fixed_entry_size_lab.py
rtk python analysis/ayugram-token-strategy/audit_fixed_entry_size.py
rtk python analysis/ayugram-token-strategy/fixed_entry_pair_lab.py
rtk python analysis/ayugram-token-strategy/audit_fixed_entry_pairs.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_fixed_entry_size.py
```

### Frozen short-target observation with original message versions

`arrival_protocols/20261021_130725_426526/protocol.json` froze the next paper comparison at **13:07:25.426 UTC**, before its message capture. It keeps the latest saved entry rule, a 3× full-position target, a five-minute timeout, a 1% daily full-loss budget, one position and one purchase per contract. The primary candidate uses the first valid observed caller/contract call and a 2.5% allocation weighted by first-minute volatility. Two controls admit repeated calls with 2.5% or 1.25% allocations. All three retain the same capacity, fee and delayed-fill rules. Base costs are 5%/10%/15%; an additional 10% case adds five-second entry/reaction delays and halves volume participation.

Capture `live_message_captures/20261021T130737288Z_f62bfed9` ran from **13:07:40.157 to 13:17:40.163 UTC**. It preserves 63 eligible original versions, including six later edited originals. Causal extraction produces 22 token signals across eight contracts. Signal availability is local receipt time. One contract can produce only one first-mention signal per Telegram message; edits never rewrite an earlier signal. Both quote and swap timestamps must precede receipt and be no more than sixty seconds old.

The context is fixed at 12:18:39.820 UTC. The gap before capture readiness remains unobserved and is not retrospectively filled. The validator manifest records its pre-market-data implementation revision, which adds cache reuse and complete merged raw metadata without changing trading rules. Collection waits until the capture has been closed for nine minutes, covering all planned positions before prices are retrieved. Historical market data is still retrieved later, so this observation does not measure actual API delivery latency or executable AMM fills.

The saved protocol and source hashes stay fixed throughout validation. Replays retain all calls, exclusions and all twelve candidate/cost/execution cases. The independent audit checks observed-version links, quote eligibility, first-call flags, preserved context, reconstructed minute features, causal cohort values and complete paper accounts.

The first replay exposed an acquisition error: the reused `fetch_mobula.mjs` collector requests minute candles only for the first caller/contract call. Five repeated-call series were therefore missing. That initial 12-call result and its audit remain saved. `complete_arrival_candles.mjs` retrieves all five missing series at the **original market cutoff**, preserving every original quote and existing candle series. It writes a separate correction under `implementation_corrections/9f0fda5c6b7ca095`; the original and corrected trading-protocol hashes are identical. This correction occurred after the first incomplete replay, so it is documented as an implementation correction of the same observation.

The corrected replay has **17 valid-quote calls, 14 first observed caller/contract calls and three repeats**. Five other quotes contain quote or swap timestamps after observed receipt and remain excluded. Seven valid calls meet the cap range, one meets the first-minute dip condition, and none meets both. **All twelve frozen cases take zero trades.** This provides no profitability or drawdown evidence. `call_decisions.csv` records each component of each call's decision.

The independent audit preserves 291,540 original context-array values, rebuilds 4,080 new minute-feature values from 7,202 observed second bars, verifies 48,174 scalar feature values and 204 scalar exit cases, and checks all twelve paper accounts. Future-value perturbations preserve 335,034 earlier feature values. The correction audit also verifies all original signal rows, supplementary response decoding, the unchanged historical cutoff and the identical trading-protocol hash. Eleven second-bar and five transaction-history responses are reused by exact request identity.

The initial acquisition pipeline is retained for reproducibility:

```sh
rtk python analysis/ayugram-token-strategy/arrival_forward.py collect --wait
rtk python analysis/ayugram-token-strategy/arrival_forward.py prepare
rtk python analysis/ayugram-token-strategy/arrival_forward.py execution
rtk python analysis/ayugram-token-strategy/arrival_forward.py evaluate
```

Run the complete corrected pipeline, including cache reuse, the unchanged-rule replay, its independent audit and per-call diagnostics:

```sh
rtk python analysis/ayugram-token-strategy/run_arrival_correction.py
```

The corrected runner validates complete execution-cache files before calling collectors, so a fully cached rerun also preserves collection metadata. A full rerun, including independent audits, completed in 10.8 seconds and left all 296 existing protocol artifacts unchanged. Completed sizing and pair-study cache reads took 0.21 and 0.13 seconds and preserved all twelve checked study artifacts.

### Fixed earlier entries with five-minute profit targets

`repeat_fixed_entry_runs/1ef5d7d5b13e70dc` transfers the exact three earlier saved daily entry rules and sizing policies to the expanded dataset. It compares **16 fixed exits** without another entry search: timeouts of 15/30/60/120/180/300 seconds, six shortened saved trailing exits, and 1.2×/1.5×/2×/3× targets with a 300-second timeout. Three reference-history populations distinguish the original first calls, expanded first calls and recoverable first calls. The reference outcome remains the earlier minute-bar three-minute paper trade, with its original 5% haircut. The original history reproduces every earlier mask, factor and gate, plus all three cost-case ten-minute control ledgers.

There are **576 fixed comparisons and 576 concentration replays**, plus three control replays. Every requested short-hold horizon is covered. The 3× target, with no stop and a five-minute timeout, gives the following retrospective results using recoverable reference history:

| Population | Return, 5% cost | DD bound, 5% | Return, 10% | Without two best tokens, 10% | Without best day, 10% | Trades |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Original calls with recoverable text | +2.98% | 1.21% | +2.33% | +0.50% | +0.87% | 9 |
| Added calls | +2.44% | 1.97% | +1.93% | −0.16% | −0.13% | 6 |
| Combined recoverable calls | +3.18% | 2.32% | +2.30% | +0.47% | +0.85% | 12 |

The highest-return combined exit is the three-minute timeout at +3.21%, but it loses after removing two best tokens. The five-minute 3× target survives those baseline removal checks. It is chosen retrospectively from this catalog; these dates were already examined. Recoverable text is a historical data restriction, **not a deployable filter based on future edits**. The original all-text control remains in the full tables.

`fixed_entry_execution_runs/448c5af9aa62a451` adds **600 execution portfolios and 400 concentration replays**. It compares 0/2/5/10-second added entry delays, 1/3/5-second exit reactions, 0.5%/1% participation in prior volume, and a $10k account case. Both 2× and 3× targets stay profitable in all 25 scenarios at a 10% sale haircut under both original and recoverable cohort histories. For the 3× target with recoverable history, minimum returns before removals are +1.52% for original calls and +0.96% for combined calls; maximum drawdown bounds are 1.34% and 3.14%. After removing two best tokens, only 20/25 original-call scenarios and 11/25 combined-call scenarios remain positive. Worst concentration-removal returns are −0.17% and −0.72%.

Entry rules are unchanged from the earlier saved choices: October 18 uses confirmed cap ≥$25k and last-five win fraction ≥40%; October 19 uses quoted cap ≥$50k with the same gate; October 20 uses quoted cap $50k–$250k and last-five mean return ≥−10%. All require a 10–25% decline during the first complete minute and wait another minute before entry. The first two days allocate 2%, weighted by ten prior outcomes; the last allocates 5%, weighted by observed volatility, with a 4% daily full-loss budget. Prior-volume limits, fees, one position and one purchase per token apply. Targets trigger a later observed-price sale; they do not guarantee an execution at the target price.

The independent feature audit checks 1,506 scalar minute references, 4,518 first-reference membership values, 13,554 history selections and 54,216 feature values. Future mutations preserve 293,328 earlier values. Separate debit/settlement calculations verify all 2,155 portfolios across the two studies, 18,988 trade calculations and 554 scalar exit checks. All 24 execution baselines reproduce the corresponding earlier ledgers. The transfer and execution runs take 16.87 and 14.17 seconds, respectively. PNG/SVG figures and numeric figure values are saved with the execution run.

These are candidates for fresh paper observation. Quote-time capacity/fee proxies may be stale at entry, executable AMM fills are unmeasured, and some concentration stresses still lose. The existing forward candidates are unchanged.

Run sequentially from the repository root:

```sh
rtk python analysis/ayugram-token-strategy/repeat_fixed_entry_lab.py
rtk python analysis/ayugram-token-strategy/audit_fixed_entry_transfer.py
rtk python analysis/ayugram-token-strategy/fixed_entry_execution_lab.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_fixed_entry_execution.py
```

### Bounded capture of new messages and edits

`capture_message_versions.mjs` reads updates for this group through the existing AyuGram account in memory. It runs for a specified 30–1,800 seconds, stores local receipt times and separate new/edit/delete events, and then disconnects. Initial/final history snapshots are labeled separately. Credentials are never saved. Only target-group content is persisted, under a private directory with one ordered append writer and a chained event hash. This collector sends no messages and makes no trading decisions.

An eligible observed original must arrive as a new-message update after readiness while connected, have no edit timestamp, and be posted after readiness. Its usable availability time is the local receipt time. This does not guarantee that no unobserved edit occurred. The audit verifies the chain, message-version hashes, eligibility and final-snapshot reconciliation, then writes normalized `versions.json`. Snapshots cannot establish completeness for deleted messages or undelivered edits.

```sh
rtk node analysis/ayugram-token-strategy/capture_message_versions.mjs 600
rtk python analysis/ayugram-token-strategy/audit_message_capture.py
```

The collector intentionally creates a new bounded observation each time. The audit operates on the latest completed capture and preserves its saved outputs on rerun.

The first completed capture is `live_message_captures/20261021T124624497Z_30ed3dab`, from **12:46:27.503 to 12:56:27.508 UTC**. It stores 31 new-message updates, nine edit events and 100-message initial/final snapshots. Thirty new versions meet the original-version rule; **six of those originals were later edited** during the window. The audit verifies all 245 event frames and 240 message-version records. The final snapshot contains thirty messages posted during the observation window, with no missing recorded new-message update and no 100-message truncation. Observed receipt minus second-resolution posting timestamps ranges from 0.398 to 1.342 seconds. No strategy was applied during this collection.

The local SDK handles Telegram's [sequence-state and gap-recovery update protocol](https://core.telegram.org/api/updates). The saved log is evidence of what this collector observed; it does not prove that every edit or deleted message was delivered.

### Expanded short-window dip and cohort search

`repeat_dip_runs/94cde95c139fade5` compares 15/30/60-second completed windows after quote availability with the first full clock minute. All price features are rebuilt from observed positive-volume second candles. Entries wait 1/15/60 seconds, then use the next observed second within ten seconds. The 32 exit rules hold 15–300 seconds, with stops, 1.2×/1.5×/2×/3× targets and trailing exits. Every added call has enough requested observation coverage for the complete planned horizons; missing entry/sale observations remain separate execution restrictions.

The search treats 791 original calls with recoverable text, all 406 added calls, and their 1,197-call combination as separate groups. It compares fifteen cap bands, actual sender type, ten price/activity/range conditions and nine cohort gates. The gates use five or ten completed outcomes from distinct other contracts. Reference positions enter five seconds after the first recoverable quote and hold 60 or 180 seconds, with 5% costs and estimated fees; returns are clipped to [-1,1]. Missing first-reference outcomes are never replaced by later successes. Both the actual exit and the complete planned horizon must precede the current feature time. The current contract is excluded.

**12,150 entries × four windows × three waits × 32 exits = 4,665,600 catalog combinations.** Earlier-training mask deduplication and 48 membership caches support 3,122,240 saved screening rows across four fits. The shortlist receives **13,824 full training portfolios in 63.28 seconds**. Screens compare first eligible calls and equally weighted calls within equally weighted contracts. They use a clipped-return heuristic, not a confidence interval. The 36 sizing policies compare flat, observed volatility, activity and prior-cohort weights, 1%/2.5%/5% allocations, and no/2%/4% daily full-loss budgets. Completed reruns preserve all eight checked feature/result artifacts.

| Daily selector | Return, 5% cost | Drawdown bound | Return, 10% cost | Trades |
| --- | ---: | ---: | ---: | ---: |
| Original calls, 2% training ceiling | -2.76% | 4.40% | -3.92% | 24 |
| Original calls, 5% ceiling | -7.20% | 17.22% | -11.39% | 26 |
| Original calls, strict checks | -13.47% | 18.43% | -17.00% | 27 |
| Added calls, 2% ceiling | -2.44% | 3.59% | -2.82% | 11 |
| Added calls, 5% ceiling | -14.27% | 17.13% | -16.46% | 12 |
| Added calls, strict checks | -20.27% | 23.42% | -22.70% | 15 |
| Combined calls, 2% ceiling | -7.43% | 9.90% | -9.00% | 15 |
| Combined calls, 5% ceiling | -15.98% | 19.73% | -18.64% | 15 |
| Combined calls, strict checks | -16.03% | 20.11% | -20.14% | 17 |

All nine selections lose at 5%, 10% and 15% costs plus estimated fees. Strict selectors require fourteen trades, ten contracts, three training dates and positive returns after removing two best contracts and the best entry day. They pass these checks in later fits and still lose on subsequent replay days. The 2%/5% labels constrain training drawdown, not later losses. This study changes the cohort references and timing grid; the earlier saved minute/cohort procedures remain separately reported. These dates were already examined, original-text availability restricts coverage, and pre-quote fee/volume estimates may be stale at later entry times.

Feature cache: `repeat_call_datasets/b231edbc401e6dd92215/dip_context/d56a67b7456db9e3`. It uses 540 first recoverable contracts for cohort history. Among 1,165 recoverable calls with both clock-minute versions, none differs by more than five percentage points in close return from the saved minute data. The independent audit checks all 6,024 raw price windows, 30,120 price values, 3,012 scalar reference returns, 12,048 history selections and 48,192 cohort values. Future mutations preserve 121,056 earlier feature values and 18,624 history selections. It verifies every catalog mask, 24,096 sizing factors, 448 independent screens including all 192 shortlisted candidates, exact reconstruction of all four shortlists from every saved score, 532 sampled training portfolios, 24 ordinary selection maxima, fifty token and fifty day exclusions, sixteen independently replayed chosen strict exclusions, 1,823 scalar strategy sales, 9,274 trade cash/drawdown calculations and all ninety saved portfolios.

Run these steps sequentially from the repository root; all use the saved cache:

```sh
rtk python analysis/ayugram-token-strategy/repeat_dip_features.py
rtk python analysis/ayugram-token-strategy/repeat_dip_lab.py
rtk python analysis/ayugram-token-strategy/audit_repeat_dip.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_repeat_dip.py
```

### Checked requesters for repeated bot calls

`repeat_requester_runs/776d83dde0c22e9f` compares actual-sender history with the human who explicitly requested a bot scan. A read-only Telegram collection retrieved all 740 required reply headers. These corroborate 602 archived associations to human parents containing the same full token address, with parent text available by the response time. The headers confirm the sender, posting time, parent ID and same-chat scope. Of these associations, 304 have recoverable original response text, including 115 of the 232 added bot calls. All accepted parents are user accounts and none is forwarded. This is requester attribution, not wallet ownership.

Four quote-history fields change: same-person prior count, previous index, time gap and quote return. Unassigned bot replies retain bot identity. The actual bot/human filters, prices, times and execution inputs are unchanged. The added repeated-call group changes from 277 to 265 calls. Twenty-five gain eligibility and 37 lose it; 331 recoverable calls have a different prior count. Equal-time quotes do not inform one another. Feature cache: `repeat_call_datasets/b231edbc401e6dd92215/requester_context/d7ce4967c5b182ba`.

The paired experiment keeps exactly the sender-based candidate pool shortlisted before each cutoff. It replays every entry/exit/delay/sizing/re-entry combination in that pool under both identities and applies identical training selection rules. **85,176 training portfolios complete in 51.58 seconds**. Every one of the original 42,588 training portfolios and 27 daily portfolios reproduces. Requester-specific candidates outside that original shortlist are not searched.

| Added-call selector | Sender return / DD, 5% cost | Requester return / DD, 5% cost | Requester return, 10% cost | Requester trades |
| --- | ---: | ---: | ---: | ---: |
| 2% training ceiling | -6.51% / 6.58% | -3.42% / 4.08% | -4.09% | 13 |
| 5% training ceiling | -4.02% / 6.76% | -9.36% / 10.91% | -11.63% | 13 |
| Strict training checks | -3.63% / 6.51% | cash | cash | 0 |

All seven requester selections that trade lose at 5%, 10% and 15% sale costs plus estimated fees. Original-call and combined-call daily ledgers are unchanged. Removing requester attribution after fitting its choices leaves all eighteen 5%/10% daily ledgers unchanged. The changed results therefore come from training selection. With the original sender choices fixed, changing attribution gives -5.49% for the larger added-call procedure and -6.10% for its strict procedure at 5% cost. No profitable trading selection emerges.

The audit independently checks 1,506 attribution decisions, 6,024 requester-history values, 201,804 entry-mask values, 1,308 scalar sales and 10,815 trade cash/drawdown calculations. It covers 606 sampled training portfolios, 48 ordinary selection maxima, all 3,029 stored token exclusions and 58 day exclusions, twenty independently replayed chosen strict exclusions, and all 145 saved daily/ablation/concentration/stress portfolios. Mutating future quotes and identities preserves 9,312 earlier history values. Completed collector, feature, research and plotting commands reuse their caches; a rerun preserved all twelve checked data/result/figure artifacts.

These dates were already examined. Unavailable original message versions restrict coverage. Current Telegram metadata corroborates the archived reply links; it is not a separately collected historical event stream. Telegram's [reply-header documentation](https://core.telegram.org/constructor/messageReplyHeader) describes the parent-message and peer fields. Saved headers are under `reply_metadata/cc7af4ac7409dc86` inside the repeated-call dataset. No credentials are saved with them.

Run the following commands sequentially from the repository root. The first command reads Telegram only when the header cache is absent; the others use saved files:

```sh
rtk node analysis/ayugram-token-strategy/fetch_reply_metadata.mjs
rtk python analysis/ayugram-token-strategy/repeat_requester_features.py
rtk python analysis/ayugram-token-strategy/repeat_requester_lab.py
rtk python analysis/ayugram-token-strategy/audit_repeat_requester.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_repeat_requester.py
```

The seventh fixed-candidate window, `fixed_validation_windows/20261021_121831`, froze at 12:18:31 UTC before retrieval and covers 11:44:24–11:58:31 UTC. It adds twenty messages, six inside the reserved interval, and **two eligible calls on one contract**. Both have a quoted cap of about $490,440, above the unchanged $250k maximum, and both fail the entry/cohort filters. There are zero trades across all candidate/cost/latency scenarios. The price cache contains only twelve observed seconds across the two call windows, and the prior transaction window is empty, so execution data would also be insufficient. All 1,128 earlier calls and nineteen numeric fields were preserved.

Seven reserved windows now contain two eligible calls and no trades. The gap-inclusive audit, `fixed_observation_audits/08fa18aff14279d4`, covers 81 messages after the original candidate freeze, six eligible calls across three contracts, and zero matching entries. Four calls are below the $50k minimum and the latest two are above the $250k maximum. Thirty earlier-history references pass the causal checks. These observations provide no trading-return evidence.

### Repeated calls and bounded re-entry

The original compiler keeps one call per sender and contract. Its raw archive contains 618 later calls, 576 with usable historical quotes. Excluding 170 later-edited messages whose original text is unavailable leaves **406 added calls**, comprising 174 human and 232 bot calls. `repeat_call_datasets/b231edbc401e6dd92215` preserves every original eligible call and adds these rows. It retains 1,506 calls across 547 contracts and 45 authors. The 207 missing second-price windows and 297 missing trade windows are cached; existing responses are reused. The expanded transaction cache contains 849,083 rows in 892 windows and 921 pages.

The new search uses 1,197 calls with recoverable original messages. The added-call group requires an earlier usable quote from the same sender, leaving 277 calls. Quote-history features use strictly earlier availability times; equal-time quotes do not inform one another. Filters cover cap bands below $3k/$6k/$10k through above $1m, sender type, gaps between calls, price changes from earlier quotes and the number of earlier calls. Missing original message versions can bias the sample. This data restriction cannot be deployed as a filter based on future edits.

`reentry_runs/e7fc4d7d82945bef` compares **4,725 entry rules × 32 exits × 3 delays = 453,600 combinations**. Holds are 15–300 seconds, with stops, 1.2×/1.5×/2×/3× targets and trailing exits. Seven purchase rules compare one, two or three purchases per token, a two-minute cooldown, and another purchase only after a completed win or loss. One global position remains. The 126 sizing/re-entry policies include 1%/2.5%/5% allocations, flat/volatility sizing and 2%/4%/no daily budget. Prior-volume limits, estimated fees and missing-exit writeoffs apply.

Two reference screens use either the first executable quote per contract or equally weighted calls within each contract. They are heuristic shortlists, not exhaustive portfolio optimization. Canonical entry masks use earlier completed training membership only. Twelve membership caches support 238,336 screens; the shortlisted candidates receive **42,588 training portfolios in 33.51 seconds**. Completed runs are reused after checking settings and table hashes, preserving their original artifacts.

| Daily selection | Return, 5% cost | Drawdown bound | Return, 10% cost | Trades |
| --- | ---: | ---: | ---: | ---: |
| Original calls, 2% training ceiling | -1.17% | 1.52% | -1.50% | 9 |
| Added repeated calls, 2% ceiling | -6.51% | 6.58% | -7.26% | 16 |
| Added repeated calls, 5% ceiling | -4.02% | 6.76% | -6.56% | 13 |
| Added repeated calls, strict checks | -3.63% | 6.51% | -6.49% | 17 |
| Combined calls, 2% ceiling | -1.75% | 3.95% | -3.95% | 22 |
| Combined calls, 5% ceiling | -1.73% | 7.21% | -6.14% | 20 |
| Combined calls, strict checks | -4.08% | 4.61% | -5.18% | 12 |

All eight trading selections lose at both costs. The strict original-call selector stays in cash. The strict repeated-call and combined-call procedures require positive training returns after excluding two best contracts by aggregate PnL and after excluding the best entry day, plus sufficient trades, contracts and dates. They pass those checks during later fits and still lose in evaluation. The comparison uses this study's quote-entry catalog; the earlier minute-dip strategies remain separate.

Repeat purchases occur in 9,794 training policy rows at 10% cost, but none of the selected daily portfolios makes a repeat purchase. Most choices allow one purchase; the chosen conditional repeat rule has no qualifying second entry. Forcing one purchase leaves all nine 10%-cost daily ledgers unchanged. The result does not establish that repeat purchases are always unprofitable.

The dataset audit preserves all 1,100 original calls, nineteen numeric fields, 267,300 transaction-feature values and nine original portfolios. It verifies 1,615 reused responses and 19,488 new minute slots. The strategy audit checks all 19,578 quote-history values, 30,264 future-perturbed feature values, 1,186 scalar sales and 11,772 independent trade calculations. It covers 684 sampled training portfolios, 425 screens including the entire shortlist, 24 ordinary selection maxima, all 1,467 saved training token exclusions, 38 training day exclusions, twelve independently replayed chosen robust exclusions and all 77 saved daily/stress/concentration portfolios. An independent account debits purchases immediately and credits proceeds only at exit. Cooldown, contract-count and previous-result branches are exercised; future outcomes preserve earlier entries in 21 cases.

From the repository root, prepare and collect only missing windows:

```sh
rtk python analysis/ayugram-token-strategy/repeat_call_dataset.py prepare
rtk node analysis/ayugram-token-strategy/fetch_second_bars.mjs analysis/ayugram-token-strategy/repeat_call_datasets/b231edbc401e6dd92215/second_bars/requests.json
rtk node analysis/ayugram-token-strategy/fetch_trade_flow.mjs analysis/ayugram-token-strategy/repeat_call_datasets/b231edbc401e6dd92215/trade_flow/requests.json
```

The following steps use saved files. Run each command after the previous command finishes:

```sh
rtk python analysis/ayugram-token-strategy/repeat_call_dataset.py compile
rtk python analysis/ayugram-token-strategy/repeat_call_dataset.py features
rtk python analysis/ayugram-token-strategy/audit_repeat_dataset.py
rtk python analysis/ayugram-token-strategy/repeat_call_features.py
rtk python analysis/ayugram-token-strategy/reentry_lab.py
rtk python analysis/ayugram-token-strategy/audit_reentry.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_reentry.py
```

The sixth unchanged-candidate window, `fixed_validation_windows/20261021_114419`, froze at 11:44:19 UTC and covers 11:18:15–11:24:19 UTC. It added sixteen messages, one within the reserved window. Its two new eligible calls are earlier than the window, leaving zero validation calls and trades. All 1,126 older calls and nineteen numeric fields were preserved. The gap-inclusive audit, `fixed_observation_audits/c165da1d03533c96`, covers 61 messages after the original freeze and finds four eligible calls across two contracts, all below the frozen $50k cap minimum. There is still no qualifying fresh trade evidence.

### Entry waits, latency and position overlap

`entry_wait_runs/577564bbc4f5c41a` preserves the earlier daily entry filters, exits and sizes while comparing waits of 1/5/15/30/45/60/90 seconds after the first minute is complete. The original wait is 60 seconds. Added delays of 0/1/2/5/10 seconds produce 33 distinct offsets. The search evaluates 594 earlier-data training portfolios in 10.26 seconds, with cached price paths and exit outcomes. Ordinary selection maximizes 10%-cost return under a training drawdown ceiling. Delay-constrained selection requires every delay scenario to pass and maximizes the worst scenario. Each day uses only completed earlier outcomes.

| Procedure | Original return / drawdown | Retimed return / drawdown | Trades | Without two best tokens | Without best day |
| --- | ---: | ---: | ---: | ---: | ---: |
| Earlier saved choices | +2.62% / 1.55% | +2.70% / 2.79% | 10 | -2.17% | -1.17% |
| Smaller partial sales, 2% training ceiling | +2.08% / 0.77% | +2.56% / 1.12% | 10 | -0.53% | -0.02% |
| Smaller partial sales, delay requirement | +2.08% / 0.77% | +2.55% / 1.12% | 5 | -0.54% | -0.03% |
| Larger partial sales | +2.73% / 1.40% | +3.68% / 2.40% | 10 | -1.24% | -0.22% |

The table uses 5% sale costs plus estimated fees. The selected daily waits are respectively `[90,90,30]`, `[90,90,60]`, `[cash,90,60]`, and `[90,90,60]`. Higher returns come with higher drawdown. All trading wait selections lose after removing their two best tokens or best entry day at both 5% and 10% costs. The stricter selector remains in cash because it requires fourteen training trades but the fits supply at most 11, 13 and 11; zero training exclusion checks run. These reused dates do not establish an independent edge.

The original smaller partial-sale procedure remains positive when its 60-second wait is increased by 1/2/5/10 seconds, with returns of +2.29%, +2.26%, +1.60% and +1.96% at 5% cost. This is sensitivity to cached prices, not measured latency or executable fills. Pre-call fee and volume estimates remain fixed and may be stale at later entry times. The run contains 198 fixed-wait portfolios, 225 selected-delay portfolios, 32 token/day removal portfolios, and PNG/SVG curves with their exact values.

The timing audit checks 36,300 raw entry fills, 2,194 independent scalar sale outcomes and 10,183 trade cash/drawdown calculations. All 594 training portfolios, 455 evaluation portfolios, 45 choices and nine original baselines reproduce. Scaling every post-cutoff candle alternately by 20 or 0.05 leaves all 594 earlier training portfolios unchanged.

`position_overlap_runs/b0f4559d360ae242` separately reproduces 72 portfolios from 24 saved procedures at three costs. None of the twelve earlier leading procedures has an otherwise eligible, untraded contract during an existing holding interval. Two losing short-hold procedures each have one possible extra call at 5% cost, on the same token; there are no additions at 10% or 15%. This upper-bound check intentionally omits cash and budget restrictions. It does not simulate concurrent returns or justify removing the one-position limit.

```sh
rtk python analysis/ayugram-token-strategy/position_overlap_audit.py
rtk python analysis/ayugram-token-strategy/entry_wait_lab.py
rtk python analysis/ayugram-token-strategy/audit_entry_wait.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_entry_wait.py
rtk python analysis/ayugram-token-strategy/context_research_report.py
rtk python analysis/ayugram-token-strategy/audit_research_artifacts.py
```

### Distinct human attention and shorter exits

The new search finds **no improvement**. At the available quote time, 277 eligible calls have two distinct senders mentioning the token within two minutes, but only **13** have two non-bot, non-forwarded human authors. A requester and the responding scanner are not independent human confirmations. These are attention counts; distinct accounts do not prove independent information or endorsement.

`confirmation_features.py` reads exact known contract addresses from all archived message bodies and entity URLs, including messages without usable price quotes. It finds 2,141 mention events, of which 758 are non-forwarded human events. Current text from 615 later-edited events becomes available only at its edit timestamp. Counts use 30/60/120/300/900-second windows and are fixed at quote availability, before the entry delay. Price comparisons use strictly earlier available quotes of the same contract. Feature cache: `coverage_repairs/evm/combined/datasets/adb4dc66b5bd0a0d3e6f/confirmation/61671c35e08dd3e6`.

`confirmation_runs/25741e241616d62a` compares **7,392 entry rules × 32 exits × 3 delays = 709,632 combinations**. Cap boundaries include $3k, $6k, $10k, $25k, $50k, $100k, $250k and $1m. Rules combine author counts, actual sender type, and pullbacks/increases relative to the first or latest earlier quote. Entries wait 5/15/30 seconds; holds are **15–300 seconds**, with 1.2×/1.5×/2×/3× targets, stops and trailing exits. Sizing uses 1%/2.5%/5%, flat/volatility/mention-count weights, and daily budgets of 2%/4%/none. The existing volume limits, fee estimates and missing-exit writeoffs apply.

The ordinary screen deduplicates masks on completed training calls only, then scores one earliest executable call per contract using clipped returns and estimated costs. It requires twelve contracts. All 2,336 human-confirmation screens meeting that minimum have negative clipped reference means at 10% cost. To check whether clipping hid profitable large winners, `--all-human` removes the positive-mean gate and both shortlist limits for that group: **all 63,072 human sizing/budget policies are portfolio-tested at both costs, using uncapped portfolio PnL**. Every one has a negative 10%-cost portfolio return. This statement applies to the fixed catalog and sample minimum, not every possible human-confirmation strategy.

The expanded run uses **66,555 policy rows and 133,110 training portfolios**, completing in 64.72 seconds. Twelve cached sets of training membership support the screens. All 27 non-human daily portfolios exactly reproduce the ordinary-screen control, `confirmation_runs/466748cfa7e5ca29`.

| Daily selection procedure | Return, 5% haircut | Drawdown bound | Trades | Return, 10% haircut |
| --- | ---: | ---: | ---: | ---: |
| Two senders, 2% training ceiling | −5.40% | 5.59% | 17 | −6.31% |
| Two senders, winner/day checks required | −1.60% | 2.07% | 5 | −1.69% |
| One human author, 2% training ceiling | −4.51% | 5.06% | 19 | −5.34% |
| No attention requirement, 2% training ceiling | −3.44% | 4.48% | 19 | −4.67% |

Human-confirmation selectors remain in cash. The stricter sender selector requires positive training returns without its two best tokens and best entry day, plus fourteen trades, ten contracts and three active training days. It stays in cash for two evaluation days, then loses on five later trades. Passing the training concentration checks does not establish future profitability. The named drawdown ceilings are training constraints and can be exceeded later. The fourth fit uses the full training dataset and adds no evaluation day.

The audit independently reconstructs all 2,141 mention events and 22,000 feature values; 77,040 feature values remain unchanged after future-message/quote perturbations. It checks twelve training-mask invariance cases, 1,248 scalar exits, 2,582 screens, 288 uncached training portfolios and 5,793 trade calculations. All 36 daily portfolios, 32 ordinary selection maxima and four selected robust training exclusions pass. The audit also verifies that all 2,336 eligible human configurations received every sizing/budget policy.

```sh
rtk python analysis/ayugram-token-strategy/confirmation_features.py
rtk python analysis/ayugram-token-strategy/confirmation_lab.py
rtk python analysis/ayugram-token-strategy/confirmation_lab.py --all-human
rtk python analysis/ayugram-token-strategy/audit_confirmation.py
```

The fifth unchanged-candidate window, `fixed_validation_windows/20261021_111745`, froze at 11:17:45 UTC and covers 10:55:03–10:57:45 UTC. It added eighteen archived messages, one inside the reserved window, with zero token calls and zero trades. All 1,126 earlier eligible calls and nineteen numeric fields were preserved. The observation audit now reads the latest completed collection directly, before report regeneration; `fixed_observation_audits/0ca60bc883b31687` covers 45 messages since the original candidate freeze, including gaps, and still finds only the two ~$5.5k calls that fail the $50k minimum. Five reserved windows and the gap audit supply no qualifying trading observations.

### Account risk controls and dependence on one day

**All twelve compared procedures become negative when October 19 is excluded**, at both 5% and 10% sale-proceeds haircuts plus estimated fees. The procedures cover partial sales, activity sizing, Decider scores, uniform exposure controls, caller histories and account risk controls. Each has trades on only three evaluation days, and they share many of the same tokens. Different parameter choices have not established independent sources of profit.

`day_dependence_runs/0e2f8a51e1ccdee5` reproduces 36 original portfolios at three cost settings, then replays 72 day exclusions at 5%/10% cost. Exclusions block all entries on a UTC day and recompute later cash, contract eligibility, overlap, budgets and active risk controls. Observed group history and the already fitted daily rules remain available. This is a descriptive concentration check on repeatedly examined dates, not cross-validation or a confidence interval. The run contains PNG/SVG figures, their exact source values and all replayed ledgers.

`account_risk_runs/e8c729aef446701e` compares **64 control configurations**: closed-equity and daily drawdown scaling, daily loss stops, profit-related size reductions, loss streaks, pauses, entry spacing and gradual size recovery. Sizing uses only already completed entered trades and current cash. Daily states reset on the next UTC entry day; the overall closed-equity high carries. Rejected calls do not make their token permanently ineligible.

The search keeps the earlier daily entry/cohort rules, budgets, six exits and four allocation scales. Its **4,608 policies** require 9,216 closed-trade plans but only **3,529 distinct candle replays**, with 5,687 cache hits. The measured run took 12.23 seconds. Cost-specific trade/contract counts are saved because a larger cost can change pause or budget decisions.

| Daily procedure | Return, 5% haircut | Drawdown bound | Return, 10% haircut | Return without Oct 19, 5% haircut |
| --- | ---: | ---: | ---: | ---: |
| Account risk, smaller | +1.73% | 0.88% | +1.34% | −0.39% |
| Same exits/sizes, controls removed | +1.83% | 0.88% | +1.45% | Not separately measured |
| Account risk, larger | +2.62% | 1.55% | +1.94% | −0.74% |
| Earlier smaller partial sales | +2.08% | 0.77% | +1.73% | −0.15% |

The controls add no observed improvement. The larger procedure reproduces the original ten-trade ledger. The stricter selector requires fourteen training trades before checking winner removal, but the three stages have at most 11, 13 and 11. It therefore stays in cash and performs zero winner-removal checks; that is an unmet sample requirement, not a validated robust strategy. Both trading risk variants lose after their two best tokens are excluded.

`audit_account_risk.py` independently reconstructs 228,652 weights from completed entered-trade history and checks 2,304 current/future outcome mutations, 492 uncached training portfolios and 9,854 trade calculations. All 768 planning/accounting cases passed. The shared `saved_procedure_replay.py` adapter reproduces complete source ledgers before performing exclusions. `audit_day_dependence.py` checks all 72 day exclusions, their unchanged earlier trade prefixes and 696 sale-ledger calculations.

```sh
rtk python analysis/ayugram-token-strategy/account_risk_lab.py
rtk python analysis/ayugram-token-strategy/audit_account_risk.py
rtk python analysis/ayugram-token-strategy/day_dependence_lab.py
rtk python analysis/ayugram-token-strategy/audit_day_dependence.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/plot_day_dependence.py
rtk python analysis/ayugram-token-strategy/context_research_report.py
rtk python analysis/ayugram-token-strategy/audit_research_artifacts.py
```

The fourth unchanged-candidate window, `fixed_validation_windows/20261021_105457`, froze at 10:54:57 UTC and covers 10:29:42–10:34:57 UTC. It added twenty archived messages and two eligible calls, all earlier than the reserved window. There are zero validation calls/trades. The prior 1,124 eligible calls and nineteen numeric fields were preserved. All four fixed-candidate windows have zero eligible validation calls and provide no profitability evidence.

`fixed_observation_audits/271fd8380cdaaafa` separately covers every archived message posted after the original candidate freeze at 09:33:36 UTC through 10:34:57 UTC, including gaps between the reserved windows. The 27 messages contain two eligible calls on one token, at caps of $5,507 and $5,525. Both fail the unchanged $50k minimum; there are no matching entries. Ten prior cohort-history references also satisfy the causal timing and target-exclusion checks. This coverage audit was specified after collection and does not retroactively make the gaps preregistered validation windows. Re-run it with `rtk python analysis/ayugram-token-strategy/fixed_observation_audit.py` before rebuilding the report after future collections.

### Caller history, explicit requesters and chain controls

`caller_history_features.py` builds two separate histories: actual message sender and explicit scanner requester. **487 of 508 bot-authored calls** reply to an archived human message containing the same complete contract address, with that parent text known before the response. Three potential matches were excluded because the parent was edited later, and exact address boundaries reject substring matches. Uncertain replies retain the bot sender. This is direct reply attribution, not wallet ownership inference.

The attribution changes history ownership without changing a signal's original sender, timestamp, price or token. Deduplicating requester/contract pairs reduces the 1,100 sender/contract events to **614 history events**, avoiding duplicate credit for a request and its scanner response. Feature cache: `coverage_repairs/evm/combined/datasets/adb4dc66b5bd0a0d3e6f/caller_history/6ee12c70828bcb72`.

Each caller score uses outcomes completed before the current UTC day and excludes the token being scored. Histories keep at most twenty distinct contracts per caller. Peer histories use the earliest group call per contract and exclude the current caller. Missing first-event outcomes are not replaced with later successful entries. Caller means shrink toward peer means with ten observations of prior weight; returns are clipped to −100% through +100% for these scores. The scores are robust ranking features, not uncapped expected-value estimates.

The three references hold for 60 or 180 seconds after a five-second delay from the available quote, or for 180 seconds after the existing confirmation wait. The available quote time is the latest of the message, quote and underlying swap timestamps. Reference position size is the smaller of $20 and 1% of prior economic volume, with the existing fee estimates and 5% sale haircut. Variants compare all earlier history against 24 hours, and all tokens against the same chain/cap band. Cap boundaries are $6k, $10k, $25k, $50k, $100k, $250k and $1m.

`caller_policy_runs/bacc3ef466017840` compares **2,305 modifiers**, four scales and six exits per day. Conditions use shrunken mean, excess over peers, win/loss frequency or a mean with the best earlier outcome removed. They require 3/5/10 caller tokens and twenty peer tokens. Failed conditions reject or halve the position; unknown callers are explicitly allowed or excluded. Caching equivalent stake vectors reduces **165,960 policy rows to 14,148 distinct portfolio evaluations**, with 158,886 cache hits. The measured run took 15.98 seconds.

| Daily procedure | Return, 5% haircut | Drawdown bound | Return, 10% haircut | Return without two best, 5% haircut | Trades |
| --- | ---: | ---: | ---: | ---: | ---: |
| Earlier saved choices | +2.62% | 1.55% | +1.94% | −1.02% | 10 |
| Sender history, smaller | +2.38% | 0.95% | +2.01% | −0.37% | 9 |
| Sender history, larger | +1.42% | 1.34% | +0.92% | −1.21% | 9 |
| Requester history, smaller | +1.43% | 0.64% | +1.14% | −0.34% | 8 |
| Requester history, larger | **+3.09%** | **1.32%** | **+2.50%** | **−0.56%** | 9 |

These are daily selections on repeatedly examined dates, with the modeled $1,000 account, volume caps and fee estimates. The larger requester procedure retains the original full-position exits and sizes. It uses no caller filter on October 18; on October 19 it rejects known requesters whose shrunken 60-second mean is below −10%; on October 20 it rejects those whose shrunken 180-second mean is below their peers. The selected filters require three caller tokens and twenty peer tokens, and allow unknown callers. They are changing daily selections, not a single unchanged rule.

Removing the requester modifiers restores the original +2.62% / 1.55% ledger. The entire difference is one omitted losing BNB Chain trade. `caller_control_runs/2ae0d8b92e00fb6c` confirms that Solana-only and BNB-exclusion controls reproduce the larger requester ledger **exactly at all three cost settings**. This is a post-hoc diagnostic. It does not distinguish persistent caller skill from one changed chain exposure, or establish that this chain or caller is generally unprofitable.

The larger requester procedure returns +2.78% / 1.53% at a five-second reaction delay and 10% haircut, +1.48% / 1.49% at 0.5% prior-volume participation, and +0.83% / 1.23% on a $10,000 account under the same volume cap. These are model sensitivities, not measured executable capacity. All caller variants become negative after their two best tokens are removed.

`caller_snapshot.csv` in the feature cache ranks both sender and requester identities at October 21, 00:00 UTC, using earlier three-minute reference outcomes. It includes counts, clipped/shrunken means, excess over peers and means without the best prior token. `caller_decisions.csv` in the policy run records the scores and weights available before each evaluated call. Neither file measures members' own PnL or establishes a reliable positive/negative-EV blacklist.

The independent audit checks 1,100 attribution decisions, 17,520 history fields, 1,752 future/current-token label mutations, 219 scalar reference returns, 168,265 modifier values, 502 uncached portfolios and 3,276 training-trade accounting calculations. All fifteen main chronological portfolios reproduced. The control study also records nine exact source-ledger agreements.

```sh
rtk python analysis/ayugram-token-strategy/caller_history_features.py
rtk python analysis/ayugram-token-strategy/caller_policy_lab.py
rtk python analysis/ayugram-token-strategy/audit_caller_policy.py
rtk python analysis/ayugram-token-strategy/caller_control_lab.py
rtk python analysis/ayugram-token-strategy/context_research_report.py
rtk python analysis/ayugram-token-strategy/audit_research_artifacts.py
```

The third unchanged-candidate window, `fixed_validation_windows/20261021_102935`, froze at 10:29:35 UTC and covers 10:05:02–10:09:35 UTC. It added seven archived messages, all earlier than that window, and zero eligible validation calls. All 1,124 older calls and nineteen numeric fields were preserved. That collection had 14,366 archived messages; the later fourth collection is described above.

### Decider with historical activity and recipient context

`context_decider.py` prepared 1,066 anonymous numeric requests to `perplexity/pplx-decider-v1.2-20261016` through the native Decisions API. All requests completed, producing 6,396 typed answers. Reported usage was 3,864,186 input tokens, 6,396 output tokens and $0.07728. Median latency was 547 ms and p95 was 655.75 ms; every response fit the one-minute response budget.

Inputs include the first completed minute, historical cap/age, earlier caller and cohort outcomes, pre-call activity and completed other-token outcomes associated with recurring recipients. Token addresses, names, tickers, caller identities, raw messages and absolute dates are excluded. Chain IDs are the only strings in the request state. Recipient features describe outcomes after earlier calls; they do not measure wallets' own trading profits or associate wallets with Telegram members.

`context_calibration.py` uses only completed outcomes before the current UTC day, one earliest usable event per token, and excludes the token being scored. Fixed score bins shrink toward the earlier base rate, with at least 30 earlier tokens required. Diagnostics cover 352 evaluation tokens. Three-minute profit ranking is weak: raw AUC 0.533 and calibrated AUC 0.457. Calibration lowers Brier error from 0.2196 to 0.2146, but the previous-day base-rate estimate is better at 0.2135. Expected-value answers remain scores, not win probabilities.

`context_decider_runs/037514af3811ab7c` compares 405 modifiers, four scales and six exits per day under the same earlier daily entry/cohort filters and budgets. It considered 29,160 training policies and ran 20,244 distinct portfolios after caching equivalent stake vectors on completed training calls. The measured run took 20.42 seconds. All nine earlier activity/control ledgers reproduced exactly.

| Daily selection procedure | Return, 5% sale haircut | Drawdown bound | Return, 10% sale haircut | Drawdown, 10% haircut |
| --- | ---: | ---: | ---: | ---: |
| Earlier smaller partial-sale procedure | +2.08% | 0.77% | +1.73% | 0.77% |
| Raw Decider, smaller | +1.96% | 0.73% | +1.54% | 0.81% |
| Raw Decider, larger | +0.30% | 1.19% | −0.09% | 1.35% |
| Calibrated Decider, smaller | +1.46% | 0.96% | +1.02% | 1.11% |
| Calibrated Decider, larger | +2.62% | 1.33% | +1.99% | 1.49% |

These are retrospective daily selections on repeatedly examined dates, not single unchanged rules or independently validated returns. They use the $1,000 account, prior-volume cap and fee estimates. The larger raw model has nine trades; the others have ten. Removing two winning tokens makes every model procedure negative. The earlier smaller partial-sale procedure beats the smaller raw model on both return and drawdown at 10% sale costs.

Removing the smaller raw model's modifiers while keeping its selected exits and sizes gives **+2.72% / 1.23% drawdown**. This is a post-hoc ablation. The model reduces both exposure and return, and has not established an advantage over matched position sizing. The larger calibrated procedure's model modifiers do not change its entered ledger. Stress scenarios for reaction delays, volume participation and account size are saved in `results.json`.

The independent audit checked 1,066 request states, 3,300 reference labels, 249 scalar calibration cases, 249 future/same-token label mutations, 83 return-calibration cases, 342 uncached portfolios and 3,272 trade-accounting calculations. The existing raw-flow, recipient-history and second-resolution execution audits remain separate.

### Uniform exposure controls

`matched_exposure_runs/b88dd51883328300` keeps each saved model procedure's daily entry/exit, base allocation and budget. It replaces per-call modifiers with one uniform multiplier per day, fitted to total entry capital on earlier completed training trades. The 201-point grid uses absolute exposure difference as its only objective. All twelve matches are within 0.41% of their training exposure target. Fitting does not use evaluation-period quantities or returns.

| Source procedure | Per-call model return / drawdown | Uniform-control return / drawdown | Uniform return at 10% costs | Uniform return without two best tokens |
| --- | ---: | ---: | ---: | ---: |
| Raw model, smaller | +1.96% / 0.73% | +1.95% / 0.83% | +1.56% | −0.68% |
| Raw model, larger | +0.30% / 1.19% | +2.66% / 1.27% | +2.07% | −0.85% |
| Calibrated model, smaller | +1.46% / 0.96% | +2.02% / 0.76% | +1.66% | −0.60% |
| Calibrated model, larger | +2.62% / 1.33% | +2.96% / 1.33% | +2.39% | −0.68% |

The main columns use a 5% sale haircut plus prior fee estimates. Uniform controls have ten trades; the larger raw model has nine. A uniform control still inherits model-selected rules and training exposure, so it is an ablation of per-call scores rather than an independently selected model-free strategy. Matching earlier turnover does not guarantee equal later exposure or drawdown.

The smaller raw model retains a small historical drawdown benefit over its uniform control. Uniform sizing improves both return and drawdown over the smaller calibrated model. Every control still loses without its two best tokens. The +2.96% result comes from the same repeatedly examined dates.

The run evaluated 2,424 training portfolios in 9.77 seconds, including its twelve model targets. It reproduced twelve saved training portfolios and twenty evaluation/ablation ledgers, independently checked 277 training-trade calculations, and changed future factors in 24 cases without changing completed training ledgers.

```sh
rtk python analysis/ayugram-token-strategy/matched_exposure_lab.py
rtk python analysis/ayugram-token-strategy/context_research_report.py
rtk python analysis/ayugram-token-strategy/audit_research_artifacts.py
```

### Caller ranking and replacements

`caller_dependency_runs/fc295c899ae96460` contains 71 caller rows across eight saved procedures. It reproduced all 24 baseline portfolios at three cost levels, then removed callers and replayed cash, overlap, budgets and later trades. Each caller contributes only one or two entered trades under these procedures.

For the earlier smaller partial-sale procedure, removing the best observed caller reduces return from +2.08% to +0.43%. For the smaller raw Decider procedure it changes +1.96% to −0.25%. These are descriptive exclusions selected after seeing the outcome, not evidence for a profitable caller blacklist. In six exclusions per procedure, another sender's call replaces the removed sender on the same token. Equal returns after excluding another caller can therefore conceal continued exposure to the same winner.

`caller_ranking.csv` saves caller labels, observed contribution, returns after exclusion and same-token replacement counts. Caller figures describe the simulated results following their messages, not personal returns or wallet ownership.

The following commands use saved requests, responses and prices and make no API calls:

```sh
rtk python analysis/ayugram-token-strategy/context_decider.py status
rtk python analysis/ayugram-token-strategy/context_calibration.py
rtk python analysis/ayugram-token-strategy/context_decider_lab.py
rtk python analysis/ayugram-token-strategy/audit_context_decider.py
rtk python analysis/ayugram-token-strategy/caller_dependency_lab.py
rtk python analysis/ayugram-token-strategy/context_research_report.py
```

`context_research_report.py` refreshes the main report and progress record and saves a hash manifest for the source, results, calibration arrays, reports and validation protocols. Mutable source and document files are also copied into the milestone bundle. `audit_research_artifacts.py` verifies the saved hashes, frozen protocol dependencies and local report targets; archived document links are resolved from their original location. `fetch_decider.mjs --folder <request-cache-directory>` is the separate API collection step; it resumes from cached responses and deduplicates equal requests before concurrent fetching.

### Second collection window for the unchanged fixed candidates

`fixed_validation_windows/20261021_100454/forward_protocol.json` was frozen at 10:04:54 UTC, before retrieval, with every trading field unchanged. The reserved interval is 09:33:54–09:44:54 UTC. Collection added 19 messages, all earlier than the reserved interval, and **zero eligible validation calls**. At that point both completed fixed-candidate windows were empty. This provides no new profitability evidence. All 1,124 previous calls and nineteen numeric fields were preserved; that combined archive has 14,359 messages.

For a later complete interval, `extend_partial_validation.py prepare` creates a new immutable protocol, using the latest combined archive as prior context. `extend_partial_validation.py collect` retrieves only after the freeze. Then use `validate_partial_fixed.py prepare`, `collect`, and `evaluate`, passing the new `--protocol` path to each. The first `collect` fetches Telegram messages and minute prices; the second fetches second bars and pre-call transactions only for eligible validation calls. Existing protocols and training data remain unchanged.

### Partial sales and remaining-position accounting

`partial_exit_engine.py` adds serialized partial sales with fractions of the original quantity, realized proceeds, remaining inventory and an extra gas/MEV estimate per partial attempt. Each decision uses a completed one-second candle; the sale then waits for the reaction delay and next observed open. Crossing several profit levels in one candle combines their fractions into one order. New decisions wait until the preceding order fills or times out. The entire maximum possible fee amount is reserved before entry, so position size cannot depend on knowing which future targets hit.

The base entry/final-exit fee remains the existing round-trip estimate. Each partial attempt adds one prior-median transaction gas/MEV fee. A fraction with no observed fill within ten seconds is written off. For the drawdown bound, a partial timeout also marks the still-open remainder at zero at that instant. Entry-price and gross-principal recovery floors exclude fees. These are modeling assumptions, not executable AMM quotes.

`partial_exit_runs/ce568e6e9f861a42` screened **282,100 combinations** across 403 rules, including full-exit controls, and evaluated 2,832 portfolios. Its primary selector chose no partial sales and returned **−2.63% / 2.81% drawdown**. The broad entry search remains unsuccessful.

`partial_saved_entry_runs/a10dbacbac7180bb` retains the earlier saved daily entry filters and refits exit/sizing choices using each day's earlier completed outcomes. It evaluated **21,816 portfolios**:

| Daily selection procedure | Return at 5% haircut | Drawdown bound | Return at 10% haircut | Return excluding two best tokens |
| --- | ---: | ---: | ---: | ---: |
| Earlier saved choices | +2.62% | 1.55% | +1.94% | −1.02% |
| 5% training-drawdown selector | **+2.73%** | **1.40%** | +2.04% | −0.91% |
| 2% training-drawdown selector | **+2.08%** | **0.77%** | +1.73% | −0.29% |

These use the modeled $1,000 account, preceding-volume cap and transaction-fee estimates. Each replay has ten trades and two actual partial sales. The stronger sample-size requirement still produces no candidate. All evaluation dates have already been examined; the new selections have no independently collected validation.

For the 2% selector, October 18 and 19 use half the earlier allocation, a 25% sale at a 3× trigger, a 50% initial stop, and a trail that activates at 1.5× with a 30% gap. October 20 uses quarter allocation and the earlier saved full-position exit. Maximum hold is ten minutes. The 5% selector retains the earlier first two daily choices, then sells 25% at a 1.2× trigger on the last day with a 50% stop and the same 1.5×/30% trail. These are changing daily selections, not one unchanged rule.

The ablation reruns the same calls without refitting. Removing only partial sales changes the 5% selector to **+2.62% / 1.55%** and the 2% selector to **+1.99% / 0.86%**. Restoring the original exits while retaining the 2% selector's daily sizes gives **+1.84% / 0.71%**. Partial sales contribute a small benefit; position sizes and the other exit changes also matter. At a five-second exit reaction and 10% proceeds haircut, the two new selections return **+1.63% / 2.88%** and **+1.92% / 0.71%**, respectively. `ablation.json` and `results.json` retain the ledgers and sensitivity cases.

The independent audit checked **12,750 event sequences**, **11,532 portfolio trades**, and **24,200 first decisions after changing later prices**. Disabling partials reproduced 44,000 earlier single-exit outcomes and 16 complete portfolios. The audit checks serialized fills, quantity conservation, fee reserves, cash, inventory and drawdown. Its source and hash are saved with both runs.

The saved-entry search now shares one price path and 404 distinct outcome banks across all three training stages, instead of rebuilding three paths and 1,212 outcomes. The measured run took 21.53 seconds versus 25.15 seconds before this change. Selected rules, ledgers, stress cases and training leaders were identical. The ablation prepares nine exit banks for its twenty comparison scenarios.

```sh
rtk python analysis/ayugram-token-strategy/audit_partial_exits.py
rtk python analysis/ayugram-token-strategy/partial_exit_lab.py
rtk python analysis/ayugram-token-strategy/partial_saved_entry_lab.py
rtk python analysis/ayugram-token-strategy/partial_exit_ablation.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

### Dynamic exits and allocation size

`dynamic_exit_runs/c040b04a89bd9d6b` evaluated **287,700 combinations and 4,224 portfolios** using 411 exits. The new triggers tighten stops over time, leave stalled trades, trail by prior candle volatility, detect fading volume or detect short-term price reversals. Holds range from five seconds to ten minutes. All decisions use completed one-second candles and fills wait for the next observed open after the reaction delay. The primary daily selector returned **−3.77% with a 4.56% drawdown bound**. The 2% training-drawdown selector returned **−0.71% / 2.68%**. Training risk constraints do not guarantee later drawdown limits.

An independent scalar implementation checked **38,473 decisions and fills** across 43 actual calls and all 411 rules. It also checked 24,200 cases against the existing fixed-exit simulator and changed future prices in 83,600 cases without affecting earlier decisions. `exit_audit.json` records the scope and code hashes.

`saved_entry_exit_runs/388ac3490c265d30` keeps the earlier saved daily entry filters and refits only exits, allocation multipliers and daily loss budgets using prior completed outcomes. It evaluated **22,248 portfolios**. The 5% training-drawdown selector returned **+1.97% / 1.36%**. The 2% selector returned **+0.78% / 0.46%**, using quarter-size positions. The stricter 14-trade/10-token minimum left it in cash; no candidate reached its concentration check. The original saved-choice ledger reproduced exactly.

Simply retaining the original exits and reducing size gave better results than those dynamic full-position exits at comparable risk. For the same modeled $1,000 account, 1% volume cap and fee assumptions:

| Multiplier on original allocation | Return at 5% haircut | Drawdown bound | Return at 10% haircut | Return excluding two best tokens |
| --- | ---: | ---: | ---: | ---: |
| 0.25× | +0.89% | 0.46% | +0.70% | −0.29% |
| 0.50× | +1.83% | 0.88% | +1.45% | −0.53% |
| 0.75× | +2.51% | 1.26% | +1.95% | −0.78% |
| 1.00× | +2.62% | 1.55% | +1.94% | −1.02% |
| 1.50× | +2.84% | 2.14% | +1.90% | −1.50% |
| 2.00× | +3.15% | 2.64% | +1.97% | −1.89% |

The 7.5% allocation ceiling and earlier daily budgets still apply, so doubling the multiplier does not necessarily double a trade. This is retrospective sensitivity on the same ten trades. It identifies a useful risk tradeoff but does not establish an edge. Every size loses without the two best tokens. `size_frontier.json` saves the full ledgers and comparison, treating differences below 0.0001 percentage point as immaterial for dominance.

```sh
rtk python analysis/ayugram-token-strategy/dynamic_exit_lab.py
rtk python analysis/ayugram-token-strategy/audit_dynamic_exits.py
rtk python analysis/ayugram-token-strategy/saved_entry_exit_lab.py
rtk python analysis/ayugram-token-strategy/risk_size_frontier.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

The third separately collected window is `validation_windows/20261021_0851`. Its rule froze at 08:50:47 UTC before retrieval. It added 14 messages through 08:30 UTC, four eligible calls after the previous 08:17:48 observation deadline, and **zero trades**. All four calls concerned TILLY at caps below $13,000, outside the frozen $50,000–$250,000 entry range. All 1,116 earlier calls and 19 numeric fields were preserved. The combined archive now contains **14,326 messages and 1,122 eligible calls**. The three reserved windows total 15 eligible calls and zero trades, so they still provide no profitability evidence.

`extend_frozen_validation.py` now accepts `--output` and `--source-dataset` for a new immutable window. Its `prepare` phase must finish before collection; `validate_cohort.py --protocol <saved_protocol_path>` performs the replay and preservation audit. Existing protocols remain unchanged.

### Pre-call transaction flow and execution size

The cached transaction dataset contains **487,906 rows from 595 complete windows and 607 cursor pages** across the 1,100 corrected calls. Each window starts up to 195 seconds before its call and ends before the message. `trade_flow_features.py` builds 27 historical features over 15/60/180-second windows and 1/5/15-second indexing lags. It measures buy/sell balance, transaction volume after netting routed swaps, address concentration, two-sided activity, momentum, activity bursts, fees and withdrawals. It does not use present-day wallet labels or infer Telegram members' wallet ownership.

The **236,800-combination** search in `trade_flow_runs/b3bb841f1fb8e9f7` screened in **0.43 seconds after loading**, evaluated 6,144 portfolios, and took 38.64 seconds overall. Its primary daily selector required positive training returns at 5% and 10% costs, a 5% training drawdown limit, and positive returns after removing the two best training tokens. The subsequent retrospective daily replay still returned **−8.41% with an 8.48% drawdown bound**, over 15 trades. Nearly all of that loss came from prices. This does not replace the earlier saved choices.

The earlier saved choices, replayed without refitting, returned **+2.62% with a 1.55% drawdown bound over ten trades** for a $1,000 account under new size and fee assumptions. A position is capped at 1% of the preceding 60-second economic volume. The fee estimate is twice the prior median gas plus MEV per transaction, plus the existing 5% sale-proceeds haircut. Five prior swaps are required. The same replay gives **+3.23% / 1.98%** at $100 and **+0.96% / 1.12%** at $10,000. At $1,000, removing the best token leaves **+0.41%**; removing the best two gives **−1.02%**. The 10% haircut result is **+1.94% / 1.71%**. These are account-size sensitivity assumptions, not measured executable capacity.

`saved_choice_sensitivity.json` contains 18 account-size, participation and cost scenarios. Its runner builds three price paths once and reuses them. `flow_audit.json` records 13,938 independent numeric comparisons, 1,197 future-data perturbation windows, 2,269 base/quote mirror checks and 425 audited portfolio trades. The requested token appears on the quote leg in 41,177 raw rows; direction and quantities are normalized before aggregation. `trade_flow/quote_leg_audit.json` confirms one such conversion against an independently fetched BSC transaction receipt. That single receipt does not verify every vendor trade.

```sh
rtk python analysis/ayugram-token-strategy/prepare_trade_flow.py
rtk env NODE_OPTIONS=--dns-result-order=ipv4first node analysis/ayugram-token-strategy/fetch_trade_flow.mjs
rtk python analysis/ayugram-token-strategy/trade_flow_lab.py
rtk python analysis/ayugram-token-strategy/trade_flow_audit.py
rtk python analysis/ayugram-token-strategy/flow_execution_stress.py
rtk python analysis/ayugram-token-strategy/quote_leg_audit.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

The preparer prints the request manifest. The collector accepts that manifest as its first argument or reads the latest pointer, resumes completed pages, and removes redundant checkpoints after completion. Raw responses, request identities, feature arrays and code hashes remain saved. Offline research and audit commands need no keys. The collector loads the configured Mobula key into memory. Data documentation is saved in `data_sources/`; the source endpoint is [Mobula batch trades](https://docs.mobula.io/rest-api-reference/endpoint/trades-filters).

### Recurring address history

`wallet_context_runs/e6cd205cf91a23a5` tests another **156,160 combinations and 6,144 portfolios**. It uses 37,086 observed recipient addresses with at least $5 of net buying in a pre-call window. Their histories describe subsequent token moves after earlier first group calls. They do not measure those addresses' actual profits or identify their owners.

The baseline waits five seconds, holds 60 or 180 seconds, charges a 10% proceeds haircut and clips returns to ±100%. A baseline becomes available only after its complete admission horizon and exit. Each token supplies one outcome; the target token's own history is excluded. Features use the prior day or all prior dates, the latest 20 outcomes per address, and three zero-return observations for shrinkage. Filters and sizing combine address familiarity, historical signal returns, win rates and performance relative to the earlier token cohort.

The primary retrospective daily replay returned **−5.57% with a 5.57% drawdown bound over 38 trades** under the $1,000 volume/fee model. The 2% training-drawdown selector returned **−6.78% / 6.78%**. Neither improved the saved choices. Training drawdown limits do not cap later drawdown.

`wallet_context_features.py` saves compact source histories and NumPy feature arrays. Reuse verifies compressed raw response hashes without reparsing all 487,906 rows. `wallet_context_lab.py` shares the existing path cache, exit simulation and portfolio search through `trade_flow_lab.run_search`. The search took 9.76 seconds after features and second bars were loaded; screening took 0.57 seconds. The earlier saved-choice benchmark reproduced exactly after this refactor. The event-selection audit compared 17,955 values against a direct scan of first-token events and perturbed future and target-token outcomes in 1,197 windows. Both methods share the aggregation formula; this audit specifically checks history selection and causality.

```sh
rtk python analysis/ayugram-token-strategy/wallet_context_lab.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

### EVM coverage correction

Use `coverage_repairs/evm/research/3bb3410a3806ad08/report.html` for the corrected replay and caller rankings. The corrected dataset has **1,100 eligible calls, 520 contracts and 45 senders**. It adds 34 eligible calls: 15 Robinhood, 13 BSC, two Base, two Avalanche and two Ethereum. The collector omitted some direct EVM body addresses and incorrectly mapped Robinhood to testnet chain 46630. [Robinhood mainnet is 4663](https://docs.robinhood.com/chain/add-network-to-wallet/).

Replaying the previously saved daily choices on corrected data returns **+3.77% with a 1.69% drawdown bound across ten trades** at a 5% sale-proceeds haircut. At 10% costs it returns **+2.99% / 1.84%**. One recovered BSC call adds a losing trade. Removing the best token leaves **+0.46%**; removing the best two gives **−0.97%**. These remain retrospective results, dependent on a small number of winners.

All 1,066 original quotes and candles were preserved, and their second-bar responses were reused byte for byte. Caller order changed for 15 shared signals and time since first call for 12. New prices were fetched later but bounded to the original observation deadline. The original snapshot and frozen validation protocol remain intact. One address posted three times has no exact Mobula match and remains unresolved.

The corrected **67,200-combination** short-hold/chain-filter search took **1.47 seconds after loading**, plus the separate data loading and stress replays. It evaluated 360 shortlisted portfolios. Its daily replay returned **−2.05% / 4.47% drawdown** at 5% costs and **−3.71% / 5.24%** at 10%. Caller, chain and fine-cap CSVs include 1/5/30/60-second entry waits and 5/10/15/30/60/120/180-second holds. Caller returns describe overlapping calls, not members' own trades or wallet profits.

```sh
rtk python analysis/ayugram-token-strategy/repair_coverage.py prepare
rtk env TOKEN_MENTIONS_PATH=analysis/ayugram-token-strategy/coverage_repairs/evm/token_mentions.json MOBULA_DATA_PATH=analysis/ayugram-token-strategy/coverage_repairs/evm/mobula_data.json node analysis/ayugram-token-strategy/fetch_mobula.mjs
rtk python analysis/ayugram-token-strategy/repair_coverage.py combine
rtk python analysis/ayugram-token-strategy/repair_coverage.py seconds
rtk python analysis/ayugram-token-strategy/repair_coverage.py replay
rtk python analysis/ayugram-token-strategy/corrected_research.py
```

The `seconds` phase prints a request manifest; pass that path to `fetch_second_bars.mjs` if its responses are missing. The saved completed cache requires no additional calls. Rebuilding after source changes creates another dataset identity. The figures below describe the original dataset and remain for comparison.

The corrected second cache contains 1,020 unique requests and 608,838 observed seconds. Of 19,551 comparable minute bars, 22 differ by more than 5%; discrepancies remain visible in the coverage file. The actual-message collector audit re-extracted all 14,273 archived messages, recovered all 55 repaired raw call records and retained every one of the 1,066 original eligible calls. Run `rtk node analysis/ayugram-token-strategy/audit_candidate_coverage.mjs` to reproduce it.

The unchanged-rule extension is frozen in `coverage_repairs/evm/validation_extension/forward_protocol.json`. It uses repaired historical context plus the previously seen first window, then evaluates messages after **07:30:43 UTC**. Its new collection added 21 messages through **07:50:22 UTC**, with three eligible calls in the reserved window and **zero trades**. The merged archive now has 14,312 messages and 1,116 eligible calls. This second empty window also supplies no profitability evidence. Its report is `coverage_repairs/evm/validation_extension/validation/report.html`.

```sh
rtk python analysis/ayugram-token-strategy/extend_frozen_validation.py prepare
rtk python analysis/ayugram-token-strategy/extend_frozen_validation.py collect
rtk python analysis/ayugram-token-strategy/validate_cohort.py --protocol analysis/ayugram-token-strategy/coverage_repairs/evm/validation_extension/forward_protocol.json
```

The cohort experiment adds recent completed outcomes from other tokens to the entry filter and position size. It searched 120 sizing policies with 19 cohort gates. Daily training selection with a 5% training drawdown ceiling returned **+4.28%**, with a **1.61% candle drawdown bound**, across **nine trades** on October 18–20. The days had already been examined during research. Removing the two best tokens changes the minute replay to **−0.51%**. This is a research candidate, not a validated trading edge.

The latest fixed rule was saved in `cohort_runs/cdbe9d78885db2c1/forward_protocol.json` before another Telegram/Mobula collection. The new window added 18 messages, 11 token messages and eight eligible calls after the training market cutoff. None passed the entry filter. The validation therefore entered zero trades and provides no evidence for profitability. Old observations were preserved: all 1,066 original calls and 19 numeric array fields matched, and the separate replay reproduced all nine prior trades.

The one-second cache contains 986 unique requests covering those 1,066 original calls. It has 600,201 observed seconds; five calls have no usable second bars. Reconstructing 19,008 minute bars yielded 18 discrepancies above 5%, retained in `second_bars/coverage.json`. Empty intervals cannot supply a fill.

With second-by-second trailing decisions and a one-second reaction delay, the same daily rule choices returned **+4.22% / 1.40% drawdown bound** at a 5% sale-proceeds haircut and **+3.54% / 1.47%** at 10%. These are execution sensitivity replays on the old dates. A separate **49,920-combination** search used holds of **5–180 seconds**, entry waits of 1–60 seconds, cap/caller/cohort filters, fixed stops, targets and trailing exits. Its daily replay returned **−0.16% / 2.36% drawdown bound** at 5% costs and **−1.32% / 2.23%** at 10%.

Reproduce from the cached data:

```sh
rtk python analysis/ayugram-token-strategy/cohort_lab.py
rtk python analysis/ayugram-token-strategy/validate_cohort.py --protocol analysis/ayugram-token-strategy/cohort_runs/cdbe9d78885db2c1/forward_protocol.json
rtk python analysis/ayugram-token-strategy/second_lab.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

The second runner saves the catalog, every screening score/count, shortlisted portfolio evaluations, trade ledgers, code hashes and exact source. Its screen uses a clipped-return heuristic; it does not estimate statistical confidence after the parameter search.

Second bars can be collected separately; a completed cache needs no further API calls:

```sh
rtk python analysis/ayugram-token-strategy/prepare_second_bars.py
rtk node analysis/ayugram-token-strategy/fetch_second_bars.mjs
```

Second-resolution exits execute at the next observed trade after the signal candle closes plus the reaction delay. Both entry and exit fills allow at most ten seconds of waiting. An unavailable entry is skipped; an unavailable exit is written down to zero. The write-down is a conservative valuation assumption. It does not establish that a real sale would return zero. Sale-proceeds haircuts are stress assumptions, and historical AMM capacity and MEV remain unmodeled.

For isolated future collections, `fetch_mentions.mjs` accepts `TOKEN_MENTIONS_PATH`, `TOKEN_MENTIONS_SINCE` and `TOKEN_MENTIONS_UNTIL`; `fetch_mobula.mjs` accepts `TOKEN_MENTIONS_PATH` and `MOBULA_DATA_PATH`; `archive_messages.mjs` accepts `MESSAGE_ARCHIVE_ROOT` and `MESSAGE_ARCHIVE_SINCE`. Keep each validation collection separate and freeze its parameters before inspecting the new data. Repeated invocations of the current validator reuse its original fixed window; extending a study requires a separately dated protocol.

## Conditional entries and historical reported metrics

Two further searches were rejected after daily retrospective replay:

| Search | Scope | Return at 5% cost | Drawdown bound | Trades |
| --- | --- | ---: | ---: | ---: |
| Conditional entries | 1,705,600 combinations | −7.04% | 11.94% | 22 |
| Reported liquidity and holder features | 346,320 portfolio evaluations | −7.28% | 7.51% | 9 |

The entry search includes 164 dip, recovery, breakout, momentum and wait triggers; 30–180 second expiry; cancellation after a price collapse; maximum entry-price chase; cap repricing at the trigger; and sizing based on observed activity, recent price range and relative volume. It uses only completed seconds. Absolute candle volume is not treated as dollar liquidity. The primary training drawdown ceiling is 5%; a 2% ceiling and a best-token-removal training check are saved separately. Training ceilings do not bound later drawdown.

The message feature parser archived 820 bot-reported token snapshots. It timestamps each version at its final edit, which permits using an edited message only after that edit actually occurred. At a one-minute observation delay, holder information is available for 557 original calls and liquidity/FDV for 314. The 261 gates cover holder count/age/concentration, liquidity, bundles, snipers, developer balance, fresh-wallet proportions, buying activity and bonding progress. Missing fields pass or fail explicitly as specified. These are reported metrics, not independently verified chain state. The search refines the 18 strongest non-model training rules at each cutoff, with 36 sizing policies.

The extraction audit separates primary calls, holder/developer wallet references, comparison tokens, prior developer launches and performance-report links. It found no unpriced direct Solana calls under the checked body and primary-link formats. Secondary token references remain separately classified and are not silently treated as new direct calls. Explicitly reported developer-wallet links are grouped by a local hash; no Telegram-member ownership is inferred.

The active account returned no history before message 2914006 and none of ten explicitly referenced older messages. The other two stored AyuGram accounts did not resolve the target group after their dialogs were enumerated. Probe results are in `history_boundary_probe*.json`.

```sh
rtk python analysis/ayugram-token-strategy/entry_trigger_lab.py
rtk python analysis/ayugram-token-strategy/message_features.py
rtk python analysis/ayugram-token-strategy/reported_metrics_lab.py
rtk python analysis/ayugram-token-strategy/audit_causal_features.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

The causal audit checked 15,908 scalar trigger decisions. Changing future prices and volumes preserved 43,488 earlier trigger decisions and their sizing inputs. Changing later reported snapshots preserved 1,936 earlier feature rows. The original nine-trade second-resolution cohort replay remains +4.22% with a 1.40% drawdown bound. Exact run sources, catalogs, screening arrays and evaluated portfolios are retained; these additional results supply no evidence to replace that provisional candidate.

## Decider, fine cap bands, and position sizing

Open `adaptive_report.html` for the combined results. `adaptive_comparison.json` identifies the primary run and the separate sensitivity runs. The primary remains `adaptive_runs/70fab2c549e7e89e`; `adaptive_runs/latest.json` can point to a later sensitivity run.

The model cache contains 5,078 requests and 25,390 answers, covering five feature delays. It uses the same native Decisions API as `src/intelligence/spam-filter.ts`. The bot's pinned `perplexity/pplx-decider-v1.1-27b` returned HTTP 404 with no endpoints. This research explicitly used `perplexity/pplx-decider-v1.2-20261016` instead.

The completed cache is reused by these offline searches:

```sh
rtk python analysis/ayugram-token-strategy/adaptive_lab.py
rtk python analysis/ayugram-token-strategy/adaptive_lab.py --latency-bars 2
rtk python analysis/ayugram-token-strategy/adaptive_lab.py --model-directions both
```

Each search saves its exact code, catalog, masks, all screening means and scores in `screen.npz`, shortlisted portfolio results in CSV files, selected trade ledgers, and an HTML report. Old runs keep their code and IDs. A new code hash creates a new run. `--shortlist` controls the number of top rules from each training metric and model group sent to the portfolio stage. `--seed` changes the reproducible interaction catalog.

The new cap edges are $3k, $4k, $6k, $8k, $10k, $15k, $25k, $50k, $100k, $250k, $500k, $1m, $2m and $5m. The catalog includes disjoint bands, wider bands and cumulative cutoffs. Both historical quote cap and cap repriced with the last completed candle are available. Repricing assumes unchanged supply. Small groups remain visible in the diagnostic tables even when they cannot meet the search's training sample requirement.

The 549 sizing policies combine equity fractions from 0.5% to 7.5%, cap and volatility multipliers, earlier caller results, earlier cap/score bucket results, Decider scores, daily loss budgets, drawdown reductions, loss-streak pauses, and one trade per contract. Each portfolio has one open unleveraged position. The entire stake, rather than the stop distance, counts against a daily loss budget. This does not model historical pool capacity or guarantee a live loss limit.

The primary selection rule maximizes training return under a 10% proceeds haircut while requiring a training candle-range drawdown bound within 10%, at least 10 entered trades, and 8 contracts. It can select cash. Comparison selectors and risk ceilings remain in the report. The original and inverted model-score searches are separate; inverted thresholds were added after viewing calibration and have no independent validation.

Model inputs omit outcomes, future candles, post-edited message bodies, addresses, links, handles and ticker identifiers. They include completed candles and earlier caller records only. Model outputs are uncalibrated trading features. Both model and non-model rules wait one extra full minute before their next-open entry in the primary comparison. The second run adds another minute. A measured model request exceeding the available wait cannot supply a trade decision.

The collector is separate and is unnecessary when the saved cache is complete:

```sh
rtk python analysis/ayugram-token-strategy/research_decider.py prepare --model perplexity/pplx-decider-v1.2-20261016
rtk node analysis/ayugram-token-strategy/fetch_decider.mjs --concurrency 6
rtk python analysis/ayugram-token-strategy/research_decider.py status
```

`prepare` writes content-addressed requests without credentials. `fetch_decider.mjs` reads `OPENROUTER_API_KEY` from the existing local environment, skips cached successes, retries temporary failures, and saves raw answers, usage and latency. A changed prompt/model creates a separate cache. Request and response hashes are recorded in every run. No Telegram messages or trades are sent.

To rebuild the combined comparison and replay sizing changes against the original chosen rules:

```sh
rtk python analysis/ayugram-token-strategy/adaptive_review.py --primary analysis/ayugram-token-strategy/adaptive_runs/70fab2c549e7e89e --others analysis/ayugram-token-strategy/adaptive_runs/a145d397796bce84 analysis/ayugram-token-strategy/adaptive_runs/d30a3e07f657be13
```

The review reconciles actual trade ledgers, position limits, overlap, contract limits and full-loss daily reserves. The adaptive runner also compares 24 real-data flat-size portfolios with the earlier engine before searching. These checks establish implementation consistency, not a profitable strategy.

## Run a search

```sh
rtk python analysis/ayugram-token-strategy/research_lab.py sweep --theories 1000000
```

The budget caps the number of evaluated combinations. When it exceeds the catalog size, every eligible distinct entry mask is paired with every exit rule. The default fill is the next full candle's open. A quote or confirmation-close fill can be compared explicitly:

```sh
rtk python analysis/ayugram-token-strategy/research_lab.py sweep --theories 1000000 --fill close
rtk python analysis/ayugram-token-strategy/research_lab.py sweep --theories 1000000 --cost 0.10
```

With a smaller budget, sampling is deterministic. `--seed` changes the reproducible interaction catalog and sample. `--shortlist` controls how many leaders from each of the training score and mean-return rankings receive full portfolio replays. `--rerun` recomputes a completed run; interrupted screening resumes from committed SQLite rows by default.

The current catalog includes market-cap bands, token age, quote freshness, entry waits, positive momentum, dip entries, candle range and close position, growing or fading volume, first and later callers, caller history, UTC sessions, human or bot senders, and message/link context. Exit families include time exits from 1 to 10 minutes, stops, 1.1x to 3x targets, trailing exits, early time exits, partial profit taking, and breakeven stops.

Every 1-minute price path is simulated once for each entry delay and exit configuration, then reused by the filters. Filters that select the same calls at the same delay share an evaluation. Their exact parameter aliases remain saved. Scores for all evaluated combinations go into SQLite; only the training shortlist gets the more expensive cash and portfolio replay.

## Saved files

- `datasets/latest.json` identifies the active dataset. Each dataset has read-only raw message, token-mention, and Mobula files, a SHA-256 manifest, compiled NumPy arrays, and reusable outcome caches. Loading a dataset checks its raw file hashes.
- `runs/latest.json` identifies the most recent run.
- Each run contains `results.sqlite`, `summary.json`, `report.md`, `leaderboard.csv`, `caller_ranking.csv`, and the exact Python source in `code/`.
- `settings.json` records the dataset path, cost and fill assumptions, random seed, code hashes, and Python/NumPy versions.
- The database tables are `entries`, `exits`, and `candidates`. `early_*`, `train_*`, and `rolling_*` use progressively later training cutoffs. `later_*` contains the reused later-date evaluation. `full_*` is fitted on all available data.

The original research files remain available for comparison. They use older assumptions. Use a specific new run's settings when comparing numbers.

## Replay an exact rule

The rule ID is local to its run. Copy one from that run's report or leaderboard:

```sh
rtk python analysis/ayugram-token-strategy/research_lab.py replay --rule-id 123 --cost 0.10 --stake 2 --start 2026-10-19 --end 2026-10-21
```

The command writes every entered trade and equity observation to a new replay JSON file. Use `--run /absolute/path/to/run` to select an older run. If the engine has changed, the command directs you to that run's archived Python source so an old result is not silently recomputed with new logic.

## Freeze or refresh inputs

The archive and snapshot are already saved. Repeating these commands reuses completed matching data:

```sh
rtk node analysis/ayugram-token-strategy/archive_messages.mjs
rtk python analysis/ayugram-token-strategy/research_lab.py prepare
```

The message archiver reads the authorized Telegram account and stops at the existing token-mention cutoff. It respects Telegram flood waits and resumes its checkpoint. It stores message text, sender metadata, dates, edit dates, links, and reply metadata. It never saves the session or API keys into the research dataset.

For new dates, run the existing `fetch_mentions.mjs` and `fetch_mobula.mjs` collectors first, then archive and prepare. Those collection commands use the already configured local AyuGram, Powerreach, and Starswap credentials. They are separate from all research commands. A new set of raw inputs creates a new dataset ID and cannot silently replace an earlier snapshot.

## Execution checks

```sh
rtk python analysis/ayugram-token-strategy/check_research_engine.py
rtk python analysis/ayugram-token-strategy/research_lab.py benchmark
```

The first command checks stop/target collisions, gap fills, partial proceeds, breakeven timing, trailing timing, stale prices, missing confirmation candles, next-open entries, cash and one-position constraints, and causal caller history. The benchmark compares 72 configurations and more than 74,000 real trade cases with the previous simulator, using matching assumptions, and records measured timings.

## Reading the results

### Fixed partial-sale candidates and new-window replay

`fixed_partial_runs/3d80934062b6022e/forward_protocol.json` freezes the fit at 2026-10-21 09:33:36 UTC.
The 7,254 full-training portfolio evaluations retain the earlier entry/cohort filter and compare 403 distinct exits
with nine allocation/daily-budget settings. The primary 2% training-drawdown selector chose a 1.25% base allocation
and no partial sales. At a 5% proceeds haircut it returns +6.10% with a 1.53% drawdown bound on fourteen training trades.
The secondary candidate sells 25% at a 1.2× trigger and uses a 5% base allocation. The robustness comparator sells
75% at 3× with a 2.5% base allocation and 2% daily full-loss budget; its training return after removing two winners
remains +0.28% at 10% costs. These are selected in-sample results, not improvements over an independent evaluation.

The newly collected window contains no calls: fourteen additional archived messages all predate its start.
The validator preserved all 1,122 older call records and nineteen numeric fields. It computes cohort features on the
full combined history, then requests second bars and preceding fee/volume windows only for new eligible calls.
An offline execution-view audit reproduced twenty complete training portfolios, 288 scalar outcomes, 280 portfolio
trade calculations and 5,832 feature values using the existing cache.

From the repository root, the completed window can be reproduced without network requests:

```sh
rtk python analysis/ayugram-token-strategy/validate_partial_fixed.py evaluate --protocol analysis/ayugram-token-strategy/fixed_partial_runs/3d80934062b6022e/forward_protocol.json
rtk python analysis/ayugram-token-strategy/audit_fixed_partial.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

For a new frozen protocol, collect its messages through `extend_frozen_validation.py collect --output <run-directory>`.
Then run `validate_partial_fixed.py prepare`, `collect`, and `evaluate`, each with `--protocol <protocol-file>`.
The `collect` phase makes API requests; the other phases use saved files. The existing protocol must remain immutable;
extending a window requires a separate protocol with unchanged behavioral fields and explicit new bounds. No retraining
is allowed during validation. `fit_partial_fixed.py` creates a distinct full-training fit when its source inputs change;
that is a new experiment, not an extension of an existing validation.

### Activity sizing and nearby-parameter sensitivity

`activity_policy_lab.py` retains the three earlier saved daily entry/cohort filters and daily budgets. It compares
207 activity modifiers, four allocation scales and six exits per day. The 14,904 policy rows require 13,476 distinct
portfolio replays after caching equivalent stake vectors on completed training calls. The cache key excludes future
features and outcomes. The measured search took 16.28 seconds; this is one run, not a repeated timing benchmark.

The activity inputs describe recent volume acceleration, buying-share changes, net/gross within-transaction flow,
trading gaps, active seconds, recipient concentration/breadth, short price returns and reference fee burden. Features
use the existing pre-call trade cache with a five-second lag. A failed condition rejects the call or scales it to 25%
or 50%. Missing values fail their condition. Net/gross flow is a routing/churn proxy, not a wash-trading classification.

The 5% training-drawdown selector returns +2.63% / 1.32% drawdown on ten retrospective trades, versus +2.62% / 1.55%
for the saved control, at 5% sale costs. It loses 1.00% without its two best evaluation tokens. The 2% selector performs
worse than the earlier partial-sale procedure. The separate robustness selector returns +3.37% on only three trades;
removing its activity filter leaves those same trades unchanged, and removing two winners makes it lose. No new
policy is promoted to the frozen validation protocols.

`local_robustness_lab.py` changes one parameter at a time around the fixed candidates, covering cap/dip boundaries,
cohort count/threshold, holding time, trail settings, allocation and partial-sale terms. All nearby variants remain
profitable in the full training data. At 10% costs, only 1/26 smaller-position variants, 1/30 larger partial-sale
variants and 10/30 robustness-comparator variants remain positive after removing their respective two best tokens.
This is sensitivity on previously inspected data and does not establish generalization.

```sh
rtk python analysis/ayugram-token-strategy/local_robustness_lab.py
rtk python analysis/ayugram-token-strategy/activity_policy_lab.py
rtk python analysis/ayugram-token-strategy/audit_activity_policy.py
rtk analysis/ayugram-token-strategy/.plot-venv/bin/python analysis/ayugram-token-strategy/activity_policy_frontier.py
rtk python analysis/ayugram-token-strategy/research_status.py
```

The plot environment is local to this research directory and contains Matplotlib 3.11.2. Plot source values are saved
beside the SVG/PNG artifacts. The audit checks 29,700 independent feature calculations, 62,100 modifier values,
580 uncached portfolios, 5,458 trade-accounting calculations and all twelve main chronological portfolios.

All historical dates have already been examined. Daily selection uses only earlier completed outcomes, but the overall exercise is retrospective research. Searching more configurations increases the chance of finding an accidental winner. The full-data candidate has no new evaluation sample.

The primary selector allows cash and requires at least 10 entered training trades, a positive training portfolio return, and a candle-range drawdown bound below 10%. It considers fixed stakes of $2 or $5 per $100 and one open position. This bound constrains the training fit only; later drawdown can exceed it.

The default proceeds haircut is 5%. Each report also includes 2%, 10%, and 15% scenarios, alternate fills, a fixed transaction-fee example, and one trade per contract. These are modeling assumptions rather than observed execution costs. There is no historical pool-impact or transaction-ordering model.

One-minute candles cannot support a 10-second backtest. Confirmation waits add to the hold, and an immediate quote entry may wait for the next full minute before its modeled holding bars begin. Stops win ambiguous stop/target collisions. The drawdown bound uses candle ranges, including the exit candle, and can exceed the actual tradable path's drawdown. Closed-equity drawdown is saved separately.

Message text is usable as a historical feature only when it was not edited after posting. The archive cannot reconstruct earlier edits or deleted messages. Current liquidity, holder concentration, spam flags, and later token performance are excluded from entry features. Caller performance is grouped by Telegram sender; the dataset contains no inferred sender-to-wallet links.
