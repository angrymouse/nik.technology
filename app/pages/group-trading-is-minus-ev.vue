<script setup lang="ts">
import research from '../../public/research/group-trading/results.json'

const title = 'Group trading is minus EV'
const description = '14,273 Telegram messages, 1,100 eligible calls, and a search for a trading edge that survives costs, drawdown, and the loss of its best winners.'
const canonical = 'https://nik.technology/group-trading-is-minus-ev'
useSeoMeta({ title: `${title} | Nik Rykov`, description, ogTitle: title, ogDescription: description,
  ogType: 'article', ogUrl: canonical, articlePublishedTime: '2026-10-21', twitterCard: 'summary' })
useHead({ link: [{ rel: 'canonical', href: canonical }] })

const delay = ref(5)
const period = ref('later')
const policyCost = ref(.1)
const delays = [...new Set(research.baselines.map(row => row.entryDelaySeconds))]
const displayedBaselines = computed(() => research.baselines
  .filter(row => row.entryDelaySeconds === delay.value && row.period === period.value)
  .sort((a, b) => a.holdSeconds - b.holdSeconds))
const baselineLosses = research.baselines.filter(row => row.return < 0).length
const baselineBest = Math.max(...research.baselines.map(row => row.return))
const baselineWorst = Math.min(...research.baselines.map(row => row.return))
const selectedPool = research.poolComparison.rows.find(row => row.allocationMultiplier === .75)!
const eligibleObserved = research.observationWindows.reduce((total, row) => total + row.eligibleCalls, 0)
const strongestSizing = research.sizing.rows.filter(row => row.allocationMultiplier === .75 && [0, 1, 1.5].includes(row.strength))
const assets = '/research/group-trading'

function pct(value: number, digits = 2, signed = true) {
  return `${signed && value > 0 ? '+' : ''}${(value * 100).toFixed(digits)}%`
}
function number(value: number) { return value.toLocaleString('en-US') }
function drawdown(value: number, digits = 2) { return pct(Math.abs(value), digits, false) }
function capBand(value: string) {
  const compact = (raw: string) => {
    const amount = Number(raw)
    return amount >= 1e6 ? `$${amount / 1e6}m` : `$${amount / 1000}k`
  }
  const [low, high] = value.split('-')
  return high === 'inf' ? `${compact(low)}+` : `${compact(low)} to ${compact(high)}`
}
function costResult(row: typeof research.callerPolicies[number]) {
  return row.costs.find(item => item.cost === policyCost.value)!
}
function time(value: string) { return value.slice(11, 19) }
</script>

<template>
  <main class="research-page">
    <article class="research-article">
      <header class="research-header">
        <NuxtLink to="/" class="home-link">← nik.technology</NuxtLink>
        <p class="eyebrow">Research notes · <time datetime="2026-10-21">21 October 2026</time></p>
        <h1>Group trading<br>is <span>minus EV.</span></h1>
        <p class="standfirst">I tried to turn a Telegram group's token calls into a profitable trading strategy.
          Short holds, caller rankings, tiny market caps, partial exits, position sizing, a decision model.
          The easy strategies lost money. The promising ones depended on a handful of winners and generous execution assumptions.</p>
        <p class="scope">This is a study of one group over six calendar dates. It has not established a reliable positive expected value,
          or proved that every possible strategy must lose.</p>
        <div class="headline-stats">
          <div><strong>{{ baselineLosses }}/{{ research.baselines.length }}</strong><span>simple baselines lost money</span></div>
          <div><strong>{{ number(research.dataset.eligibleFirstCalls) }}</strong><span>eligible first calls</span></div>
          <div><strong>8 or 9</strong><span>trades behind the narrowest edge</span></div>
        </div>
      </header>

      <nav class="contents" aria-label="Research sections">
        <a href="#baselines">Simple trades</a><a href="#search">The search</a><a href="#callers">Callers &amp; caps</a>
        <a href="#decider">Decider</a><a href="#execution">Execution</a><a href="#observations">New observations</a><a href="#data">Data</a>
      </nav>

      <section id="baselines">
        <p class="section-number">01 / Start with the obvious trade</p>
        <h2>Buy the call. Sell a few seconds later.</h2>
        <p>The baseline grid uses six entry waits, nine holds from 5 to 180 seconds, and two chronological periods.
          All {{ research.baselines.length }} accounts lose money. Returns range from {{ pct(baselineWorst) }} to {{ pct(baselineBest) }}.</p>
        <p>Each trade uses up to 1% of account equity, with one open position, one purchase per contract, a 4% daily loss reserve,
          and a 5% haircut to sale proceeds. These early baselines do not include separate gas, MEV, or price-impact estimates.</p>

        <div class="baseline-explorer">
          <div class="controls">
            <label>Entry wait
              <select v-model.number="delay"><option v-for="seconds in delays" :key="seconds" :value="seconds">{{ seconds }} seconds</option></select>
            </label>
            <label>Period
              <select v-model="period"><option value="earlier">16–18 October</option><option value="later">19–21 October</option></select>
            </label>
          </div>
          <p class="chart-heading">Account return by holding period <span>5% sale haircut</span></p>
          <div class="baseline-bars" aria-live="polite" aria-atomic="true">
            <div class="baseline-bar-row" v-for="row in displayedBaselines" :key="row.holdSeconds">
              <span class="hold-label">{{ row.holdSeconds }}s</span>
              <div class="bar-track" aria-hidden="true"><div class="loss-bar" :style="{ width: `${Math.abs(row.return) / .12 * 100}%` }" /></div>
              <span class="loss-value">{{ pct(row.return) }}</span>
              <span class="trade-count">{{ row.trades }} trades</span>
            </div>
          </div>
          <p class="small-note">Bar length is loss magnitude on a 0–12% scale. These accounts overlap; they are not 108 independent samples.</p>
          <details>
            <summary>Drawdowns and missing-sale write-downs</summary>
            <div class="table-scroll"><table>
              <caption>Selected baseline accounts</caption>
              <thead><tr><th scope="col">Hold</th><th scope="col">Return</th><th scope="col">Drawdown bound</th><th scope="col">Trades</th><th scope="col">Write-downs</th></tr></thead>
              <tbody><tr v-for="row in displayedBaselines" :key="row.holdSeconds"><th scope="row">{{ row.holdSeconds }}s</th><td>{{ pct(row.return) }}</td><td>{{ drawdown(row.drawdownBound) }}</td><td>{{ row.trades }}</td><td>{{ row.writeoffs }}</td></tr></tbody>
            </table></div>
          </details>
        </div>
        <p class="small-note">Fills require an observed trade within ten seconds. Missing entries are skipped.
          A missing sale is valued at zero recovery, a conservative accounting assumption rather than proof the token became worthless.
          Drawdown uses candle highs and lows; it is a bound, not a measured tick-by-tick account path.</p>
      </section>

      <section id="search">
        <p class="section-number">02 / Make the rules less naive</p>
        <h2>A lot of ways to lose more carefully</h2>
        <p>The archive contains {{ number(research.dataset.archivedMessages) }} messages from 16 through 21 October.
          Correcting missed EVM addresses produced {{ number(research.dataset.eligibleFirstCalls) }} eligible first calls across
          {{ research.dataset.firstCallContracts }} contracts and {{ research.dataset.senders }} senders.
          Keeping repeated calls expands that to {{ number(research.dataset.callsIncludingRepeats) }} calls and
          {{ research.dataset.contractsIncludingRepeats }} contracts.</p>
        <p>The search covers entry delays and dips, rebounds and breakouts, fixed stops, trailing stops, partial sales,
          2×/3×/4× targets, repeated calls, caller history, recent outcomes on other tokens, transaction flow,
          reported holders and liquidity, recurring addresses, and account-level risk controls.</p>
        <p>Market-cap cutoffs include $3k, $4k, $6k, $8k, $10k, $15k, $25k, $50k, $100k, $250k, $500k, $1m, $2m, and $5m.
          The search tries narrow bands, wider ranges, and cumulative cutoffs. It does not assume that everything below $50k behaves alike.</p>
        <div class="table-scroll"><table>
          <caption>Three unsuccessful daily selection procedures · 5% sale haircut</caption>
          <thead><tr><th scope="col">Search</th><th scope="col">Size of search</th><th scope="col">Return</th><th scope="col">Drawdown bound</th><th scope="col">Trades</th></tr></thead>
          <tbody><tr v-for="row in research.historicalSearches" :key="row.label"><th scope="row">{{ row.label }}</th><td>{{ number(row.evaluations) }}<small>{{ row.evaluationUnit }}</small></td><td class="negative">{{ pct(row.return) }}</td><td>{{ drawdown(row.drawdownBound) }}</td><td>{{ row.trades }}</td></tr></tbody>
        </table></div>
        <p>Daily selections train on earlier completed outcomes. That avoids using a future trade to choose its own rule.
          It does not undo repeated research on the same dates. These are retrospective comparisons, with different rules selected on different days.</p>
      </section>

      <section id="callers">
        <p class="section-number">03 / Caller selection</p>
        <h2>A caller ranking is easy to overread</h2>
        <p>Scanner replies can make one call look like two endorsements. Of 508 bot-authored calls in the corrected first-call dataset,
          487 could be linked to an earlier human request containing the same complete contract address.
          Deduplicating requester/contract pairs leaves 614 history events.</p>
        <p>Caller policies use only earlier completed outcomes and exclude the token currently being scored. They compare a caller with peers,
          shrink small samples toward the peer mean, and try rejecting or reducing positions from weaker histories.</p>
        <label class="inline-control">Sale haircut for caller and model tables
          <select v-model.number="policyCost"><option :value=".05">5%</option><option :value=".1">10%</option><option :value=".15">15%</option></select>
        </label>
        <div class="table-scroll"><table>
          <caption>Caller-policy portfolios · estimated fees included</caption>
          <thead><tr><th scope="col">Procedure</th><th scope="col">Return</th><th scope="col">Drawdown bound</th><th scope="col">Trades</th></tr></thead>
          <tbody><tr v-for="row in research.callerPolicies" :key="row.label"><th scope="row">{{ row.label }}</th><td>{{ pct(costResult(row).return) }}</td><td>{{ drawdown(costResult(row).drawdownBound) }}</td><td>{{ costResult(row).trades }}</td></tr></tbody>
        </table></div>
        <p>The larger requester policy looks better than the earlier choices. Its entire improvement comes from omitting one losing BNB Chain trade.
          A Solana-only rule or a BNB exclusion reproduces its ledger exactly at all three cost settings.
          That result cannot distinguish caller skill from one changed chain exposure. Every caller-policy variant loses after removing its two best tokens.</p>
        <details>
          <summary>Anonymous caller ranking, ordered by earlier performance</summary>
          <p>One-second entry wait, 60-second hold, 5% sale haircut. Ranking uses 16–17 October; the later column uses the remaining history.
            Require at least five observations in both periods. These are overlapping per-call returns, not account returns or members' personal PnL.</p>
          <div class="table-scroll"><table>
            <caption>Earlier ranking and later per-call outcomes</caption>
            <thead><tr><th scope="col">Caller</th><th scope="col">Earlier calls</th><th scope="col">Earlier mean</th><th scope="col">Later calls</th><th scope="col">Later mean</th><th scope="col">Later median</th></tr></thead>
            <tbody><tr v-for="row in research.callerReference.rows" :key="row.caller"><th scope="row">{{ row.caller }}</th><td>{{ row.earlier.observations }}</td><td>{{ pct(row.earlier.meanReturn) }}</td><td>{{ row.later.observations }}</td><td>{{ pct(row.later.meanReturn) }}</td><td>{{ pct(row.later.medianReturn) }}</td></tr></tbody>
          </table></div>
        </details>
        <details>
          <summary>Market-cap bands under one fixed reference trade</summary>
          <p>One-second wait, 60-second hold, 5% sale haircut, all historical dates. These are overlapping per-call observations.
            Empty bands are omitted. This descriptive table is not a fitted blacklist; thin bands and shared tokens can produce unstable averages.</p>
          <div class="table-scroll"><table>
            <caption>Per-call outcomes by quoted market cap</caption>
            <thead><tr><th scope="col">Cap band</th><th scope="col">Calls</th><th scope="col">Contracts</th><th scope="col">Mean</th><th scope="col">Median</th><th scope="col">Win rate</th></tr></thead>
            <tbody><tr v-for="row in research.capReference.rows" :key="row.band"><th scope="row">{{ capBand(row.band) }}</th><td>{{ row.observations }}</td><td>{{ row.contracts }}</td><td>{{ pct(row.meanReturn) }}</td><td>{{ pct(row.medianReturn) }}</td><td>{{ pct(row.winRate, 1, false) }}</td></tr></tbody>
          </table></div>
        </details>
        <p>Recurring wallet addresses also supply historical features. Repeated activity around a caller's tokens does not establish that the caller owns those wallets.</p>
      </section>

      <section id="decider">
        <p class="section-number">04 / Ask a decision model</p>
        <h2>Decider did not establish an advantage</h2>
        <p>The context experiment sent 1,066 anonymous numeric requests to Decider v1.2 and cached 6,396 answers.
          Inputs included completed price bars, cap and age, earlier caller outcomes, transaction activity, and prior outcomes associated with recurring recipients.
          They excluded token identifiers, handles, raw messages, future prices, and future outcomes.</p>
        <div class="table-scroll"><table>
          <caption>Context Decider portfolios · {{ pct(policyCost, 0, false) }} sale haircut plus estimated fees</caption>
          <thead><tr><th scope="col">Procedure</th><th scope="col">Return</th><th scope="col">Drawdown bound</th><th scope="col">Trades</th></tr></thead>
          <tbody><tr v-for="row in research.deciderPolicies" :key="row.label"><th scope="row">{{ row.label }}</th><td>{{ pct(costResult(row).return) }}</td><td>{{ drawdown(costResult(row).drawdownBound) }}</td><td>{{ costResult(row).trades }}</td></tr></tbody>
        </table></div>
        <p>All four model procedures lose after removing two winning tokens. Uniform sizing controls, matched to earlier training exposure,
          also explain much of the apparent benefit. The smaller raw model retains a modest historical drawdown improvement;
          uniform sizing beats the smaller calibrated model on both return and drawdown.</p>
      </section>

      <section id="execution">
        <p class="section-number">05 / Make the fills less generous</p>
        <h2>The remaining edge is very thin</h2>
        <p>The later candidate waits for a first-minute dip, filters market cap and recent completed token outcomes,
          then uses volatility/cohort sizing, a 3× target, and a five-minute timeout.
          It admits only eight or nine historical trades. Searching more ways to size or exit those trades does not create more evidence.</p>
        <div class="table-scroll"><table>
          <caption>28 exit rules × 2 allocations · settings that pass the declared concentration and scenario checks</caption>
          <thead><tr><th scope="col">Price model</th><th scope="col">Passing settings</th></tr></thead>
          <tbody><tr><th scope="row">Vendor candles</th><td>26 / 56</td></tr><tr><th scope="row">Ordinary recorded swaps</th><td>12 / 56</td></tr><tr><th scope="row">Unfavorable recorded swaps</th><td class="negative">0 / 56</td></tr></tbody>
        </table></div>
        <p>The unfavorable case buys at the entry-second high and sells at a later sale-second low. It is a within-second price stress,
          not a price that could have been known in advance. The grid adds 168,000 accounts to 84,000 vendor-price controls.</p>
        <h3>Stronger sizing reduces both drawdown and return</h3>
        <p>Another 63,000 accounts vary the response to the saved sizing factor. Strength zero removes variation between valid factors;
          strength one uses the original formula; 1.5 amplifies it. Capacity limits still apply.</p>
        <div class="table-scroll"><table>
          <caption>Three-quarter allocation · 10% sale haircut plus fees · extrema across all three price and capacity modes</caption>
          <thead><tr><th scope="col">Factor strength</th><th scope="col">Minimum return</th><th scope="col">Largest DD bound</th><th scope="col">After two best tokens</th></tr></thead>
          <tbody><tr v-for="row in strongestSizing" :key="row.strength"><th scope="row">{{ row.strength }}×</th><td>{{ pct(row.minimumReturn, 3) }}</td><td>{{ drawdown(row.maximumDrawdownBound, 3) }}</td><td class="negative">{{ pct(row.minimumWithoutTwoBest, 4) }}</td></tr></tbody>
        </table></div>
        <details class="figure-details"><summary>Full sizing-response figure</summary>
          <figure><a :href="`${assets}/sizing-response.svg`"><img :src="`${assets}/sizing-response.svg`" alt="Return, drawdown, and two-winner removal across seven sizing strengths and two allocation levels" loading="lazy" width="1440" height="960"></a>
            <figcaption>All seven sizing strengths. Open the figure for its full resolution.</figcaption></figure>
        </details>
        <h3>Selecting a pool does not add the edge</h3>
        <p>The routing study tests 12 ways to choose the largest recent-volume pool. It includes
          {{ number(research.poolComparison.accounts) }} accounts and {{ number(research.poolComparison.pairRemovals) }} exhaustive token-pair removals.
          Removing a token reruns account admissions, so a previously skipped opportunity can enter.</p>
        <p>Using entry-time capacity estimates leaves a small positive worst case at three-quarter allocation.
          But the all-pool control already has that result when compared under the same assumptions.</p>
        <div class="table-scroll"><table>
          <caption>Matched capacity modes · three-quarter allocation · 10% sale haircut plus estimated fees</caption>
          <thead><tr><th scope="col">Price source</th><th scope="col">Minimum return</th><th scope="col">Largest DD bound</th><th scope="col">After two best tokens</th></tr></thead>
          <tbody>
            <tr><th scope="row">All pools, matched controls</th><td>{{ pct(selectedPool.allPools.minimumReturn, 5) }}</td><td>{{ drawdown(selectedPool.allPools.maximumDrawdownBound, 4) }}</td><td>{{ pct(selectedPool.allPools.minimumWithoutTwoBest, 5) }}</td></tr>
            <tr><th scope="row">Chosen pool</th><td>{{ pct(selectedPool.chosenPool.minimumReturn, 5) }}</td><td>{{ drawdown(selectedPool.chosenPool.maximumDrawdownBound, 4) }}</td><td>{{ pct(selectedPool.chosenPool.minimumWithoutTwoBest, 5) }}</td></tr>
          </tbody>
        </table></div>
        <p>The chosen pool's minimum after <em>any</em> token pair is {{ pct(selectedPool.minimumAfterAnyPair, 5) }}.
          Half allocation fails that check. Each number is a separate extremum across scenarios, not one account's return and drawdown.</p>
        <p class="small-note">The sizing study above also includes a quote-time-only capacity control. This matched pool comparison uses the two
          entry-time modes on both sides. Dropping the extra control must not be credited as an improvement from pool selection.</p>
        <figure><a :href="`${assets}/pool-comparison.svg`"><img :src="`${assets}/pool-comparison.svg`" alt="All pool-share thresholds have the same headline results; matched all-pool controls nearly coincide with chosen-pool results" loading="lazy" width="1440" height="960"></a>
          <figcaption>Lookbacks of 15, 30, and 60 seconds; minimum pool shares of 0%, 75%, 90%, and 95%. Curves overlap because the headline results coincide.</figcaption></figure>
        <div class="finding">
          <h3>The sale-capacity problem is still unresolved</h3>
          <p>{{ research.saleCapacity.chosenPoolCasesAboveCapacity }} distinct chosen-pool sale scenarios exceed the same volume-participation limit
            used to size entries, when that limit is measured again before sale.
            Another {{ research.saleCapacity.chosenPoolCasesWithHigherExitFee }} have higher exit-time fee estimates than the model reserved.</p>
          <p>At a $1,000 bankroll, the largest chosen-pool sale reaches roughly 2.38 times that proxy capacity.
            These are repeated scenarios, not {{ research.saleCapacity.chosenPoolCasesAboveCapacity }} independent trades.
            The diagnostic has not recalculated profits with partial fills, extra fees, or unsold inventory.
            A {{ pct(selectedPool.minimumAfterAnyPair, 5) }} margin cannot settle that question.</p>
        </div>
      </section>

      <section id="observations">
        <p class="section-number">06 / Stop fitting and watch</p>
        <h2>New observations have produced no trades</h2>
        <p>Two completed source-filter windows froze their rules before message capture. They contain
          {{ eligibleObserved }} eligible calls and zero qualifying entries. That is no new evidence of profitability or low drawdown.</p>
        <div class="table-scroll"><table>
          <caption>21 October 2026 · UTC · source-filter observation windows in this snapshot</caption>
          <thead><tr><th scope="col">Capture</th><th scope="col">Signals</th><th scope="col">Eligible calls</th><th scope="col">Paper accounts</th><th scope="col">Trades per account</th></tr></thead>
          <tbody><tr v-for="row in research.observationWindows" :key="row.startedAt"><th scope="row">{{ time(row.startedAt) }} to {{ time(row.endedAt) }}</th><td>{{ row.signals }}</td><td>{{ row.eligibleCalls }}</td><td>{{ row.paperAccounts }}</td><td>{{ row.maximumTradesInAnyAccount }}</td></tr></tbody>
        </table></div>
        <p>The capture preserves the message version actually received, including later edits. Local receipt time determines availability.
          Market history is retrieved after each window matures, so this does not measure live data latency or successful on-chain fills.
          Gaps between captures remain unobserved.</p>
        <h3>What would change the conclusion</h3>
        <p>The candidate needs complete sale accounting, including partial fills and residual inventory, and enough new qualifying trades
          under rules chosen in advance. Until then, the research supports a narrow conclusion: following these group calls mechanically
          lost money in the baseline grid, and the selected exceptions have not demonstrated a dependable edge.</p>
      </section>

      <section id="data">
        <p class="section-number">07 / Data and method</p>
        <h2>Saved once. Replayed many times.</h2>
        <p>Messages, market responses, features, model answers, and price paths are cached separately from the simulator.
          Each study saves its settings, source hashes, and results. Independent accounting checks reconstruct exits, cash,
          inventory, fees, and admission decisions; future-data perturbations check whether earlier decisions change.</p>
        <p>The exhaustive pair study computes {{ number(research.pairCache.computedAccounts) }} accounts and reuses
          {{ number(research.pairCache.identicalInputReuses) }} identical input/path combinations.
          Reuse includes every possible opportunity, not just the trades taken in the original ledger.
          This avoids duplicate calculations without treating them as fresh statistical evidence.</p>
        <ul class="downloads">
          <li><a :href="`${assets}/results.json`" download>Aggregate results JSON <span>tables, anonymous rankings, and source hashes ↗</span></a></li>
          <li><a :href="`${assets}/baseline-horizons.csv`" download>All 108 baseline accounts <span>CSV ↗</span></a></li>
          <li><a :href="`${assets}/manifest.json`" download>Snapshot manifest <span>SHA-256 hashes of the public data and figures ↗</span></a></li>
        </ul>
        <p class="small-note">Research snapshot: 21 October 2026, 15:41 UTC. The downloads contain aggregate results, not the private message archive.
          Prices and indexed transactions came from <a href="https://docs.mobula.io/rest-api-reference/introduction">Mobula</a>.
          Recorded trades and past volume do not measure executable pool depth. Results are scenario estimates on a short, repeatedly examined history.</p>
      </section>
    </article>
  </main>
</template>

<style scoped>
.research-page { background: #0b0c0e; color: #d4d4d8; font-family: system-ui, sans-serif; }
.research-article { max-width: 1080px; margin: 0 auto; padding: 54px 28px 96px; }
.home-link { color: #a1a1aa; font-size: .85rem; text-decoration: none; }
.eyebrow, .section-number { color: #a1a1aa; font: .75rem/1.5 'Iosevka Web', monospace; letter-spacing: .1em; text-transform: uppercase; }
.eyebrow { margin: 48px 0 20px; }
h1, h2, h3, .headline-stats strong { color: #fafafa; font-family: 'Bricolage Grotesque', system-ui, sans-serif; }
h1 { font-size: clamp(3.4rem, 8vw, 6.5rem); font-weight: 700; line-height: .99; letter-spacing: -.055em; margin: 0 0 32px; }
h1 span { color: #ff885b; }
.standfirst { max-width: 820px; font-size: 1.23rem; line-height: 1.7; color: #e4e4e7; }
.scope { max-width: 790px; color: #a1a1aa; font-size: .93rem; }
p { max-width: 840px; line-height: 1.8; margin: 0 0 20px; }
.headline-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; border-top: 1px solid #343438; border-bottom: 1px solid #343438; padding: 27px 0; margin-top: 36px; }
.headline-stats strong { display: block; font-size: 2.3rem; font-weight: 600; letter-spacing: -.035em; }
.headline-stats span { display: block; color: #a1a1aa; font-size: .82rem; margin-top: 4px; }
.contents { display: flex; flex-wrap: wrap; gap: 12px 25px; padding: 24px 0; font-size: .85rem; border-bottom: 1px solid #343438; }
a { color: #ffb092; text-underline-offset: 4px; }
a:hover { color: #ffd6c5; text-decoration: underline; }
section { padding-top: 70px; scroll-margin-top: 25px; }
.section-number { margin-bottom: 12px; }
h2 { font-size: clamp(1.8rem, 4vw, 2.55rem); font-weight: 600; letter-spacing: -.025em; line-height: 1.15; margin: 0 0 25px; }
h3 { font-size: 1.4rem; font-weight: 600; letter-spacing: -.015em; line-height: 1.3; margin: 32px 0 14px; }
.baseline-explorer { padding: 25px; background: #141519; border: 1px solid #343438; margin: 28px 0 20px; }
.controls { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 26px; }
label { display: flex; flex-direction: column; gap: 7px; color: #b5b5c0; font-size: .8rem; }
select { color: #f4f4f5; background: #202126; border: 1px solid #52525b; border-radius: 4px; padding: 9px 34px 9px 11px; font: inherit; cursor: pointer; min-height: 40px; }
.inline-control { align-items: flex-start; margin: 25px 0; }
.inline-control select { min-width: 110px; }
.chart-heading { color: #f4f4f5; font-size: .9rem; margin-bottom: 20px; }
.chart-heading span { color: #a1a1aa; margin-left: 16px; font-size: .75rem; }
.baseline-bars { display: grid; gap: 12px; margin-bottom: 20px; }
.baseline-bar-row { display: grid; grid-template-columns: 35px minmax(50px, 1fr) 80px 90px; gap: 14px; align-items: center; font: .82rem/1.3 'Iosevka Web', monospace; }
.bar-track { height: 19px; background: #242529; }
.loss-bar { height: 100%; background: #ed9274; }
.loss-value { color: #ffb092; text-align: right; font-variant-numeric: tabular-nums; }
.trade-count { color: #a1a1aa; text-align: right; font-size: .75rem; }
.small-note, figcaption { color: #a1a1aa; font-size: .82rem; line-height: 1.7; }
.table-scroll { overflow-x: auto; margin: 28px 0; scrollbar-color: #52525b #141519; }
table { width: 100%; border-collapse: collapse; font-size: .88rem; font-variant-numeric: tabular-nums; }
caption { text-align: left; color: #a1a1aa; font-size: .78rem; line-height: 1.5; padding: 0 0 13px; }
th, td { padding: 13px 16px; border-bottom: 1px solid #303137; text-align: right; white-space: nowrap; }
th:first-child { text-align: left; padding-left: 0; white-space: normal; min-width: 140px; }
thead th { color: #a1a1aa; font-size: .75rem; font-weight: 500; border-top: 1px solid #343438; }
tbody th { color: #e4e4e7; font-weight: 500; }
td small { display: block; font-size: .7rem; color: #a1a1aa; margin-top: 3px; }
.negative { color: #ffb092; }
details { border-top: 1px solid #343438; border-bottom: 1px solid #343438; margin: 20px 0; padding: 17px 0; }
details + details { border-top: 0; margin-top: -20px; }
summary { color: #e4e4e7; cursor: pointer; font-size: .92rem; padding: 4px 0; }
details[open] summary { margin-bottom: 18px; }
details p { font-size: .9rem; }
figure { margin: 30px 0; }
figure img { width: 100%; height: auto; background: #fff; }
figcaption { margin-top: 12px; max-width: 840px; }
.finding { border-left: 3px solid #ff885b; padding: 2px 0 2px 25px; margin: 36px 0 0; }
.finding h3 { margin-top: 0; }
.finding p:last-child { margin-bottom: 0; }
.downloads { list-style: none; padding: 0; margin: 30px 0; border-top: 1px solid #343438; }
.downloads li { border-bottom: 1px solid #343438; }
.downloads a { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px 20px; padding: 17px 0; font-size: .9rem; }
.downloads span { color: #a1a1aa; font-size: .8rem; }
a:focus-visible, select:focus-visible, summary:focus-visible { outline: 2px solid #ff885b; outline-offset: 5px; }
@media (max-width: 600px) {
  .research-article { padding: 32px 20px 64px; }
  .eyebrow { margin-top: 36px; }
  .standfirst { font-size: 1.07rem; }
  .headline-stats { gap: 12px; }
  .headline-stats strong { font-size: 1.7rem; }
  .headline-stats span { font-size: .73rem; }
  section { padding-top: 50px; }
  .baseline-explorer { padding: 18px 14px; margin-left: -6px; margin-right: -6px; }
  .baseline-bar-row { grid-template-columns: 32px minmax(30px, 1fr) 64px; gap: 10px; }
  .trade-count { display: none; }
  .chart-heading span { display: block; margin: 4px 0 0; }
  th, td { padding: 12px 10px; }
  .finding { padding-left: 18px; }
}
@media print {
  .research-page { background: white; color: #222; }
  h1, h2, h3, .headline-stats strong, th, td, p, a, summary { color: #222; }
  .contents, .home-link { display: none; }
  .research-article { padding: 0; }
  section { padding-top: 28px; }
  .table-scroll { overflow: visible; }
  .baseline-explorer { background: white; }
}
</style>
