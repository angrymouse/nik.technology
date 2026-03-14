import * as defaultCore from "./v3.js";

const EPSILON = 1e-8;
const SIDES = ["yes", "no"];

function assertValidSide(side) {
  if (side !== "yes" && side !== "no") {
    throw new Error(`Invalid side: ${side}`);
  }
}

function assertValidOutcome(outcome) {
  if (outcome !== "yes" && outcome !== "no") {
    throw new Error(`Invalid outcome: ${outcome}`);
  }
}

function assertFiniteNonNegative(name, value) {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${name} must be a finite non-negative number`);
  }
}

function assertValidBasis(basis) {
  if (!Number.isFinite(basis) || basis < 0 || basis > 1) {
    throw new Error("basis must be a finite number between 0 and 1");
  }
}

function getSideOrders(core, side) {
  assertValidSide(side);
  return side === "yes" ? core.yesOrders : core.noOrders;
}

function getTieBreak(side, left, right) {
  if (side === "yes") return left.priceBps - right.priceBps;
  return right.priceBps - left.priceBps;
}

function getOrdersByDistance(core, side) {
  return getSideOrders(core, side)
    .slice()
    .sort(
      (left, right) =>
        Math.abs(core.currentPriceBps - left.priceBps) - Math.abs(core.currentPriceBps - right.priceBps) ||
        getTieBreak(side, left, right),
    );
}

function actualTradePrice(side, priceBps) {
  assertValidSide(side);
  return side === "yes" ? priceBps / 100000 : (100000 - priceBps) / 100000;
}

function cloneAssignments(assignments) {
  return assignments.map((assignment) => ({ ...assignment }));
}

function sumAssignments(assignments) {
  return assignments.reduce((total, assignment) => total + assignment.amount, 0);
}

function cloneLots(lots) {
  return lots.map((lot) => ({ amount: lot.amount, basis: lot.basis }));
}

function sumLotAmounts(lots) {
  return lots.reduce((total, lot) => total + lot.amount, 0);
}

function sumLotCost(lots) {
  return lots.reduce((total, lot) => total + lot.amount * lot.basis, 0);
}

function makeAccount(cash) {
  return { cash, yes: 0, no: 0 };
}

function makeLotBook() {
  return { yes: [], no: [] };
}

function makeQuoteInventory() {
  return { yes: new Map(), no: new Map() };
}

function makeZeroBySide() {
  return { yes: 0, no: 0 };
}

function getOrderedPriceLevels(core, side) {
  const levels = [];
  const seen = new Set();

  for (const order of getOrdersByDistance(core, side)) {
    if (seen.has(order.priceBps)) continue;
    const totalAmount = getSideOrders(core, side)
      .filter((entry) => entry.priceBps === order.priceBps)
      .reduce((total, entry) => total + entry.amount, 0);

    levels.push({ priceBps: order.priceBps, amount: totalAmount });
    seen.add(order.priceBps);
  }

  return levels;
}

class PredictionMarketEngine {
  constructor({ core = defaultCore, botCash = 5000, userCash = 5000 } = {}) {
    assertFiniteNonNegative("botCash", botCash);
    assertFiniteNonNegative("userCash", userCash);
    this.core = core;
    this.initialBotCash = botCash;
    this.initialUserCash = userCash;
    this.resetEngineState();

    this.refreshInventoryQuotes();
  }

  resetEngineState() {
    this.bot = makeAccount(this.initialBotCash);
    this.user = makeAccount(this.initialUserCash);
    this.botLots = makeLotBook();
    this.quoteInventory = makeQuoteInventory();
    this.unassignedInventory = makeZeroBySide();
  }

  reset(priceBps) {
    if (priceBps !== undefined) assertFiniteNonNegative("priceBps", priceBps);
    this.core.reset(priceBps);
    this.resetEngineState();
    return this.refreshInventoryQuotes();
  }

  setParams(params) {
    this.core.setParams(params);
    return this.refreshInventoryQuotes();
  }

  syncBotInventory() {
    this.cleanupLots();
    this.bot.yes = this.getLotAmount("yes");
    this.bot.no = this.getLotAmount("no");
  }

  cleanupLots() {
    for (const side of SIDES) {
      this.botLots[side] = this.botLots[side].filter((lot) => lot.amount > EPSILON);
    }
  }

  getLotAmount(side) {
    assertValidSide(side);
    return sumLotAmounts(this.botLots[side]);
  }

  getInventoryCostBasis(side) {
    if (side !== undefined) assertValidSide(side);
    if (side) return sumLotCost(this.botLots[side]);
    return {
      yes: sumLotCost(this.botLots.yes),
      no: sumLotCost(this.botLots.no),
    };
  }

  getInventorySide() {
    this.syncBotInventory();
    if (this.bot.yes > EPSILON && this.bot.no <= EPSILON) return "yes";
    if (this.bot.no > EPSILON && this.bot.yes <= EPSILON) return "no";
    return null;
  }

  addInventoryLot(side, amount, basis) {
    assertValidSide(side);
    assertFiniteNonNegative("amount", amount);
    assertValidBasis(basis);
    if (amount <= EPSILON) return;
    const cost = amount * basis;
    if (this.bot.cash + EPSILON < cost) {
      throw new Error("bot cash is insufficient to fund inventory");
    }

    this.bot.cash -= cost;
    this.recordInventoryLot(side, amount, basis);
  }

  recordInventoryLot(side, amount, basis) {
    assertValidSide(side);
    assertFiniteNonNegative("amount", amount);
    assertValidBasis(basis);
    if (amount <= EPSILON) return;

    this.botLots[side].push({ amount, basis });
    this.syncBotInventory();
  }

  mergeUser(maxAmount = Infinity) {
    if (maxAmount !== Infinity) assertFiniteNonNegative("maxAmount", maxAmount);
    const merged = Math.min(this.user.yes, this.user.no, maxAmount);
    if (merged <= EPSILON) return 0;

    this.user.yes -= merged;
    this.user.no -= merged;
    this.user.cash += merged;

    return merged;
  }

  mergeBotInventory(maxAmount = Infinity) {
    if (maxAmount !== Infinity) assertFiniteNonNegative("maxAmount", maxAmount);
    this.cleanupLots();
    this.botLots.yes.sort((left, right) => right.basis - left.basis);
    this.botLots.no.sort((left, right) => right.basis - left.basis);

    let merged = 0;
    let yesIndex = 0;
    let noIndex = 0;

    while (yesIndex < this.botLots.yes.length && noIndex < this.botLots.no.length && merged < maxAmount - EPSILON) {
      const yesLot = this.botLots.yes[yesIndex];
      const noLot = this.botLots.no[noIndex];
      const size = Math.min(yesLot.amount, noLot.amount, maxAmount - merged);

      yesLot.amount -= size;
      noLot.amount -= size;
      this.bot.cash += size;
      merged += size;

      if (yesLot.amount <= EPSILON) yesIndex += 1;
      if (noLot.amount <= EPSILON) noIndex += 1;
    }

    this.syncBotInventory();
    return merged;
  }

  refreshInventoryQuotes() {
    const merged = this.mergeBotInventory();
    this.quoteInventory = makeQuoteInventory();
    this.unassignedInventory = makeZeroBySide();

    for (const side of SIDES) {
      this.unassignedInventory[side] = this.assignInventoryToSide(side);
    }

    return {
      merged,
      quoteInventory: this.getQuoteInventory(),
      unassignedInventory: { ...this.unassignedInventory },
    };
  }

  assignInventoryToSide(side) {
    assertValidSide(side);
    const orders = getOrdersByDistance(this.core, side);
    const lots = this.botLots[side]
      .slice()
      .sort((left, right) => left.basis - right.basis || right.amount - left.amount)
      .map((lot) => ({ lot, remaining: lot.amount }));

    const assignmentsByPrice = this.quoteInventory[side];
    let lotIndex = 0;

    for (const order of orders) {
      const quotePrice = actualTradePrice(side, order.priceBps);
      let remainingOrder = order.amount;
      const assignments = [];

      while (remainingOrder > EPSILON && lotIndex < lots.length) {
        const current = lots[lotIndex];
        if (current.remaining <= EPSILON) {
          lotIndex += 1;
          continue;
        }

        if (current.lot.basis > quotePrice + EPSILON) break;

        const covered = Math.min(remainingOrder, current.remaining);
        assignments.push({ lot: current.lot, amount: covered });
        current.remaining -= covered;
        remainingOrder -= covered;

        if (current.remaining <= EPSILON) lotIndex += 1;
      }

      if (assignments.length > 0) assignmentsByPrice.set(order.priceBps, assignments);
    }

    return lots.reduce((total, lot) => total + lot.remaining, 0);
  }

  getAssignedAmount(side) {
    assertValidSide(side);
    let total = 0;
    for (const assignments of this.quoteInventory[side].values()) {
      total += sumAssignments(assignments);
    }
    return total;
  }

  getFrontAssignedAmount(side) {
    assertValidSide(side);

    let reachable = 0;
    for (const level of getOrderedPriceLevels(this.core, side)) {
      const assigned = sumAssignments(this.quoteInventory[side].get(level.priceBps) ?? []);
      if (assigned <= EPSILON) break;

      reachable += Math.min(level.amount, assigned);
      if (assigned + EPSILON < level.amount) break;
    }

    return reachable;
  }

  getApprovedAmount(side, requestedAmount) {
    assertValidSide(side);
    assertFiniteNonNegative("requestedAmount", requestedAmount);
    const inventorySide = this.getInventorySide();
    const maxByInventory = inventorySide === side ? this.getFrontAssignedAmount(side) : requestedAmount;

    let remainingRequest = Math.min(requestedAmount, maxByInventory);
    let approvedAmount = 0;
    let remainingUserCash = this.user.cash;
    let remainingBotCash = inventorySide === side ? Infinity : this.bot.cash;

    for (const order of getOrdersByDistance(this.core, side)) {
      if (remainingRequest <= EPSILON) break;
      if (order.amount <= EPSILON) continue;

      const orderBudget = Math.min(order.amount, remainingRequest);
      const tradePrice = actualTradePrice(side, order.priceBps);
      const mintCost = inventorySide === side ? 0 : 1 - tradePrice;
      const byUserCash = tradePrice <= EPSILON ? orderBudget : remainingUserCash / tradePrice;
      const byBotCash = mintCost <= EPSILON ? orderBudget : remainingBotCash / mintCost;
      const fillable = Math.min(orderBudget, byUserCash, byBotCash);

      if (fillable <= EPSILON) break;

      approvedAmount += fillable;
      remainingRequest -= fillable;
      remainingUserCash -= fillable * tradePrice;
      if (inventorySide !== side) remainingBotCash -= fillable * mintCost;

      if (fillable + EPSILON < orderBudget) break;
    }

    return approvedAmount;
  }

  getExpectedFillDetails(side, requestedAmount) {
    assertValidSide(side);
    assertFiniteNonNegative("requestedAmount", requestedAmount);

    const expected = [];
    let remainingRequest = requestedAmount;

    for (const order of getOrdersByDistance(this.core, side)) {
      if (remainingRequest <= EPSILON) break;
      if (order.amount <= EPSILON) continue;

      const fillable = Math.min(order.amount, remainingRequest);
      if (fillable <= EPSILON) continue;

      expected.push({ priceBps: order.priceBps, amount: fillable });
      remainingRequest -= fillable;
    }

    return expected;
  }

  assertCoreFillMatches(expectedFillDetails, result) {
    const actualFillDetails = result.fillDetails ?? [];
    const expectedFilled = expectedFillDetails.reduce((total, fill) => total + fill.amount, 0);
    const actualFilled = actualFillDetails.reduce((total, fill) => total + fill.amount, 0);

    if (Math.abs(result.filled - expectedFilled) > EPSILON || Math.abs(actualFilled - expectedFilled) > EPSILON) {
      throw new Error("core fill amount diverged from expected front-of-book execution");
    }

    if (actualFillDetails.length !== expectedFillDetails.length) {
      throw new Error("core fill path diverged from expected front-of-book execution");
    }

    for (let index = 0; index < expectedFillDetails.length; index += 1) {
      const expected = expectedFillDetails[index];
      const actual = actualFillDetails[index];

      if (!actual || actual.priceBps !== expected.priceBps || Math.abs(actual.amount - expected.amount) > EPSILON) {
        throw new Error("core fill path diverged from expected front-of-book execution");
      }
    }
  }

  consumeAssignedInventory(side, priceBps, amount) {
    assertValidSide(side);
    assertFiniteNonNegative("amount", amount);
    const assignments = this.quoteInventory[side].get(priceBps) ?? [];
    let remaining = amount;
    let consumed = 0;

    while (remaining > EPSILON && assignments.length > 0) {
      const assignment = assignments[0];
      const used = Math.min(remaining, assignment.amount, assignment.lot.amount);

      assignment.amount -= used;
      assignment.lot.amount -= used;
      remaining -= used;
      consumed += used;

      if (assignment.amount <= EPSILON || assignment.lot.amount <= EPSILON) assignments.shift();
    }

    if (assignments.length === 0) this.quoteInventory[side].delete(priceBps);
    else this.quoteInventory[side].set(priceBps, assignments);

    this.syncBotInventory();
    return consumed;
  }

  trade(side, amount) {
    assertValidSide(side);
    assertFiniteNonNegative("amount", amount);
    const preTrade = this.refreshInventoryQuotes();
    const approvedAmount = this.getApprovedAmount(side, amount);
    if (approvedAmount <= EPSILON) {
      return {
        filled: 0,
        fillDetails: [],
        partial: amount > EPSILON,
        spent: 0,
        minted: 0,
        inventoryUsed: 0,
        averagePrice: 0,
        approvedAmount: 0,
        rejectedAmount: amount,
        preTrade,
        postTrade: preTrade,
      };
    }

    const expectedFillDetails = this.getExpectedFillDetails(side, approvedAmount);
    const result = this.core.fill(approvedAmount, side);
    this.assertCoreFillMatches(expectedFillDetails, result);
    const retainedSide = side === "yes" ? "no" : "yes";
    let spent = 0;
    let minted = 0;
    let inventoryUsed = 0;

    for (const fill of result.fillDetails) {
      const fillPrice = actualTradePrice(side, fill.priceBps);
      const fromInventory = this.consumeAssignedInventory(side, fill.priceBps, fill.amount);
      const toMint = fill.amount - fromInventory;

      inventoryUsed += fromInventory;
      if (toMint > EPSILON) {
        this.bot.cash -= toMint;
        this.recordInventoryLot(retainedSide, toMint, 1 - fillPrice);
        minted += toMint;
      }

      this.user[side] += fill.amount;

      const tradeValue = fillPrice * fill.amount;
      this.user.cash -= tradeValue;
      this.bot.cash += tradeValue;
      spent += tradeValue;
    }

    const postTrade = this.refreshInventoryQuotes();

    return {
      ...result,
      partial: result.partial || approvedAmount < amount - EPSILON,
      spent,
      minted,
      inventoryUsed,
      averagePrice: result.filled > EPSILON ? spent / result.filled : 0,
      approvedAmount,
      rejectedAmount: Math.max(0, amount - approvedAmount),
      preTrade,
      postTrade,
    };
  }

  getQuoteInventory(side) {
    if (side) return this.getQuoteInventoryForSide(side);

    return {
      yes: this.getQuoteInventoryForSide("yes"),
      no: this.getQuoteInventoryForSide("no"),
    };
  }

  getQuoteInventoryForSide(side) {
    assertValidSide(side);
    return cloneAssignments(
      getOrdersByDistance(this.core, side)
        .map((order) => ({
          priceBps: order.priceBps,
          amount: sumAssignments(this.quoteInventory[side].get(order.priceBps) ?? []),
        }))
        .filter((assignment) => assignment.amount > EPSILON),
    );
  }

  getState() {
    return {
      bot: { ...this.bot },
      user: { ...this.user },
      currentPriceBps: this.core.currentPriceBps,
      coreProfit: this.core.profit,
      quoteInventory: this.getQuoteInventory(),
      unassignedInventory: { ...this.unassignedInventory },
      inventoryCostBasis: this.getInventoryCostBasis(),
      botLots: {
        yes: cloneLots(this.botLots.yes),
        no: cloneLots(this.botLots.no),
      },
    };
  }

  getSettlementValue(outcome) {
    assertValidOutcome(outcome);
    return {
      bot: this.bot.cash + (outcome === "yes" ? this.bot.yes : this.bot.no),
      user: this.user.cash + (outcome === "yes" ? this.user.yes : this.user.no),
    };
  }

  getSettlementPnL(outcome) {
    const settlement = this.getSettlementValue(outcome);
    return {
      bot: settlement.bot - this.initialBotCash,
      user: settlement.user - this.initialUserCash,
    };
  }
}

export { EPSILON, PredictionMarketEngine, actualTradePrice, getOrdersByDistance };
