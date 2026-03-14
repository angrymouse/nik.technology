import { createPchip } from "./pchip.js";

let capital = 1000;
let amountEpsilon = 1e-12;
let points = [
  { x: 0, y: 0.7557 },
  { x: 7000, y: 1.4806 },
  { x: 14000, y: 2.6215 },
  { x: 21000, y: 4.1945 },
  { x: 28000, y: 6.0653 },
  { x: 35000, y: 7.926 },
  { x: 42000, y: 9.3602 },
  { x: 50000, y: 10.0 },
  { x: 58000, y: 9.3602 },
  { x: 65000, y: 7.926 },
  { x: 72000, y: 6.0653 },
  { x: 79000, y: 4.1945 },
  { x: 86000, y: 2.6215 },
  { x: 93000, y: 1.4806 },
  { x: 100000, y: 0.7557 },
];

let normalDistro = createPchip(points);
let spacing = 200;
let maxPriceBps = 100000;
let currentPriceBps = 40000;
let spreadBps = 2000;
let minSpreadBps = 1000;
let orderDepthBps = 5000;

let fullBook = [];
let totalIntegral = normalDistro.totalIntegral();
for (let i = spacing; i < maxPriceBps; i += spacing) {
  let segment = normalDistro.integralAt(i) - normalDistro.integralAt(i - spacing);
  fullBook.push({
    amount: (segment / totalIntegral) * capital,
    priceBps: i,
  });
}

let yesOrders = [];
let noOrders = [];
let hiddenYesOrders = new Map();
let hiddenNoOrders = new Map();
let orderMap = new Map();
let currentBookIdGenerator = 0;
let profit = 0;

function getSideOrders(type) {
  return type === "yes" ? yesOrders : noOrders;
}

function getHiddenOrders(type) {
  return type === "yes" ? hiddenYesOrders : hiddenNoOrders;
}

function sortOrders() {
  yesOrders.sort((a, b) => a.priceBps - b.priceBps);
  noOrders.sort((a, b) => a.priceBps - b.priceBps);
}

function sumOrders(orders) {
  return orders.reduce((total, order) => total + order.amount, 0);
}

function sumHiddenOrders(type) {
  let total = 0;
  for (let amount of getHiddenOrders(type).values()) {
    total += amount;
  }
  return total;
}

function sumSideLiquidity(type) {
  return sumOrders(getSideOrders(type)) + sumHiddenOrders(type);
}

function pruneEmptyOrders() {
  const emptyOrderIds = [];

  for (const order of yesOrders) {
    if (order.amount <= amountEpsilon) emptyOrderIds.push(order.oid);
  }

  for (const order of noOrders) {
    if (order.amount <= amountEpsilon) emptyOrderIds.push(order.oid);
  }

  for (const oid of emptyOrderIds) {
    removeOrder(oid);
  }
}

function getBookIndex(priceBps) {
  return Math.round(priceBps / spacing) - 1;
}

function getReferenceOrder(priceBps) {
  return fullBook[getBookIndex(priceBps)];
}

function getVisibleReferenceOrders(type) {
  let visible = [];

  for (let base of fullBook) {
    if (Math.abs(currentPriceBps - base.priceBps) >= orderDepthBps) continue;
    if (Math.abs(currentPriceBps - base.priceBps) <= spreadBps) continue;
    if ((base.priceBps > currentPriceBps ? "yes" : "no") !== type) continue;
    visible.push(base);
  }

  return visible;
}

function getTargetVisibleOrderCount(type) {
  return getVisibleReferenceOrders(type).length;
}

function getHiddenReferenceOrders(type) {
  let hidden = [];

  for (let base of fullBook) {
    if ((base.priceBps > currentPriceBps ? "yes" : "no") !== type) continue;
    if (Math.abs(currentPriceBps - base.priceBps) <= spreadBps) continue;
    if (Math.abs(currentPriceBps - base.priceBps) < orderDepthBps) continue;
    hidden.push(base);
  }

  hidden.sort((left, right) => (type === "yes" ? left.priceBps - right.priceBps : right.priceBps - left.priceBps));
  return hidden;
}

function getFarthestReferencePrice(type) {
  if (type === "yes") return fullBook[fullBook.length - 1].priceBps;
  return fullBook[0].priceBps;
}

function setHiddenAmount(type, priceBps, amount) {
  if (amount <= amountEpsilon) return;
  getHiddenOrders(type).set(priceBps, amount);
}

function storeHiddenAmount(type, priceBps, amount) {
  if (amount <= amountEpsilon) return;
  let hiddenOrders = getHiddenOrders(type);
  hiddenOrders.set(priceBps, (hiddenOrders.get(priceBps) ?? 0) + amount);
}

function takeHiddenAmount(type, priceBps) {
  let hiddenOrders = getHiddenOrders(type);
  let hiddenAmount = hiddenOrders.get(priceBps) ?? 0;
  hiddenOrders.delete(priceBps);
  return hiddenAmount;
}

function clearHiddenOrders(type) {
  getHiddenOrders(type).clear();
}

function hideOrder(oid) {
  let order = orderMap.get(oid);
  if (!order) return;

  storeHiddenAmount(order.type, order.priceBps, order.amount);
  removeOrder(oid);
}

function restoreHiddenVisibleOrders(type) {
  for (let reference of getVisibleReferenceOrders(type)) {
    if (getSideOrders(type).some((order) => order.priceBps === reference.priceBps)) continue;

    let hiddenAmount = takeHiddenAmount(type, reference.priceBps);
    if (hiddenAmount > amountEpsilon) addOrder(type, reference.priceBps, hiddenAmount);
  }
}

function allocateHiddenLiquidity(type, totalLiquidity) {
  clearHiddenOrders(type);
  if (totalLiquidity <= amountEpsilon) return;

  let hiddenReferences = getHiddenReferenceOrders(type);
  let fallbackPriceBps = hiddenReferences.length > 0 ? hiddenReferences[hiddenReferences.length - 1].priceBps : getFarthestReferencePrice(type);

  for (let reference of hiddenReferences) {
    let hiddenAmount = Math.min(reference.amount, totalLiquidity);
    setHiddenAmount(type, reference.priceBps, hiddenAmount);
    totalLiquidity -= hiddenAmount;
    if (totalLiquidity <= amountEpsilon) break;
  }

  if (totalLiquidity > amountEpsilon) {
    storeHiddenAmount(type, fallbackPriceBps, totalLiquidity);
  }
}

function trimExcessVisibleOrders(type) {
  let visiblePrices = new Set(getVisibleReferenceOrders(type).map((reference) => reference.priceBps));

  for (let order of getSideOrders(type).slice()) {
    if (order.amount <= amountEpsilon) continue;
    if (visiblePrices.has(order.priceBps)) continue;
    hideOrder(order.oid);
  }

  let liveOrders = getOrdersByDistance(type).filter((order) => order.amount > amountEpsilon);
  let targetCount = getTargetVisibleOrderCount(type);

  while (liveOrders.length > targetCount) {
    let worstOrder = liveOrders.pop();
    if (!worstOrder) break;
    hideOrder(worstOrder.oid);
  }
}

function extendVisibleDepth(type) {
  let orders = getSideOrders(type);
  if (orders.length === 0) return;
  let targetCount = getTargetVisibleOrderCount(type);
  let liveCount = orders.filter((order) => order.amount > amountEpsilon).length;

  let nextPriceBps = type === "yes" ? orders[orders.length - 1].priceBps + spacing : orders[0].priceBps - spacing;
  while (liveCount < targetCount && Math.abs(nextPriceBps - currentPriceBps) < orderDepthBps) {
    let reference = getReferenceOrder(nextPriceBps);
    if (!reference) break;

    let hiddenAmount = takeHiddenAmount(type, nextPriceBps);
    addOrder(type, nextPriceBps, hiddenAmount > amountEpsilon ? hiddenAmount : reference.amount);
    liveCount += 1;
    nextPriceBps += type === "yes" ? spacing : -spacing;
  }
}

function redistributeTransportedLiquidity(type) {
  let visibleReferences = getVisibleReferenceOrders(type);
  let totalLiquidity = sumSideLiquidity(type);

  for (let order of getSideOrders(type).slice()) {
    removeOrder(order.oid);
  }
  clearHiddenOrders(type);

  if (totalLiquidity <= amountEpsilon) return;
  if (visibleReferences.length === 0) {
    allocateHiddenLiquidity(type, totalLiquidity);
    return;
  }

  let visibleCapacity = visibleReferences.reduce((total, reference) => total + reference.amount, 0);
  let visibleLiquidity = Math.min(totalLiquidity, visibleCapacity);
  let hiddenLiquidity = Math.max(0, totalLiquidity - visibleLiquidity);

  for (let reference of visibleReferences) {
    addOrder(type, reference.priceBps, (visibleLiquidity * reference.amount) / visibleCapacity);
  }
  allocateHiddenLiquidity(type, hiddenLiquidity);
}

function getOrdersByDistance(type) {
  return getSideOrders(type)
    .slice()
    .sort(
      (a, b) =>
        Math.abs(currentPriceBps - a.priceBps) - Math.abs(currentPriceBps - b.priceBps) || a.priceBps - b.priceBps,
    );
}

function initializeBook() {
  yesOrders = [];
  noOrders = [];
  hiddenYesOrders.clear();
  hiddenNoOrders.clear();
  orderMap.clear();

  for (let base of fullBook) {
    if (Math.abs(currentPriceBps - base.priceBps) >= orderDepthBps) continue;
    if (Math.abs(currentPriceBps - base.priceBps) <= spreadBps) continue;

    let order = {
      ...base,
      oid: ++currentBookIdGenerator,
      type: base.priceBps > currentPriceBps ? "yes" : "no",
    };
    orderMap.set(order.oid, order);

    if (order.type === "yes") yesOrders.push(order);
    else noOrders.push(order);
  }

  sortOrders();
}

function removeOrder(oid) {
  const order = orderMap.get(oid);
  if (!order) return;

  const orders = getSideOrders(order.type);
  const idx = orders.findIndex((entry) => entry.oid === oid);
  if (idx !== -1) orders.splice(idx, 1);

  orderMap.delete(oid);
}

function addOrder(type, priceBps, amount) {
  const existingOrder = getSideOrders(type).find((order) => order.priceBps === priceBps);
  if (existingOrder) {
    existingOrder.amount += amount;
    return existingOrder;
  }

  const order = {
    oid: ++currentBookIdGenerator,
    type,
    priceBps,
    amount,
  };

  orderMap.set(order.oid, order);
  const orders = getSideOrders(type);
  orders.push(order);
  orders.sort((a, b) => a.priceBps - b.priceBps);

  return order;
}

function ensureOppositeOrders(side) {
  const oppositeType = side === "yes" ? "no" : "yes";
  if (getSideOrders(oppositeType).length > 0) return true;

  let exactIndex = currentPriceBps / spacing;
  let seedIdx = side === "yes" ? Math.ceil(exactIndex) - 2 : Math.floor(exactIndex);
  let seedReference = fullBook[seedIdx];
  if (!seedReference) return false;

  addOrder(oppositeType, seedReference.priceBps, takeHiddenAmount(oppositeType, seedReference.priceBps));
  return true;
}

function propagateFill(side, filled, bestProviderLive) {
  const oppositeType = side === "yes" ? "no" : "yes";

  if (!ensureOppositeOrders(side)) return null;

  let oppositeOrders = getOrdersByDistance(oppositeType);
  let toPropBack = filled;

  for (let order of oppositeOrders) {
    if (toPropBack <= amountEpsilon) break;

    let shadowOrder = getReferenceOrder(order.priceBps);
    if (!shadowOrder) continue;

    let cap = Math.min(toPropBack, shadowOrder.amount);
    let room = cap - order.amount;
    if (room > amountEpsilon) {
      order.amount += room;
      toPropBack -= room;
    }
  }

  let origIdx = getBookIndex(oppositeOrders[0].priceBps);
  while (toPropBack > amountEpsilon) {
    origIdx += side === "yes" ? 1 : -1;

    let orderToAdd = fullBook[origIdx];
    if (!orderToAdd) break;

    if (bestProviderLive && Math.abs(orderToAdd.priceBps - bestProviderLive.priceBps) < minSpreadBps) {
      break;
    }

    let transported = Math.min(orderToAdd.amount, toPropBack);
    addOrder(oppositeType, orderToAdd.priceBps, transported);

    toPropBack -= transported;
  }

  return toPropBack;
}

function replenishProviderOrders(side) {
  let providerOrders = getOrdersByDistance(side);
  let worstProviderPriceBps =
    providerOrders.length > 0 ? providerOrders[providerOrders.length - 1].priceBps : undefined;

  for (let order of providerOrders) {
    if (order.amount > amountEpsilon) break;
    if (worstProviderPriceBps === undefined) break;

    let nextWorstPriceBps = worstProviderPriceBps + (side === "yes" ? spacing : -spacing);
    let nextWorstReferenceOrder = getReferenceOrder(nextWorstPriceBps);
    if (!nextWorstReferenceOrder) break;

    removeOrder(order.oid);
    let hiddenAmount = takeHiddenAmount(side, nextWorstReferenceOrder.priceBps);
    addOrder(side, nextWorstReferenceOrder.priceBps, hiddenAmount > amountEpsilon ? hiddenAmount : nextWorstReferenceOrder.amount);
    worstProviderPriceBps = nextWorstPriceBps;
  }
}

function updatePrice() {
  let bestYes = yesOrders[0];
  let bestNo = noOrders[noOrders.length - 1];
  if (bestYes && bestNo) {
    currentPriceBps = (bestYes.priceBps + bestNo.priceBps) / 2;
  }
}

function fill(amount, side) {
  let providerTotalBefore = sumSideLiquidity(side);
  let oppositeType = side === "yes" ? "no" : "yes";
  let oppositeTotalBefore = sumSideLiquidity(oppositeType);
  let providerOrders = getOrdersByDistance(side);
  let filled = 0;
  const fillDetails = [];

  for (let i = 0; filled < amount; i++) {
    if (providerOrders[i] === undefined) {
      break;
    }

    if (providerOrders[i].amount <= amountEpsilon) {
      providerOrders[i].amount = 0;
      continue;
    }

    let fillable = Math.min(providerOrders[i].amount, amount - filled);
    if (fillable <= amountEpsilon) {
      providerOrders[i].amount = 0;
      continue;
    }

    filled += fillable;
    providerOrders[i].amount -= fillable;
    if (providerOrders[i].amount <= amountEpsilon) {
      providerOrders[i].amount = 0;
    }
    fillDetails.push({ priceBps: providerOrders[i].priceBps, amount: fillable });
  }

  let bestProviderLive = providerOrders.find((order) => order.amount > amountEpsilon);
  let remaining = propagateFill(side, filled, bestProviderLive);
  if (remaining === null) return { filled: 0, fillDetails: [], partial: false };

  profit += remaining;
  replenishProviderOrders(side);
  pruneEmptyOrders();
  updatePrice();
  restoreHiddenVisibleOrders("yes");
  restoreHiddenVisibleOrders("no");
  trimExcessVisibleOrders("yes");
  trimExcessVisibleOrders("no");
  trimExcessVisibleOrders(side);
  extendVisibleDepth(side);
  redistributeTransportedLiquidity(oppositeType);

  let providerTotalAfter = sumSideLiquidity(side);
  let oppositeTotalAfter = sumSideLiquidity(oppositeType);

  return {
    filled,
    fillDetails,
    partial: filled + amountEpsilon < amount,
    providerTotalBefore,
    providerTotalAfter,
    oppositeTotalBefore,
    oppositeTotalAfter,
    transported: oppositeTotalAfter - oppositeTotalBefore,
  };
}

function reset(priceBps) {
  currentPriceBps = priceBps ?? 40000;
  profit = 0;
  initializeBook();
}

function setParams(params) {
  if (params.spreadBps > 0) spreadBps = params.spreadBps;
  if (params.minSpreadBps > 0) minSpreadBps = params.minSpreadBps;
  if (params.orderDepthBps > 0) orderDepthBps = params.orderDepthBps;
}

initializeBook();

export {
  capital,
  normalDistro,
  spacing,
  maxPriceBps,
  currentPriceBps,
  spreadBps,
  minSpreadBps,
  orderDepthBps,
  fullBook,
  currentBookIdGenerator,
  yesOrders,
  noOrders,
  profit,
  initializeBook,
  fill,
  reset,
  setParams,
};
