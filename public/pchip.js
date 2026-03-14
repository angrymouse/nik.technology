function validatePoints(points) {
  if (!Array.isArray(points)) {
    throw new TypeError("PCHIP points must be an array");
  }

  for (let i = 0; i < points.length; i++) {
    const point = points[i];

    if (!point || !Number.isFinite(point.x) || !Number.isFinite(point.y)) {
      throw new TypeError(`Invalid PCHIP point at index ${i}`);
    }

    if (i > 0 && !(point.x > points[i - 1].x)) {
      throw new RangeError("PCHIP point x values must be strictly increasing");
    }
  }

  return points;
}

function resolveTangents(points, tangents) {
  if (tangents === undefined) {
    return computePchipTangents(points);
  }

  if (!Array.isArray(tangents) || tangents.length !== points.length) {
    throw new TypeError("PCHIP tangents must match the point count");
  }

  return tangents;
}

function findSegmentIndex(points, x) {
  let low = 0;
  let high = points.length - 2;

  while (low <= high) {
    const mid = (low + high) >> 1;
    const left = points[mid].x;
    const right = points[mid + 1].x;

    if (x < left) {
      high = mid - 1;
      continue;
    }

    if (x >= right) {
      low = mid + 1;
      continue;
    }

    return mid;
  }

  return Math.max(0, Math.min(points.length - 2, low));
}

function integrateSegment(points, tangents, index, t = 1) {
  const p0 = points[index];
  const p1 = points[index + 1];
  const h = p1.x - p0.x;
  const t2 = t * t;
  const t3 = t2 * t;
  const t4 = t3 * t;

  const iH00 = t4 / 2 - t3 + t;
  const iH10 = t4 / 4 - (2 * t3) / 3 + t2 / 2;
  const iH01 = -t4 / 2 + t3;
  const iH11 = t4 / 4 - t3 / 3;

  return h * (
    p0.y * iH00 +
    h * tangents[index] * iH10 +
    p1.y * iH01 +
    h * tangents[index + 1] * iH11
  );
}

export function computePchipTangents(points) {
  validatePoints(points);

  const n = points.length;
  if (n === 0) return [];
  if (n === 1) return [0];

  const tangents = new Array(n);
  const h = new Array(n - 1);
  const delta = new Array(n - 1);

  for (let i = 0; i < n - 1; i++) {
    h[i] = points[i + 1].x - points[i].x;
    delta[i] = (points[i + 1].y - points[i].y) / h[i];
  }

  if (n === 2) {
    tangents[0] = delta[0];
    tangents[1] = delta[0];
    return tangents;
  }

  tangents[0] = ((2 * h[0] + h[1]) * delta[0] - h[0] * delta[1]) / (h[0] + h[1]);
  if (tangents[0] * delta[0] < 0) {
    tangents[0] = 0;
  } else if (Math.abs(tangents[0]) > 3 * Math.abs(delta[0])) {
    tangents[0] = 3 * delta[0];
  }

  const last = n - 2;
  tangents[n - 1] = (
    (2 * h[last] + h[last - 1]) * delta[last] -
    h[last] * delta[last - 1]
  ) / (h[last] + h[last - 1]);
  if (tangents[n - 1] * delta[last] < 0) {
    tangents[n - 1] = 0;
  } else if (Math.abs(tangents[n - 1]) > 3 * Math.abs(delta[last])) {
    tangents[n - 1] = 3 * delta[last];
  }

  for (let i = 1; i < n - 1; i++) {
    if (delta[i - 1] * delta[i] <= 0) {
      tangents[i] = 0;
      continue;
    }

    const w1 = 2 * h[i] + h[i - 1];
    const w2 = h[i] + 2 * h[i - 1];
    tangents[i] = (w1 + w2) / (w1 / delta[i - 1] + w2 / delta[i]);
  }

  return tangents;
}

export function evaluatePchip(points, x, tangents) {
  validatePoints(points);

  if (points.length === 0) return 0;
  if (points.length === 1) return points[0].y;
  if (x <= points[0].x) return points[0].y;
  if (x >= points[points.length - 1].x) return points[points.length - 1].y;

  const slopes = resolveTangents(points, tangents);
  const index = findSegmentIndex(points, x);
  const p0 = points[index];
  const p1 = points[index + 1];
  const h = p1.x - p0.x;
  const t = (x - p0.x) / h;
  const t2 = t * t;
  const t3 = t2 * t;

  return (
    (2 * t3 - 3 * t2 + 1) * p0.y +
    (t3 - 2 * t2 + t) * h * slopes[index] +
    (-2 * t3 + 3 * t2) * p1.y +
    (t3 - t2) * h * slopes[index + 1]
  );
}

export function integratePchip(points, x, tangents) {
  validatePoints(points);

  if (points.length < 2) return 0;

  const startX = points[0].x;
  const endX = points[points.length - 1].x;

  if (x <= startX) return 0;

  const limitX = Math.min(x, endX);
  const slopes = resolveTangents(points, tangents);

  let sum = 0;
  for (let i = 0; i < points.length - 1; i++) {
    const left = points[i].x;
    const right = points[i + 1].x;

    if (right <= limitX) {
      sum += integrateSegment(points, slopes, i, 1);
      continue;
    }

    if (left < limitX) {
      sum += integrateSegment(points, slopes, i, (limitX - left) / (right - left));
    }

    break;
  }

  return sum;
}

export function integratePchipNormalized(points, p, tangents) {
  validatePoints(points);

  if (points.length < 2) return 0;
  if (!Number.isFinite(p)) {
    throw new TypeError("PCHIP normalized integral limit must be finite");
  }

  const startX = points[0].x;
  const endX = points[points.length - 1].x;
  return integratePchip(points, startX + p * (endX - startX), tangents);
}

export function createPchip(points) {
  const curvePoints = validatePoints(points).map((point) => ({ x: point.x, y: point.y }));
  const tangents = computePchipTangents(curvePoints);

  return {
    points: curvePoints,
    tangents,
    at(x) {
      return evaluatePchip(curvePoints, x, tangents);
    },
    integralAt(x) {
      return integratePchip(curvePoints, x, tangents);
    },
    integralToP(p) {
      return integratePchipNormalized(curvePoints, p, tangents);
    },
    totalIntegral() {
      return integratePchip(curvePoints, curvePoints[curvePoints.length - 1]?.x ?? 0, tangents);
    },
  };
}

export default {
  createPchip,
  computePchipTangents,
  evaluatePchip,
  integratePchip,
  integratePchipNormalized,
};
