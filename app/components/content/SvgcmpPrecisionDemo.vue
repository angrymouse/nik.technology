<template>
  <figure class="my-8">
    <div class="glass p-5 md:p-6">
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div class="text-[11px] uppercase tracking-[0.24em] text-zinc-500">Interactive</div>
          <h3 class="mt-2 text-lg font-semibold text-white">Rounding path coordinates</h3>
          <p class="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
            Move the precision slider and compare the raw path text with a rounded fixed-point version. The preview
            overlays the original path and the rounded one.
          </p>
        </div>

        <label class="flex items-center gap-3 text-sm text-zinc-300">
          <span class="text-zinc-400">Decimal places</span>
          <input v-model="decimals" type="range" min="0" max="3" class="w-32 accent-[#FF885B]" />
          <span class="w-4 text-right tabular-nums">{{ decimals }}</span>
        </label>
      </div>

      <div class="mt-6 grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
        <section class="rounded-2xl border border-white/8 bg-black/30 p-4">
          <div class="flex items-center justify-between text-xs uppercase tracking-[0.22em] text-zinc-500">
            <span>Preview</span>
            <span>scale = {{ scale }}</span>
          </div>

          <svg viewBox="0 0 104 42" class="mt-3 w-full rounded-xl bg-white/[0.03] p-3">
            <path
              :d="rawPath"
              fill="none"
              stroke="rgba(56,189,248,0.55)"
              stroke-width="1.5"
              stroke-dasharray="2.5 2.5"
            />
            <path
              :d="roundedPath"
              fill="none"
              stroke="#FF885B"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>

          <div class="mt-3 flex flex-wrap gap-4 text-sm text-zinc-400">
            <div class="flex items-center gap-2">
              <span class="h-2.5 w-2.5 rounded-full bg-sky-400/80" />
              <span>raw editor values</span>
            </div>
            <div class="flex items-center gap-2">
              <span class="h-2.5 w-2.5 rounded-full bg-[#FF885B]" />
              <span>rounded packed values</span>
            </div>
          </div>
        </section>

        <section class="rounded-2xl border border-white/8 bg-black/30 p-4">
          <div class="text-xs uppercase tracking-[0.22em] text-zinc-500">Coordinate payload</div>

          <div class="mt-3 grid grid-cols-2 gap-3 text-sm">
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Path text bytes</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ rawPath.length }}</dd>
            </div>
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Fixed-point bytes</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ packedCoordinateBytes }}</dd>
            </div>
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Largest coordinate error</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ maxDelta }}</dd>
            </div>
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Stored integers</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ integerValues.join(', ') }}</dd>
            </div>
          </div>

          <div class="mt-4 space-y-3 text-sm text-zinc-300">
            <div>
              <div class="mb-1 text-zinc-500">Raw path</div>
              <code class="block overflow-x-auto whitespace-nowrap rounded-xl bg-black/40 px-3 py-2 text-xs text-zinc-300">{{ rawPath }}</code>
            </div>
            <div>
              <div class="mb-1 text-zinc-500">Rounded path</div>
              <code class="block overflow-x-auto whitespace-nowrap rounded-xl bg-black/40 px-3 py-2 text-xs text-zinc-300">{{ roundedPath }}</code>
            </div>
          </div>
        </section>
      </div>
    </div>
  </figure>
</template>

<script setup>
import { computed, ref } from 'vue'

const decimals = ref(2)

const rawPoints = [
  { x: 6.1234, y: 18.5678 },
  { x: 18.9123, y: 4.4812 },
  { x: 33.7788, y: 7.4021 },
  { x: 48.5543, y: 18.6621 },
  { x: 63.3388, y: 31.1022 },
  { x: 84.4449, y: 15.1148 },
]

function roundValue(value) {
  const factor = 10 ** decimals.value
  return Math.round(value * factor) / factor
}

function pathFromPoints(points) {
  return points.map((point, index) => `${index === 0 ? 'M' : 'L'}${point.x} ${point.y}`).join(' ')
}

const roundedPoints = computed(() => rawPoints.map((point) => ({ x: roundValue(point.x), y: roundValue(point.y) })))
const rawPath = computed(() => pathFromPoints(rawPoints))
const roundedPath = computed(() => pathFromPoints(roundedPoints.value))
const scale = computed(() => 10 ** decimals.value)
const packedCoordinateBytes = computed(() => roundedPoints.value.length * 4 + 1)

const integerValues = computed(() =>
  roundedPoints.value.flatMap((point) => [Math.round(point.x * scale.value), Math.round(point.y * scale.value)])
)

const maxDelta = computed(() => {
  let delta = 0
  for (let index = 0; index < rawPoints.length; index += 1) {
    delta = Math.max(delta, Math.abs(rawPoints[index].x - roundedPoints.value[index].x))
    delta = Math.max(delta, Math.abs(rawPoints[index].y - roundedPoints.value[index].y))
  }
  return delta.toFixed(3)
})
</script>
