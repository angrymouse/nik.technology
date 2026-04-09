<template>
  <figure class="my-8">
    <div class="glass p-5 md:p-6">
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div class="text-[11px] uppercase tracking-[0.24em] text-zinc-500">Interactive</div>
          <h3 class="mt-2 text-lg font-semibold text-white">Interleaved stream vs sectioned storage</h3>
          <p class="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
            Repeat the same path, or shift it while keeping the command pattern the same. The left side keeps the
            stream interleaved. The right side stores structure and payload separately.
          </p>
        </div>

        <div class="flex flex-col gap-3 text-sm text-zinc-300 md:items-end">
          <label class="flex items-center gap-3">
            <span class="text-zinc-400">Paths in run</span>
            <input v-model="copies" type="range" min="1" max="6" class="w-32 accent-[#FF885B]" />
            <span class="w-4 text-right tabular-nums">{{ copies }}</span>
          </label>

          <div class="inline-flex rounded-lg border border-white/10 bg-white/[0.03] p-1">
            <button
              v-for="option in modeOptions"
              :key="option.value"
              type="button"
              class="rounded-md px-3 py-1.5 transition"
              :class="mode === option.value ? 'bg-[#FF885B] text-black' : 'text-zinc-400 hover:text-white'"
              @click="mode = option.value"
            >
              {{ option.label }}
            </button>
          </div>
        </div>
      </div>

      <div class="mt-6 grid gap-4 lg:grid-cols-2">
        <section class="rounded-2xl border border-white/8 bg-black/30 p-4">
          <div class="text-xs uppercase tracking-[0.22em] text-zinc-500">Source-like stream</div>
          <div class="mt-3 flex flex-wrap gap-1.5">
            <span
              v-for="(token, index) in interleavedTokens"
              :key="`${token.text}-${index}`"
              class="rounded-md px-2 py-1 text-xs font-medium"
              :class="token.kind === 'command' ? 'bg-[#FF885B]/15 text-[#FFb18f]' : 'bg-sky-500/15 text-sky-300'"
            >
              {{ token.text }}
            </span>
          </div>

          <dl class="mt-4 grid grid-cols-2 gap-3 text-sm">
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Command tokens stored</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ naiveCommandTokens }}</dd>
            </div>
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Numeric values stored</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ naiveNumericValues }}</dd>
            </div>
          </dl>
        </section>

        <section class="rounded-2xl border border-white/8 bg-black/30 p-4">
          <div class="text-xs uppercase tracking-[0.22em] text-zinc-500">Sectioned representation</div>

          <div class="mt-3 space-y-3 text-sm text-zinc-300">
            <div class="rounded-xl bg-white/[0.03] p-3">
              <div class="text-zinc-500">pattern[0]</div>
              <div class="mt-2 flex flex-wrap gap-1.5">
                <span
                  v-for="command in commandPattern"
                  :key="command"
                  class="rounded-md bg-[#FF885B]/15 px-2 py-1 text-xs font-medium text-[#FFb18f]"
                >
                  {{ command }}
                </span>
              </div>
            </div>

            <div class="rounded-xl bg-white/[0.03] p-3">
              <div class="text-zinc-500">Path payload rows</div>
              <div class="mt-2 space-y-2">
                <div
                  v-for="(row, index) in pooledRows"
                  :key="`row-${index}`"
                  class="flex flex-wrap items-center gap-1.5"
                >
                  <span class="mr-2 text-xs text-zinc-500">path[{{ index }}]</span>
                  <span
                    v-for="(value, valueIndex) in row"
                    :key="`${index}-${valueIndex}`"
                    class="rounded-md bg-sky-500/15 px-2 py-1 text-xs font-medium text-sky-300"
                  >
                    {{ value }}
                  </span>
                </div>
              </div>
            </div>

            <div class="rounded-xl bg-white/[0.03] p-3">
              <div class="text-zinc-500">Node stream references</div>
              <div class="mt-2 flex flex-wrap gap-1.5">
                <span
                  v-for="(refValue, index) in nodeRefs"
                  :key="`ref-${index}`"
                  class="rounded-md bg-emerald-500/15 px-2 py-1 text-xs font-medium text-emerald-300"
                >
                  {{ refValue }}
                </span>
              </div>
            </div>
          </div>

          <dl class="mt-4 grid grid-cols-2 gap-3 text-sm">
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Command tokens stored</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ pooledCommandTokens }}</dd>
            </div>
            <div class="rounded-xl bg-white/[0.03] p-3">
              <dt class="text-zinc-500">Numeric values stored</dt>
              <dd class="mt-1 text-lg font-semibold text-white">{{ pooledNumericValues }}</dd>
            </div>
          </dl>
        </section>
      </div>

      <p class="mt-4 text-sm text-zinc-500">
        Commands saved: <span class="text-white">{{ naiveCommandTokens - pooledCommandTokens }}</span>
        &middot; Numeric values saved:
        <span class="text-white">{{ naiveNumericValues - pooledNumericValues }}</span>
      </p>
    </div>
  </figure>
</template>

<script setup>
import { computed, ref } from 'vue'

const copies = ref(4)
const mode = ref('varied')

const modeOptions = [
  { label: 'Same pattern, shifted data', value: 'varied' },
  { label: 'Exact same path', value: 'exact' },
]

const commandPattern = ['M', 'L', 'L', 'Z']
const baseNumbers = [0, 0, 10, 10, 20, 0]

function makeNumbers(index) {
  if (mode.value === 'exact') return [...baseNumbers]

  const dx = index * 6
  const dy = index * 4
  return [
    baseNumbers[0] + dx,
    baseNumbers[1] + dy,
    baseNumbers[2] + dx,
    baseNumbers[3] + dy,
    baseNumbers[4] + dx,
    baseNumbers[5] + dy,
  ]
}

const pathRows = computed(() => Array.from({ length: copies.value }, (_, index) => makeNumbers(index)))

const interleavedTokens = computed(() =>
  pathRows.value.flatMap((row) => [
    { text: 'M', kind: 'command' },
    { text: String(row[0]), kind: 'value' },
    { text: String(row[1]), kind: 'value' },
    { text: 'L', kind: 'command' },
    { text: String(row[2]), kind: 'value' },
    { text: String(row[3]), kind: 'value' },
    { text: 'L', kind: 'command' },
    { text: String(row[4]), kind: 'value' },
    { text: String(row[5]), kind: 'value' },
    { text: 'Z', kind: 'command' },
  ])
)

const pooledRows = computed(() => (mode.value === 'exact' ? [pathRows.value[0] ?? baseNumbers] : pathRows.value))

const nodeRefs = computed(() =>
  Array.from({ length: copies.value }, (_, index) => (mode.value === 'exact' ? 'path[0]' : `pattern[0] + data[${index}]`))
)

const naiveCommandTokens = computed(() => copies.value * commandPattern.length)
const naiveNumericValues = computed(() => copies.value * baseNumbers.length)
const pooledCommandTokens = computed(() => commandPattern.length)
const pooledNumericValues = computed(() => pooledRows.value.length * baseNumbers.length)
</script>
