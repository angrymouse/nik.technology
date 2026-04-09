<template>
  <figure class="my-8">
    <div class="glass p-5 md:p-6">
      <div class="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <div class="text-[11px] uppercase tracking-[0.24em] text-zinc-500">Interactive</div>
          <h3 class="mt-2 text-lg font-semibold text-white">Packing command vocabularies below one byte</h3>
          <p class="mt-2 max-w-2xl text-sm leading-6 text-zinc-400">
            Path commands only need 20 codes, so they fit in 5 bits. Compact path run modes need even less and fit in 4.
            Drag the slider and watch the packed stream shrink.
          </p>
        </div>

        <label class="flex items-center gap-3 text-sm text-zinc-300">
          <span class="text-zinc-400">Entries</span>
          <input v-model="entryCount" type="range" min="8" max="40" step="4" class="w-32 accent-[#FF885B]" />
          <span class="w-8 text-right tabular-nums">{{ entryCount }}</span>
        </label>
      </div>

      <div class="mt-6 grid gap-4 lg:grid-cols-[1.15fr_0.85fr]">
        <section class="rounded-2xl border border-white/8 bg-black/30 p-4">
          <div class="text-xs uppercase tracking-[0.22em] text-zinc-500">Command stream</div>
          <div class="mt-3 flex flex-wrap gap-1.5">
            <span
              v-for="(command, index) in commandSequence"
              :key="`${command.label}-${index}`"
              class="rounded-md bg-[#FF885B]/15 px-2 py-1 text-xs font-medium text-[#FFb18f]"
            >
              {{ command.label }}
            </span>
          </div>

          <div class="mt-4 text-xs text-zinc-500">5-bit codes</div>
          <div class="mt-2 flex flex-wrap gap-1.5 font-mono text-xs text-zinc-300">
            <span
              v-for="(command, index) in commandSequence"
              :key="`bits-${index}`"
              class="rounded-md bg-white/[0.03] px-2 py-1"
            >
              {{ command.bits }}
            </span>
          </div>

          <div class="mt-4 text-xs text-zinc-500">Packed bytes</div>
          <div class="mt-2 flex flex-wrap gap-1.5 font-mono text-xs text-zinc-300">
            <span
              v-for="(chunk, index) in packedByteChunks"
              :key="`chunk-${index}`"
              class="rounded-md bg-sky-500/15 px-2 py-1 text-sky-200"
            >
              {{ chunk }}
            </span>
          </div>
        </section>

        <section class="rounded-2xl border border-white/8 bg-black/30 p-4">
          <div class="text-xs uppercase tracking-[0.22em] text-zinc-500">Byte cost</div>

          <div class="mt-3 space-y-3 text-sm">
            <div class="rounded-xl bg-white/[0.03] p-3">
              <div class="flex items-center justify-between">
                <span class="text-zinc-400">1 byte per command</span>
                <span class="font-semibold text-white">{{ rawCommandBytes }} bytes</span>
              </div>
              <div class="mt-2 h-2 rounded-full bg-white/[0.06]">
                <div class="h-2 rounded-full bg-zinc-500" :style="{ width: '100%' }" />
              </div>
            </div>

            <div class="rounded-xl bg-white/[0.03] p-3">
              <div class="flex items-center justify-between">
                <span class="text-zinc-400">5-bit packed commands</span>
                <span class="font-semibold text-white">{{ packedCommandBytes }} bytes</span>
              </div>
              <div class="mt-2 h-2 rounded-full bg-white/[0.06]">
                <div class="h-2 rounded-full bg-[#FF885B]" :style="{ width: `${(packedCommandBytes / rawCommandBytes) * 100}%` }" />
              </div>
            </div>

            <div class="rounded-xl bg-white/[0.03] p-3">
              <div class="flex items-center justify-between">
                <span class="text-zinc-400">4-bit metadata stream</span>
                <span class="font-semibold text-white">{{ packedModeBytes }} bytes</span>
              </div>
              <div class="mt-2 h-2 rounded-full bg-white/[0.06]">
                <div class="h-2 rounded-full bg-emerald-400" :style="{ width: `${(packedModeBytes / rawCommandBytes) * 100}%` }" />
              </div>
            </div>
          </div>

          <p class="mt-4 text-sm text-zinc-400">
            Saved against 1 byte per command:
            <span class="font-semibold text-white">{{ rawCommandBytes - packedCommandBytes }} bytes</span>
          </p>
        </section>
      </div>
    </div>
  </figure>
</template>

<script setup>
import { computed, ref } from 'vue'

const entryCount = ref(16)

const baseCommands = [
  { label: 'M', code: 1 },
  { label: 'C', code: 9 },
  { label: 'S', code: 11 },
  { label: 'Q', code: 13 },
  { label: 'T', code: 15 },
  { label: 'L', code: 2 },
  { label: 'A', code: 17 },
  { label: 'Z', code: 19 },
]

function toFiveBit(code) {
  return code.toString(2).padStart(5, '0')
}

const commandSequence = computed(() =>
  Array.from({ length: entryCount.value }, (_, index) => {
    const command = baseCommands[index % baseCommands.length]
    return {
      ...command,
      bits: toFiveBit(command.code),
    }
  })
)

const rawCommandBytes = computed(() => entryCount.value)
const packedCommandBytes = computed(() => Math.ceil((entryCount.value * 5) / 8))
const packedModeBytes = computed(() => Math.ceil((entryCount.value * 4) / 8))

const packedByteChunks = computed(() => {
  const bitStream = commandSequence.value.map((command) => command.bits).join('')
  const chunks = []

  for (let index = 0; index < bitStream.length; index += 8) {
    chunks.push(bitStream.slice(index, index + 8).padEnd(8, '·'))
  }

  return chunks
})
</script>
