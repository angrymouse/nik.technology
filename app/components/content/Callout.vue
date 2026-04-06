<template>
  <div :class="['my-6 p-4 rounded-r-lg border-l-2', borderColor, bgColor]">
    <div class="flex items-center gap-2 mb-2 text-sm font-semibold" :class="titleColor">
      <span>{{ icon }}</span>
      <span>{{ label }}</span>
    </div>
    <div class="text-zinc-300 text-sm leading-relaxed">
      <slot />
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  type: {
    type: String,
    default: 'info',
    validator: (v) => ['info', 'warning', 'tip'].includes(v),
  },
})

const config = computed(() => {
  const types = {
    info: {
      icon: 'i',
      label: 'Info',
      border: 'border-zinc-400',
      bg: 'bg-white/[0.02]',
      title: 'text-zinc-300',
    },
    warning: {
      icon: '!',
      label: 'Warning',
      border: 'border-[#FF885B]',
      bg: 'bg-[#FF885B]/[0.03]',
      title: 'text-[#FF885B]',
    },
    tip: {
      icon: '*',
      label: 'Tip',
      border: 'border-emerald-500',
      bg: 'bg-emerald-500/[0.03]',
      title: 'text-emerald-400',
    },
  }
  return types[props.type] || types.info
})

const icon = computed(() => config.value.icon)
const label = computed(() => config.value.label)
const borderColor = computed(() => config.value.border)
const bgColor = computed(() => config.value.bg)
const titleColor = computed(() => config.value.title)
</script>
