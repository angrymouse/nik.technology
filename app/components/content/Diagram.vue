<template>
  <figure :class="['my-8', width === 'full' ? 'w-full' : 'max-w-2xl mx-auto']">
    <div class="glass p-6 overflow-x-auto">
      <slot />
    </div>
    <figcaption v-if="caption" class="text-center text-zinc-500 text-sm mt-3">
      {{ caption }}
    </figcaption>
  </figure>
</template>

<script setup>
defineProps({
  caption: {
    type: String,
    default: '',
  },
  width: {
    type: String,
    default: 'default',
    validator: (v) => ['default', 'full'].includes(v),
  },
})
</script>
