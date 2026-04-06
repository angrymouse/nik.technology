<template>
  <div class="min-h-screen bg-black">
    <SparkleBackground />
    <div class="relative z-10 container mx-auto px-4 py-12 max-w-3xl">
      <h1 class="font-display text-4xl md:text-5xl font-bold text-white mb-2 tracking-tight">
        Blog
      </h1>
      <p class="text-zinc-500 mb-10 text-sm">Thoughts, notes, and technical writings.</p>

      <div v-if="posts && posts.length" class="flex flex-col gap-5">
        <NuxtLink
          v-for="post in posts"
          :key="post.path"
          :to="post.path"
          class="glass block p-6 group"
        >
          <div class="flex items-baseline justify-between gap-4 mb-2">
            <h2 class="font-display text-xl md:text-2xl font-semibold text-white group-hover:text-neon-green transition-colors">
              {{ post.title }}
            </h2>
            <time
              :datetime="post.date"
              class="text-zinc-500 text-xs whitespace-nowrap flex-shrink-0"
            >
              {{ formatDate(post.date) }}
            </time>
          </div>
          <p v-if="post.description" class="text-zinc-400 text-sm leading-relaxed mb-3">
            {{ post.description }}
          </p>
          <div v-if="post.tags?.length" class="flex flex-wrap gap-2">
            <span
              v-for="tag in post.tags"
              :key="tag"
              class="glass-pill"
            >
              {{ tag }}
            </span>
          </div>
        </NuxtLink>
      </div>

      <div v-else class="glass p-12 text-center">
        <p class="text-zinc-500">No posts yet. Check back soon.</p>
      </div>
    </div>
  </div>
</template>

<script setup>
useSeoMeta({
  title: 'Blog - Nik Rykov',
  description: 'Thoughts, notes, and technical writings by Nik Rykov.',
  ogTitle: 'Blog - Nik Rykov',
  ogDescription: 'Thoughts, notes, and technical writings by Nik Rykov.',
})

const { data: posts } = await useAsyncData('blog-list', () =>
  queryCollection('blog')
    .where('draft', 'IS NOT', true)
    .order('date', 'DESC')
    .select('title', 'description', 'date', 'tags', 'path')
    .all()
)

function formatDate(dateStr) {
  if (!dateStr) return ''
  const d = new Date(dateStr)
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}
</script>
