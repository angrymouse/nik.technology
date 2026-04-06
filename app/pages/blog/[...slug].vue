<template>
  <div class="min-h-screen bg-black">
    <SparkleBackground />
    <div class="relative z-10 container mx-auto px-4 py-12">
      <article v-if="post" class="prose-blog">
        <!-- Back link -->
        <NuxtLink
          to="/blog"
          class="inline-flex items-center text-zinc-500 hover:text-neon-green text-sm mb-8 transition-colors"
        >
          &larr; Back to blog
        </NuxtLink>

        <!-- Header -->
        <header class="mb-10">
          <h1 class="font-display text-3xl md:text-4xl font-bold text-white tracking-tight mb-4">
            {{ post.title }}
          </h1>
          <div class="flex flex-wrap items-center gap-4 text-sm text-zinc-500">
            <time v-if="post.date" :datetime="post.date">
              {{ formatDate(post.date) }}
            </time>
            <span v-if="readingTime" class="text-zinc-600">&middot;</span>
            <span v-if="readingTime" class="text-zinc-500">{{ readingTime }} min read</span>
          </div>
          <div v-if="post.tags?.length" class="flex flex-wrap gap-2 mt-4">
            <span
              v-for="tag in post.tags"
              :key="tag"
              class="glass-pill"
            >
              {{ tag }}
            </span>
          </div>
        </header>

        <!-- Content -->
        <ContentRenderer :value="post" />
      </article>

      <div v-else class="glass p-12 text-center max-w-2xl mx-auto">
        <p class="text-zinc-500">Post not found.</p>
        <NuxtLink to="/blog" class="text-neon-green hover:underline text-sm mt-4 inline-block">
          &larr; Back to blog
        </NuxtLink>
      </div>
    </div>
  </div>
</template>

<script setup>
const route = useRoute()

const { data: post } = await useAsyncData(`blog-${route.path}`, () =>
  queryCollection('blog')
    .path(route.path)
    .first()
)

const readingTime = computed(() => {
  if (!post.value?.body) return null
  // Rough estimate: count text nodes in the AST
  const text = JSON.stringify(post.value.body)
  const wordCount = text.split(/\s+/).length / 3 // JSON overhead factor
  return Math.max(1, Math.round(wordCount / 200))
})

function formatDate(dateStr) {
  if (!dateStr) return ''
  const d = new Date(dateStr)
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}

if (post.value) {
  useSeoMeta({
    title: `${post.value.title} - Nik Rykov`,
    description: post.value.description || '',
    ogTitle: post.value.title,
    ogDescription: post.value.description || '',
    ogType: 'article',
    articlePublishedTime: post.value.date,
    twitterCard: 'summary_large_image',
  })
}
</script>
