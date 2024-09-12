<template>
    <div class="container mx-auto px-4 py-8">
      <h1 class="text-4xl font-bold mb-8 text-center text-zinc-100">Design Gallery</h1>
      
      <!-- Single SVG Image -->
      <div v-if="isSingleSVG" class="flex justify-center items-center min-h-[calc(100vh-12rem)]">
        <div class="w-full max-w-4xl aspect-square">
          <img
            :src="galleryImages[0]"
            alt="Full page design"
            class="w-full h-full object-contain"
          />
        </div>
      </div>
  
      <!-- Multiple Images Gallery -->
      <div v-else class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
        <div
          v-for="(image, index) in paginatedImages"
          :key="index"
          class="bg-zinc-800 rounded-lg overflow-hidden shadow-lg transition-transform duration-300 hover:scale-105"
        >
          <div class="aspect-square">
            <img
              :src="image"
              :alt="`Design ${index + 1}`"
              class="w-full h-full object-cover"
            />
          </div>
     
        </div>
      </div>
  
      <!-- Pagination (only show for multiple images) -->
      <div v-if="!isSingleSVG && galleryImages.length > itemsPerPage" class="flex justify-center mt-8 space-x-4">
        <button
          @click="previousPage"
          :disabled="currentPage === 1"
          class="bg-zinc-700 hover:bg-zinc-600 disabled:bg-zinc-800 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-2 px-4 rounded transition duration-300"
        >
          Previous
        </button>
        <span class="text-zinc-300 self-center">Page {{ currentPage }} of {{ totalPages }}</span>
        <button
          @click="nextPage"
          :disabled="currentPage >= totalPages"
          class="bg-zinc-700 hover:bg-zinc-600 disabled:bg-zinc-800 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold py-2 px-4 rounded transition duration-300"
        >
          Next
        </button>
      </div>
  
      <!-- Back to Home Link -->
      <div class="text-center mt-8">
        <NuxtLink to="/" class="text-neon-green hover:underline transition duration-300">
          &larr; Back to Home
        </NuxtLink>
      </div>
    </div>
  </template>
  
  <script setup>
  import { ref, computed } from 'vue'
  
  const itemsPerPage = 12
  const currentPage = ref(1)
  
  // Server-side only function to get gallery images
  async function getGalleryImages() {  
    const { readdir } = require('node:fs/promises')
    const { join } = require('node:path')

    const galleryDir = join(process.cwd(), 'public', 'gallery')
    return readdir(galleryDir)
      .then(files => 
        files
          .filter(file => /\.(png|jpe?g|gif|svg)$/i.test(file))
          .map(file => `/gallery/${file}`)
      )
      .catch(error => {
        console.error('Error reading gallery directory:', error)
        return []
      })
  
  }
  

  const { data: galleryImages } = await useLazyAsyncData('galleryImages', getGalleryImages, {
    server: true,
    prefetch:true
  })
  
  const isSingleSVG = computed(() => {
    return galleryImages.value?.length === 1 && galleryImages.value[0].endsWith('.svg')
  })
  
  const paginatedImages = computed(() => {
    if (!galleryImages.value || isSingleSVG.value) return []
    const start = (currentPage.value - 1) * itemsPerPage
    const end = start + itemsPerPage
    return galleryImages.value.slice(start, end)
  })
  
  const totalPages = computed(() => {
    if (isSingleSVG.value) return 1
    return Math.ceil((galleryImages.value?.length || 0) / itemsPerPage)
  })
  
  const previousPage = () => {
    if (currentPage.value > 1) {
      currentPage.value--
    }
  }
  
  const nextPage = () => {
    if (currentPage.value < totalPages.value) {
      currentPage.value++
    }
  }
  </script>