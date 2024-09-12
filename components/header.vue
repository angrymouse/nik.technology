<template>
    <header class="bg-black p-4">
      <nav class="container mx-auto flex justify-between items-center">
        <h1 class="text-2xl font-bold text-white">Nik Rykov</h1>
        
        <!-- Hamburger menu for mobile -->
        <button class="lg:hidden text-white focus:outline-none p-2" @click="toggleMenu">
          <Menu v-if="!isMenuOpen" class="w-8 h-8" />
          <X v-else class="w-8 h-8" />
        </button>
        
        <!-- Navigation menu for desktop -->
        <ul class="hidden lg:flex lg:space-x-4">
          <li v-for="item in menuItems" :key="item.href">
            <NuxtLink :to="item.href" class="text-white hover:text-neon-green">
              {{ item.label }}
            </NuxtLink>
          </li>
        </ul>
      </nav>
      
      <!-- Mobile menu (hidden by default) -->
      <Transition name="slide-fade">
        <div v-if="isMenuOpen" class="lg:hidden mt-4">
          <ul class="flex flex-col space-y-2">
            <li v-for="item in menuItems" :key="item.href">
              <NuxtLink 
                :to="item.href" 
                class="block text-white hover:text-neon-green text-lg py-3 px-4 bg-zinc-800 rounded-md w-full text-center"
                @click="closeMenu"
              >
                {{ item.label }}
              </NuxtLink>
            </li>
          </ul>
        </div>
      </Transition>
    </header>
  </template>
  
  <script setup>
  import { ref } from 'vue'
  import { Menu, X } from 'lucide-vue-next'
  
  const isMenuOpen = ref(false)
  
  const menuItems = [
    { label: 'About', href: '#about' },
    { label: 'Skills', href: '#jack-of-all-trades' },
    { label: 'Projects', href: '#projects' },
    { label: 'Contact', href: '#contact' }
  ]
  
  const toggleMenu = () => {
    isMenuOpen.value = !isMenuOpen.value
  }
  
  const closeMenu = () => {
    isMenuOpen.value = false
  }
  </script>
  
  <style scoped>
  .slide-fade-enter-active,
  .slide-fade-leave-active {
    transition: all 0.3s ease;
  }
  
  .slide-fade-enter-from,
  .slide-fade-leave-to {
    transform: translateY(-20px);
    opacity: 0;
  }
  </style>