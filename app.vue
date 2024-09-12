<template>
  <div class="min-h-screen bg-zinc-900 text-white">
    <header class="bg-black p-4">
      <nav class="container mx-auto flex justify-between items-center">
        <h1 class="text-2xl font-bold">Nik Rykov</h1>
        <ul class="flex space-x-4">
          <li><a href="#about" class="hover:text-neon-green">About</a></li>
          <li><a href="#jack-of-all-trades" class="hover:text-neon-green">Skills</a></li>
          <li><a href="#projects" class="hover:text-neon-green">Projects</a></li>
          <li><a href="#contact" class="hover:text-neon-green">Contact</a></li>
        </ul>
      </nav>
    </header>

    <NuxtPage />

    <footer class="bg-black p-4 mt-12 border-t-2 border-neon-green">
      <div class="container mx-auto text-center">
        <p>&copy; 2024 Nik Rykov. All rights reserved.</p>
      </div>
    </footer>
  </div>
</template>


<style>
@import 'tailwindcss/base';
@import 'tailwindcss/components';
@import 'tailwindcss/utilities';

:root {
  --neon-green: #FF885B;
}

</style>