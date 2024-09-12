<template>
  <div class="min-h-screen bg-zinc-900 text-white">
    <Header/>

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