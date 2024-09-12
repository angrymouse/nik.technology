<template>
    <div class="container mx-auto mt-8 px-4">

      <section id="about" class="mb-12">
        <div class="flex items-center space-x-8">
          <img src="@/assets/photo.png" alt="Your Photo" class="w-48 h-48 rounded-full object-cover border-4 border-neon-green">
          <div>
            <h2 class="text-3xl font-bold mb-4">About Me</h2>
            <p class="text-gray-300">
              Hey! I'm Nik Rykov, the technology guy originating from Ukraine and nearing 19. 
              <br>
              I spend most of my time thinking about software, designing it, implementing it, and helping other people build software of their own.
              <br>
              I have some expertise in cryptocurrency industry, as it's the only one being able to give me the ability to design complex/sophisticated protocols able to load my brain.  
            </p>
          </div>
        </div>
      </section>
  
  
      <section id="jack-of-all-trades" class="mb-12">
        <h2 class="text-3xl font-bold mb-4">Jack of all trades AND a master of one</h2>
        <div class="text-lg text-zinc-400 mb-4">Even though my main strength is in designing software systems and protocols, I know *just enough* of other aspects to ship products/protocols/projects.</div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div class="bg-zinc-800 p-6 rounded-lg border-2 border-zinc-950">
            <div class="flex items-center mb-2">
              <Code class="w-6 h-6 mr-2 text-neon-green" />
              <h3 class="text-xl font-semibold">Software Development</h3>
            </div>
            <p class="text-zinc-300">I've got 7 years of experience in programming, with JS being my primary programming language. I managed to develop all types of applications, from personal to open-source software/libraries to commercial products. Make sure to check out my <a class="text-neon-green hover:underline" target="_blank" href="https://github.com/angrymouse">GitHub</a>
            </p>
          </div>

          <div class="bg-zinc-800 p-6 rounded-lg border-2 border-zinc-950">
            <div class="flex items-center mb-2">
              <Palette class="w-6 h-6 mr-2 text-neon-green" />
              <h3 class="text-xl font-semibold">Design</h3>
            </div>
            <p class="text-zinc-300">I designed several UIs, slide designs, banners, logotypes for a number of products I've been involved with. While not being my primary strength, my design skills are usually sufficient to convey needed thought and make UIs pleasant to use. Check out my <NuxtLink to="/gallery" class="text-neon-green hover:underline" target="_blank">gallery</NuxtLink>
            </p>
          </div>

          <div class="bg-zinc-800 p-6 rounded-lg border-2 border-zinc-950">
            <div class="flex items-center mb-2">
              <GitBranch class="w-6 h-6 mr-2 text-neon-green" />
              <h3 class="text-xl font-semibold">Protocol Design/Technology Research</h3>
            </div>
            <p class="text-zinc-300">
              My strong side. I know how to convert the end goal desire into a detailed plan for achieving it. 
              I designed multiple technical papers and specifications for the goals I encountered during my journey. Most of them are listed in my <a class="text-neon-green hover:underline" target="_blank" href="https://github.com/angrymouse/papers/">papers repo</a>.
            </p>
          </div>
  
          <div class="bg-zinc-800 p-6 rounded-lg border-2 border-zinc-950">
            <div class="flex items-center mb-2">
              <Layers class="w-6 h-6 mr-2 text-neon-green" />
              <h3 class="text-xl font-semibold">Managing small teams</h3>
            </div>
            <p class="text-zinc-300">
              I have managed few small scale teams (&lt;10 people). Even though I don't have experience managing large teams, I can direct and help a group of people to achieve good, objective results.
            </p>
          </div>
        </div>
      </section>

      <section id="projects" class="mb-12">
        <h2 class="text-3xl font-bold mb-4">Projects I worked on</h2>
        <div class="flex justify-center md:justify-start gap-6 flex-wrap ">
          <a href="https://findadiscord.com" class="p-0.5 bg-gradient-to-r from-red-500 to-neon-green w-48 rounded-3xl">
            <div class="bg-zinc-800 p-4 pt-0 rounded-3xl flex justify-start flex-col items-center h-full">
              <NuxtImg src="/fad_logo.svg" width="80" class="mt-4" />
              <h3 class="text-md font-semibold m-2">FindADiscord.com</h3>
              <div class="text-gray-300 text-center">Sole developer<br><div class="text-zinc-400 text-sm">2019-Present</div></div>
            </div>
          </a>
          
          <a href="https://arweave.org" class="p-0.5 bg-gradient-to-r from-red-500 to-neon-green rounded-3xl w-48">
            <div class="bg-zinc-800 p-4 pt-0 rounded-3xl flex justify-start flex-col items-center h-full">
              <NuxtImg src="/arweave.svg" width="80" class="mt-4" />
              <h3 class="text-md font-semibold m-2">Arweave</h3>
              <div class="text-gray-300 text-center">Software Developer<br> <div class="text-zinc-400 text-sm">2021-2023</div></div>
            </div>
          </a>
          
          <a href="https://stargaze.zone" class="p-0.5 bg-gradient-to-r from-red-500 to-neon-green rounded-3xl w-48">
            <div class="bg-zinc-800 p-4 pt-0 rounded-3xl flex justify-start flex-col items-center h-full">
              <NuxtImg src="/stargaze.svg" width="80" class="mt-4" />
              <h3 class="text-md font-semibold m-2">Stargaze</h3>
              <div class="text-gray-300 text-center">Software Developer <br> <div class="text-zinc-400 text-sm">2022-2023</div></div>
            </div>
          </a>
          <a href="https://www.wvm.dev/" class="p-0.5 bg-gradient-to-r from-red-500 to-neon-green rounded-3xl w-48">
            <div class="bg-zinc-800 p-4 pt-0 rounded-3xl flex justify-start flex-col items-center h-full">
              <NuxtImg src="/weavevm.png" width="80" class=" mt-4 rounded-3xl" />
              <h3 class="text-md font-semibold m-2">WeaveVM</h3>
              <div class="text-gray-300 text-center">Technical Advisor <br> <div class="text-zinc-400 text-sm">2024-Present</div></div>
            </div>
          </a>
          <a href="https://handshake.org" class="p-0.5 bg-gradient-to-r from-red-500 to-neon-green rounded-3xl w-48">
            <div class="bg-zinc-800 p-4 pt-0 rounded-3xl flex justify-start flex-col items-center h-full">
              <NuxtImg src="/handshake.svg" width="80" class="mt-4" />
              <h3 class="text-md font-semibold m-2">Handshake</h3>
              <div class="text-gray-300 text-center">Volunteer<br> <div class="text-zinc-400 text-sm">2021-Present</div></div>
            </div>
          </a>
          <a href="https://highlayer.io" class="p-0.5 bg-gradient-to-r from-red-500 to-neon-green rounded-3xl w-48">
            <div class="bg-zinc-800 p-4 pt-0 rounded-3xl flex justify-start flex-col items-center h-full">
              <NuxtImg src="/highlayer.svg" width="80" class=" mt-4 rounded-3xl bg-[rgb(171,57,21)]" />
              <h3 class="text-md font-semibold m-2">Highlayer</h3>
              <div class="text-gray-300 text-center">Founder/CTO <br> <div class="text-zinc-400 text-sm">2023-Present</div></div>
            </div>
          </a>
        </div>
      </section>
  

      <section id="contact" class="mb-12">
        <h2 class="text-3xl font-bold mb-4">Contact Me</h2>

        <div class="bg-zinc-800 p-4 rounded-lg border-2 border-zinc-950 mb-6 max-w-2xl">
          <div class="flex items-center mb-2">
            <Lock class="w-5 h-5 mr-2 text-neon-green" />
            <h3 class="text-lg font-semibold">PGP Key</h3>
          </div>
          <div class="text-zinc-300 text-sm py-2">If you have something important or confidential for me, it's always good idea to send it in pgp-encrypted format. Here's my public key, you can encrypt message to it and then use one of communication methods below. </div>
         
          <div class="relative bg-zinc-700 rounded-md overflow-hidden">
            <pre ref="pgpKeyPre" class="text-neon-green text-xs whitespace-pre-wrap break-all font-mono p-3 max-h-48 overflow-y-auto">-----BEGIN PGP PUBLIC KEY BLOCK-----
  mDMEZuI2AxYJKwYBBAHaRw8BAQdAJdzqsxGZ9tJb5leQcvJBjl7Jj3+YIQutBBui
  aeKGXSW0Fk5payBSeWtvdiA8bmlrQGhucy5pcz6ImQQTFgoAQRYhBLqmSa3FKSgd
  +d/pvsHv2R0dXdZQBQJm4jYDAhsDBQkFpCAdBQsJCAcCAiICBhUKCQgLAgQWAgMB
  Ah4HAheAAAoJEMHv2R0dXdZQorYBAPRjuIZjsZWTJi1cZViSgLPkDmJYxcD5JNu8
  +7bky3tMAP4kPMeayYBSx7e+YZB93nFuicrc4q+gKnd8mjmjZkiRBrg4BGbiNgMS
  CisGAQQBl1UBBQEBB0CoBM0/VuBKxtS0wd08h5dGp0G0ygbnfvZv1vIWiEJfDwMB
  CAeIfgQYFgoAJhYhBLqmSa3FKSgd+d/pvsHv2R0dXdZQBQJm4jYDAhsMBQkFpCAd
  AAoJEMHv2R0dXdZQvmsA/2V8hhThvxuuoQHt2bxiHidd/ZTcrcNo0XC/axgq2/n7
  AP4v26WUJLbNiW6KvnAltArskMpMCGFfN6xjQ/PLZAcZAg==
  =v9iU
  -----END PGP PUBLIC KEY BLOCK-----</pre>
            <button @click="copyPGPKey" :class="[
              'absolute bottom-1 right-1 px-1.5 py-0.5 rounded text-xs transition-colors duration-300 flex items-center',
              copied ? 'bg-green-500 text-white opacity-100' : 'bg-zinc-600 text-zinc-300 opacity-50 hover:opacity-100 hover:bg-zinc-500'
          ]">
            <component :is="copied ? CheckCircle : Copy" class="w-3 h-3 mr-1" />
            {{ copied ? 'Copied!' : 'Copy' }}
          </button>
        </div>
      </div>
      <div class="flex flex-wrap gap-4">

        <div class="bg-zinc-800 p-4 rounded-lg border-2 border-zinc-950 w-60">
          <div class="flex items-center mb-2">
            <MessageCircle class="w-5 h-5 mr-2 text-neon-green" />
            <h3 class="text-lg font-semibold">Discord</h3>
          </div>
          <div class="mt-2 p-2 bg-zinc-700 rounded-md text-center">
            <code class="text-neon-green">angrymouse</code>
          </div>
        </div>


        <div class="bg-zinc-800 p-4 rounded-lg border-2 border-zinc-950 w-60">
          <div class="flex items-center mb-2">
            <Phone class="w-5 h-5 mr-2 text-neon-green" />
            <h3 class="text-lg font-semibold">Signal</h3>
          </div>
          <div class="mt-2 p-2 bg-zinc-700 rounded-md text-center">
            <a href="https://signal.me/#eu/rOtG9QHSOXI8F8EDWdSaMxLItDJ4Di7TzL1otKDswlaZC3L6tsdFxpuPhhL9OxIV" 
               target="_blank" 
               class="text-neon-green hover:underline">
              angrymouse.01
            </a>
          </div>
        </div>

        <div class="bg-zinc-800 p-4 rounded-lg border-2 border-zinc-950 w-60">
          <div class="flex items-center mb-2">
            <Send class="w-5 h-5 mr-2 text-neon-green" />
            <h3 class="text-lg font-semibold">Telegram</h3>
          </div>
          <div class="mt-2 p-2 bg-zinc-700 rounded-md text-center">
            <a href="https://t.me/angermouse" 
               target="_blank" 
               class="text-neon-green hover:underline">
              @angermouse
            </a>
          </div>
        </div>

        <div class="bg-zinc-800 p-4 rounded-lg border-2 border-zinc-950 w-60">
          <div class="flex items-center mb-2">
            <Mail class="w-5 h-5 mr-2 text-neon-green" />
            <h3 class="text-lg font-semibold">E-mail</h3>
          </div>
          <div class="mt-2 p-2 bg-zinc-700 rounded-md text-center">
            <a href="mailto:nik@hns.is" 
               target="_blank" 
               class="text-neon-green hover:underline">
              nik@hns.is
            </a>
          </div>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup>
import { ref } from 'vue';
import { Code, Palette, GitBranch, Layers, MessageCircle, Phone, Mail, Send, Lock, Copy, CheckCircle } from 'lucide-vue-next';

const pgpKeyPre = ref(null);
const copied = ref(false);

const copyPGPKey = () => {
  if (pgpKeyPre.value) {
    copied.value = true;
      setTimeout(() => {
        copied.value = false;
      }, 3000);
    navigator.clipboard.writeText(pgpKeyPre.value.textContent)
  }
};
</script>

<style scoped>

</style>