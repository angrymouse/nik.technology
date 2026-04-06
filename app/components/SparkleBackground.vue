<template>
  <canvas
    ref="canvas"
    class="fixed inset-0 z-0 pointer-events-none"
    aria-hidden="true"
  />
</template>

<script setup>
import { ref, onMounted, onUnmounted } from 'vue'

const canvas = ref(null)
let animationId = null
let particles = []

function createParticles(width, height) {
  const isMobile = width < 768
  const count = isMobile ? 50 : 100
  particles = []

  for (let i = 0; i < count; i++) {
    particles.push({
      x: Math.random() * width,
      y: Math.random() * height,
      size: 0.5 + Math.random() * 1.5,
      phase: Math.random() * Math.PI * 2,
      speed: 0.3 + Math.random() * 0.7, // oscillation speed
      minOpacity: 0.05 + Math.random() * 0.1,
      maxOpacity: 0.3 + Math.random() * 0.5,
    })
  }
}

function draw(ctx, time) {
  const { width, height } = ctx.canvas
  ctx.clearRect(0, 0, width, height)

  for (const p of particles) {
    const opacity =
      p.minOpacity +
      (p.maxOpacity - p.minOpacity) *
        (0.5 + 0.5 * Math.sin(time * 0.001 * p.speed + p.phase))

    ctx.beginPath()
    ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2)
    ctx.fillStyle = `rgba(255, 255, 250, ${opacity})`
    ctx.fill()
  }
}

onMounted(() => {
  const cvs = canvas.value
  if (!cvs) return

  // Respect reduced motion
  const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches
  if (prefersReduced) return

  const ctx = cvs.getContext('2d')
  if (!ctx) return

  function resize() {
    const dpr = window.devicePixelRatio || 1
    cvs.width = window.innerWidth * dpr
    cvs.height = window.innerHeight * dpr
    cvs.style.width = `${window.innerWidth}px`
    cvs.style.height = `${window.innerHeight}px`
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    createParticles(window.innerWidth, window.innerHeight)
  }

  resize()
  window.addEventListener('resize', resize)

  function animate(time) {
    draw(ctx, time)
    animationId = requestAnimationFrame(animate)
  }
  animationId = requestAnimationFrame(animate)

  onUnmounted(() => {
    if (animationId) cancelAnimationFrame(animationId)
    window.removeEventListener('resize', resize)
  })
})
</script>
