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
let resizeHandler = null

function createSeededRandom(seed) {
  let state = seed >>> 0

  return () => {
    state = (state * 1664525 + 1013904223) >>> 0
    return state / 4294967296
  }
}

function createParticleSeed(width, height, count) {
  return (
    Math.imul(Math.round(width), 73856093) ^
    Math.imul(Math.round(height), 19349663) ^
    Math.imul(count, 83492791)
  ) >>> 0
}

function createParticles(width, height) {
  const isMobile = width < 768
  const count = isMobile ? 50 : 100
  const random = createSeededRandom(createParticleSeed(width, height, count))

  particles = []

  for (let i = 0; i < count; i++) {
    particles.push({
      x: random() * width,
      y: random() * height,
      size: 1.5 + random() * 2.5,
      phase: random() * Math.PI * 2,
      speed: 0.3 + random() * 0.7,
      rotation: random() * Math.PI * 2,
      minOpacity: 0.08 + random() * 0.12,
      maxOpacity: 0.35 + random() * 0.45,
    })
  }
}

function drawSparkle(ctx, particle, opacity, time) {
  const outerRadius = particle.size
  const innerRadius = outerRadius * 0.28
  const rotation = particle.rotation + time * 0.00015 * particle.speed

  ctx.save()
  ctx.translate(particle.x, particle.y)
  ctx.rotate(rotation)
  ctx.beginPath()

  for (let i = 0; i < 8; i++) {
    const angle = (Math.PI / 4) * i
    const radius = i % 2 === 0 ? outerRadius : innerRadius
    const px = Math.cos(angle) * radius
    const py = Math.sin(angle) * radius

    if (i === 0) {
      ctx.moveTo(px, py)
    }
    else {
      ctx.lineTo(px, py)
    }
  }

  ctx.closePath()
  ctx.fillStyle = `rgba(255, 255, 245, ${opacity})`
  ctx.shadowColor = `rgba(255, 255, 220, ${opacity * 0.9})`
  ctx.shadowBlur = outerRadius * 4
  ctx.fill()

  ctx.beginPath()
  ctx.arc(0, 0, innerRadius * 0.9, 0, Math.PI * 2)
  ctx.fillStyle = `rgba(255, 255, 255, ${Math.min(1, opacity + 0.2)})`
  ctx.fill()
  ctx.restore()
}

function draw(ctx, time) {
  const { width, height } = ctx.canvas
  ctx.clearRect(0, 0, width, height)

  for (const p of particles) {
    const opacity =
      p.minOpacity +
      (p.maxOpacity - p.minOpacity) *
        (0.5 + 0.5 * Math.sin(time * 0.001 * p.speed + p.phase))

    drawSparkle(ctx, p, opacity, time)
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

  resizeHandler = resize
  resize()
  window.addEventListener('resize', resizeHandler)

  function animate(time) {
    draw(ctx, time)
    animationId = requestAnimationFrame(animate)
  }
  animationId = requestAnimationFrame(animate)
})

onUnmounted(() => {
  if (animationId) cancelAnimationFrame(animationId)
  if (resizeHandler) window.removeEventListener('resize', resizeHandler)
})
</script>
