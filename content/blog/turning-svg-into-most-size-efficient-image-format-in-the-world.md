---
title: "Turning SVG into the most size-efficient image format in the world"
description: "How I took SVG apart, treated it like source code, and kept removing repeated bytes until the compiled format beat svgz by a wide margin."
date: "2026-04-07"
tags: ["svg", "compression", "bytecode", "graphics", "compilers"]
---

[GitHub](https://github.com/angrymouse/svgcmp) | [npm](https://www.npmjs.com/package/svgcmp) | [Telegram](https://t.me/TheTechQuant)

SVG is a great format to work with.

It is text. You can open it in an editor, diff it, search it, patch it, and usually figure out what is going on without special tools.

It is also a bad way to store an image if the only thing you care about is size.

That is not a philosophical complaint about XML. It is a very literal complaint about repeated bytes.

An SVG keeps saying the same things again and again:

- tag names
- attribute names
- namespace strings
- decimal numbers written as text
- colors written as text
- path commands mixed in with their numeric payloads
- the same style combinations on sibling elements
- the same path structure with slightly different coordinates

If the goal is authoring, those are reasonable choices.

If the goal is making the file as small as possible, they are expensive habits.

So I stopped treating SVG as the final format and started treating it as source code.

That was the start of `svgcmp`.

## What a browser does, and what I do not need to ship

A browser does a lot of work before it can draw an SVG.

It reads XML. It resolves tags and attributes. It parses decimal strings into numbers. It parses color strings into channels. It reads a path string like this:

```xml
<path d="M0 0 L10 10 L20 0 Z" fill="#00ff00" stroke="black" stroke-width="2"/>
```

and turns it into something closer to this:

- element kind: path
- path commands: `M L L Z`
- path numbers: `0 0 10 10 20 0`
- fill: green
- stroke: black
- stroke width: 2

That second representation is much closer to the drawing itself.

So the core decision was simple: store something closer to what the renderer already wants, not the text that humans happened to write.

I call it a VM because the output is a compact instruction/data format for drawing, but the important part is not the name. The important part is that the binary stores meaning directly instead of storing markup and asking the decoder to rediscover the meaning every time.

## Where SVG files keep spending bytes

The same attribute names appear on every sibling. The same path command patterns show up over and over. The same stroke widths and fills get restated on long runs of `<path>` elements. Numbers that would fit comfortably in a byte or two are written as several ASCII characters plus punctuation.

A browser can afford verbose, irregular input because it is built to accept it.

A storage format should not be.

## Step 1: stop paying for repeated strings

Known tags and attributes became numeric codes. Repeated strings moved into tables. Anything common stopped being written as text over and over.

So instead of shipping `stroke-width` every time a path needs it, the file ships a small symbol. Instead of repeating `http://www.w3.org/2000/svg`, the file stores it once and refers to it.

## Step 2: split the document into sections

Early versions were binary, but they still interleaved structure and payload too closely.

The cleaner layout was to split the file into distinct sections:

- string table
- path pool
- transform pool
- node stream

And inside the path pool, split command bytes from numeric data.

Instead of interleaving commands and numbers, it writes command streams together and numeric streams together.

That makes the layout smaller and more compressible because similar bytes stay together.

## Step 3: separate path shape from path coordinates

A path really contains two different things:

1. the command pattern
2. the numbers attached to it

For example, these paths all share the same pattern:

```text
M C S Q T L A Z
```

The coordinates differ, but the structure does not.

So `svgcmp` stores path command patterns separately from path instances.

At one point I was storing a parallel stream of value counts for each path command. That turned out to be nonsense. The opcode already tells you the arity. A cubic curve always needs six numbers. A close-path needs none. The decoder already knows this.

## Step 4: treat coordinates like storage, not scripture

SVG files often carry more numeric precision than the image needs.

That is useful while editing and wasteful when shipping an asset.

So path coordinates moved into fixed-point storage with adaptive scaling.

In practice that means:

- coordinates are rounded
- the scale is chosen based on size, not on sentiment
- values are forced into small integer ranges wherever possible

If a control point is written as `10.5432` and `10.54` renders the same image, the extra digits do not help.

Once coordinates are rounded into tighter integer ranges, two more things happen:

- the raw path payload shrinks
- delta encoding starts working much better because nearby paths stay numerically close

## Step 5: give `<path>` a dedicated compact encoding

Generic element encoding is flexible.

It is also wasteful when a file contains long runs of nearly identical `<path>` elements.

So `svgcmp` gives `<path>` its own compact node form.

Instead of repeatedly spelling out the same structural facts, the compact form assumes a known field order and uses a small bitmask for what is present. In the common case, a path node boils down to:

- compact-path opcode
- path reference
- compact style payload

not:

- generic element opcode
- tag symbol
- attribute count
- attribute name
- value opcode
- attribute name
- value opcode
- attribute name
- value opcode
- attribute name
- value opcode

For long runs of paths, that savings adds up quickly.

## Step 6: reuse style across path runs

A lot of neighboring paths share the same style, or almost the same style.

Maybe the fill stays `none` for a whole run. Maybe `stroke-width` is fixed. Maybe the stroke color shifts gradually instead of changing in unrelated jumps.

So the compact path encoding became stateful.

If a path can reuse style from the previous compact path node, it does. If the stroke color only changes a little, the file can store a small RGB delta instead of a full paint payload.

## Step 7: pack small vocabularies below one byte

After the larger structural waste was gone, fixed overhead started to matter more.

Path commands live in a small vocabulary. Some compact-path mode values do too. Spending a whole byte on each of them is convenient, but not justified.

So those streams got packed more tightly. For example, path commands are packed into 5-bit codes and compact path run metadata uses 4-bit values where that is enough.

## Step 8: reorder for locality when it is safe

Compression works better when similar records sit next to each other.

So the encoder reorders data where that does not change the image:

- path pools are grouped by command pattern
- paths inside a pattern group are ordered by numeric similarity
- transform pools are grouped by shape and ordered by value similarity
- some sibling runs of compact paths are reordered conservatively when the style makes that safe

SVG draw order can affect the result, so the reordering rules stay conservative.

## Step 9: delta-code whatever behaves predictably

Once similar records are adjacent, delta coding starts paying off.

A path index that would have been written as an absolute reference can often be stored as a small delta from the previous one. Similar paths with the same command pattern can store coordinate deltas instead of full coordinate lists. Similar transforms can do the same thing.

The current format uses delta or predictive coding in several places, including:

- path index deltas inside compact path runs
- coordinate delta mode for same-pattern paths
- transform delta mode for repeated transform shapes
- RGB deltas for nearby stroke colors

When the stream turns into small signed changes instead of unrelated absolute values, the final compressor has less entropy to deal with.

## Step 10: stop storing paint as text

SVG color syntax is useful for humans and bad for storage.

These are comfortable to write:

- `#00ff00`
- `black`
- `rgba(255,0,0,0.5)`

Inside `svgcmp`, paint becomes typed byte payloads.

That means:

- opaque colors use RGB
- alpha is stored only when it is needed
- special values like `none` and `currentColor` get dedicated representations

There is no reason to ship six hexadecimal characters when three bytes say the same thing.

## Step 11: only then compress it with zstd

Zstd is the outer compression layer.

If the representation underneath is still noisy, swapping compressors only gives you a slightly smaller noisy format.

The useful work happened before zstd ever saw the file:

- deduplicate repeated structures
- separate commands from data
- tighten numeric encoding
- reuse style
- improve locality
- pack opcodes and metadata more aggressively

After that, zstd gets a much better byte stream to work with.

## Why `svgz` is the comparison that matters

Raw SVG is not the interesting baseline.

The real comparison is `svgz`, because gzip is already good at repetitive text, and SVG gives it plenty to work with.

That is why most of the work went into changing the structure instead of swapping compressors. To beat `svgz`, the redundancy has to go away before the general-purpose compressor runs.

The format has to stop looking like source text and start looking like the drawing.

## Current results

On the current fixtures, `svgcmp` beats `svgz` across the board.

| Fixture | SVGZ | svgcmp | Improvement vs SVGZ |
|---|---:|---:|---:|
| `basic.svg` | 337 | 187 | 44.5% smaller |
| `repeated-basic.svg` | 350 | 197 | 43.7% smaller |
| `complex-paths.svg` | 761 | 442 | 41.9% smaller |
| `repeated-complex-paths.svg` | 180 | 113 | 37.2% smaller |

`complex-paths.svg` was the fixture that kept finding weak spots in the format.

It exposed waste in path metadata, style payloads, coordinate storage, ordering, and delta behavior.

## What the VM idea really bought me

Calling the project a VM kept the focus on the renderer-facing representation.

Not "how do I zip XML a bit better?"

But:

**What does the renderer actually need, and what is the cheapest way to store it?**

From there, a lot of decisions followed naturally:

- strings become symbols
- repeated structures become tables and pools
- paths become patterns plus numeric payloads
- generic numbers become fixed-point integers
- repeated path nodes get their own encoding
- repeated style becomes state
- predictable values become deltas
- small vocabularies get packed below a byte

That is closer to a compiler mindset than a markup mindset.

SVG is still the source language. It just is not the thing I want to ship anymore.

Thanks for reading. If you found this interesting, follow my Telegram channel [The Tech Quant](https://t.me/TheTechQuant) for more posts like this.

