---
title: "Turning SVG into most size efficient image format in the world"
description: "How I turned verbose SVG text into a tiny VM-friendly binary by attacking redundancy at every level: symbols, paths, styles, ordering, fixed-point math, and compression."
date: "2026-04-07"
tags: ["svg", "compression", "bytecode", "graphics", "compilers"]
---

SVG is one of those formats that feels elegant right until you try to ship a lot of it over the wire.

As a *language*, SVG is beautiful. As a *storage format*, SVG is kind of insane.

It is text. It repeats itself constantly. It spells out the same attribute names over and over. It stores geometry as human-readable decimal strings. It keeps saying things like `stroke-width`, `translate`, `viewBox`, `fill`, `path`, `xmlns`, and `http://www.w3.org/2000/svg` like bandwidth is free and CPUs are paid by the letter.

That is fine if the goal is readability.

It is not fine if the goal is: **make this thing as small as physically possible**.

So I started building a weird machine for it.

Not a general-purpose machine. Not JavaScript in disguise. A tiny non-programmable SVG virtual machine whose only job is to represent SVG structure more efficiently than SVG itself.

And once you start looking at SVG through that lens, you realize something important:

> SVG is already a program. It is just written in the most wasteful possible notation.

## The problem with SVG is not that it is complex. The problem is that it is redundant.

Take a simple SVG and squint at it as data instead of markup.

You immediately see the same kinds of waste everywhere:

- tag names repeated across siblings
- attribute names repeated across every element
- long namespace strings repeated in every file
- decimal numbers written as text
- path commands mixed together with their numeric payloads
- repeated path structures written out from scratch
- repeated transforms written out from scratch
- style patterns repeated from node to node
- colors written as strings instead of bytes
- semantically similar siblings serialized in arbitrary order

A browser can deal with this because browsers are heroic garbage disposals.

But if you are trying to build a compact transport or storage format, SVG is basically handing you a giant bag of repeated tokens and begging to be normalized.

## Step one: stop thinking in terms of files, start thinking in terms of a VM

The first real shift was this: instead of “compressing SVG text,” represent SVG as a small instruction-driven document format.

That gives you a few immediate wins.

You can stop paying text costs for structure.

Instead of writing:

```xml
<path d="M0 0 L10 10 L20 0 Z" fill="#00ff00" stroke="black" stroke-width="2"/>
```

You can encode the same thing as:

- node opcode: path element
- attribute presence bits
- path reference
- paint payload
- paint payload
- number payload

That is a very different game.

Once the representation becomes binary and typed, you stop paying for punctuation, whitespace, quotes, XML syntax, and decimal string parsing overhead. You can encode meaning directly instead of encoding text that later needs to be interpreted as meaning.

That is the foundation the whole project sits on.

## Then the real work starts: removing every repeated byte you can find

The VM alone is not enough. A naive binary format can still be bloated.

So the rest of the work became a long, mildly obsessive campaign against wasted bytes.

## 1. Symbol tables instead of repeated text

The easiest redundancy to kill is repeated strings.

SVG loves repeated strings:

- tag names like `svg`, `g`, `path`, `rect`
- attribute names like `fill`, `stroke`, `transform`
- namespace values
- IDs and references

So the format moved those into compact symbol tables and numeric codes. Known tags and attributes got fixed codes. Unknown ones fall back through a string table.

This means you are no longer writing `stroke-width` every time. You write a small integer. That is boring, but boring is how you get small.

## 2. Section the binary so similar bytes live together

This was one of the biggest conceptual improvements.

Early on, path data looked a lot like the original SVG mindset:

- command
n- numeric payload
- command
- numeric payload
- command
- numeric payload

That is convenient to stream, but it is not especially compressible.

Compression algorithms love repetition and homogeneity. They want stretches of similar things sitting next to each other.

So the format was reworked into sections.

Instead of interleaving command bytes and coordinate bytes, it now keeps major payload classes in their own structured blocks:

- string table
- path pool
- transform pool
- node stream

And within the path pool, commands and data are kept distinct. That means opcode streams cluster with opcode streams, and numeric streams cluster with numeric streams.

That matters a lot once an outer compressor gets involved.

## 3. Pool repeated path programs and transform programs

SVG files often repeat themselves shamelessly.

The same icon path shows up multiple times.
The same transform stack shows up on multiple siblings.
The same command pattern appears again and again with slightly different coordinates.

So instead of storing each path inline every time, the VM builds pools:

- unique path values
- unique transform values
- unique path *patterns*

Then nodes reference those pooled entries by index.

This is where the format started behaving less like “binary SVG” and more like a real compiled artifact.

The DOM-like node stream became a graph of references into sectioned payloads. That alone changes the economics dramatically.

## 4. Split path command patterns from path numeric data

This was a huge one.

Paths have two parts:

1. the *shape of the instruction stream* — `M C S Q T L A Z`
2. the actual numbers

If twelve paths all share the same command pattern but have different coordinates, writing the command pattern twelve times is just waste.

So the format now stores path command patterns once, separately from path instances.

A path instance becomes something closer to:

- which command pattern it uses
- where its numeric data begins

Even better, the value count for each command is derived from the opcode itself. There is no need to write parallel metadata explaining that `C` takes 6 values and `Z` takes 0. The opcode already tells you that.

That removed an entire stream of redundant bookkeeping.

## 5. Force coordinates into small fixed-width math

This is where things stopped being polite and started being effective.

Path coordinates were moved away from generic variable-length numeric encoding and into compact fixed-point storage with an aggressive size-first policy.

In plain English:

- coordinates are rounded
- scales are chosen adaptively
- path values are forced to fit tiny integer ranges whenever possible

The key realization is that most SVGs do not need arbitrary floating-point dignity. They need to look correct.

Human eyes do not care whether a control point was stored as `10.5432` or rounded to a tighter representation that renders identically on screen.

So the encoder picks the smallest practical scale that preserves enough fidelity while minimizing bytes.

That does two things:

- raw geometry gets smaller
- delta encoding gets dramatically better because the numbers are closer together

This is where compression stops being only about syntax and starts being about *numerical discipline*.

## 6. Use compact path-specialized node opcodes

Generic element encoding is flexible, but flexibility costs bytes.

A `<path>` element with exactly these attributes:

- `d`
- `fill`
- `stroke`
- `stroke-width`

shows up constantly.

So instead of serializing it like a generic XML-ish node, the format gives it its own compact encoding.

That means:

- dedicated node opcode
- bitmask for which style fields are present
- implicit field ordering
- path reference directly
- paint payloads in compact form

This avoids repeating generic tag and attribute symbols for the most common and most expensive shape in many SVGs.

It is the binary equivalent of saying: *we know what you meant, stop over-explaining.*

## 7. Reuse style across path runs

Then I noticed another SVG habit: once someone starts drawing paths, they often keep using the same styling for a while.

Maybe the fill stays `none`.
Maybe `stroke-width` is always `1.5`.
Maybe stroke colors evolve gradually instead of jumping randomly.

So compact path encoding grew memory.

Consecutive path nodes can now reuse previous style fields instead of re-encoding them. And when stroke colors move by small RGB deltas, the VM stores only the delta.

This is the kind of optimization that sounds tiny until you realize it hits every sibling in a path-heavy illustration.

And then it is not tiny anymore.

## 8. Pack opcodes below one byte when possible

If your opcode vocabulary is small, a full byte per opcode is a luxury.

Path command streams and transform opcode streams now use bit-packed representations.

For example, path commands fit in 5 bits, so the format packs them densely instead of wasting 8 bits each. Compact path-run mode values were tightened too, down to 4 bits each.

This is the sort of thing you only do after the bigger architectural fixes are in place. But once you are chasing the final stretch, it matters.

Sub-byte packing is annoying to implement, but bytes do not care about your feelings.

## 9. Reorder data for locality and better deltas

This is one of the most underrated parts.

Compression is not only about representation. It is also about **ordering**.

If similar things are adjacent, deltas get smaller and outer compressors get happier.

So the encoder now reorders pooled paths and transforms in ways that preserve meaning but improve locality:

- path pools are grouped by command pattern
- within a pattern group, paths are greedily ordered by numeric similarity
- transform pools are grouped by shape and ordered by value similarity
- some compact path sibling runs can be safely reordered when style and opacity rules make order irrelevant

That last point matters because visual order in SVG can affect rendering. So the reordering has to be conservative.

But where it is safe, it pays off.

This is the point where the format stops merely “encoding SVG” and starts *staging the bytes for compression warfare*.

## 10. Predictive and delta coding for geometry and transforms

Once similar records are adjacent, delta coding becomes much more effective.

The format now uses predictive schemes like:

- path index deltas for consecutive compact path nodes
- path coordinate delta mode for same-pattern paths
- transform section delta mode for consecutive transforms with matching shapes
- RGB deltas for nearby stroke colors

A number like `121` is fine.

A delta like `+3` is much better.

And when a whole stream turns into lots of tiny signed deltas, the outer compressor starts looking like a genius even though you did most of the hard work beforehand.

## 11. Colors are bytes, not strings

A lot of SVG style data is encoded in the least direct possible way.

`#00ff00` is text.
`black` is text.
`rgba(255,0,0,0.5)` is text.

The VM turns that into paint opcodes and byte payloads.

It also distinguishes:

- opaque RGB
- RGBA only when alpha is actually needed
- special cases like `none`, `inherit`, `currentColor`

That means no more shipping six-character hex strings when three bytes will do.

## 12. Then wrap the whole thing in zstd

After all the structural work, I still wanted the last layer of entropy squeezed out.

So the compiled binary gets wrapped in Zstandard.

This is important: **zstd is not the core idea**. If the binary format is bad, zstd just compresses a bad format.

The real gains came from normalizing the structure first.

But once the data is:

- deduplicated
- sectioned
- ordered for locality
- numerically tightened
- opcode-packed

…then zstd has a field day.

That is the right order of operations.

Not “throw a compressor at SVG and pray.”

First make the representation worthy of compression. Then compress it.

## The funny part: gzip is actually a very strong opponent

People underestimate how good gzip is on SVG.

SVG is repetitive text. Repetitive text is exactly what gzip eats for breakfast.

So beating raw SVG is easy.
Beating **SVGZ** is the real test.

That is why most of the work above was necessary.

You do not get 30–40% wins over gzip-compressed SVG by swapping one library call. You get there by removing structural stupidity from the data model itself.

## Current results

On the latest tracked fixtures, the compiled `svgvm` output is currently smaller than `svgz` across the board.

Here is the current snapshot:

| Fixture | SVGZ | svgvm | Improvement vs SVGZ |
|---|---:|---:|---:|
| `basic.svg` | 337 | 187 | 44.5% smaller |
| `repeated-basic.svg` | 350 | 197 | 43.7% smaller |
| `complex-paths.svg` | 761 | 442 | 41.9% smaller |
| `repeated-complex-paths.svg` | 180 | 113 | 37.2% smaller |

The important one for me is `complex-paths.svg`.

That was the annoying case. The one that kept exposing waste in path encoding, style encoding, and data ordering. Once that fixture dropped meaningfully below `svgz`, the whole project stopped being a cute trick and started becoming a serious format experiment.

## So what actually happened here?

If I had to summarize the whole project in one sentence, it would be this:

> I stopped storing SVG as prose and started storing it as intent.

That is the whole game.

SVG as text is optimized for humans, editors, diff tools, and standards committees.

SVGVM is optimized for the much more savage question:

**What is the minimum number of bytes required to say the same visual thing?**

Once you ask that question honestly, you end up doing all the things above:

- symbol tables
- pooled sections
- command/data separation
- fixed-point quantization
- specialized path opcodes
- style reuse
- delta coding
- sub-byte packing
- locality-aware ordering
- outer compression only after structural cleanup

That is how you go from “SVG is nice” to “why is this image format still spelling out `http://www.w3.org/2000/svg` like it is writing a Victorian novel?”

## The bigger lesson

This is not really just about SVG.

It is about a pattern that shows up everywhere in software.

A lot of popular formats are optimized for:

- readability
- debuggability
- interoperability
- authoring convenience

Those are good goals.

But if you care about absolute size, you eventually have to break away from the source format and build a representation that reflects the *semantics* instead of the syntax.

That is what compilers do.
That is what codecs do.
That is what this turned into.

SVG was never the final form. SVG was just the source language.

## And no, I still do not think we are done

There are still more ugly tricks left.

Things like:

- even tighter compact style packing
- more aggressive transform predictors
- command-slot predictors for path geometry
- smarter safe sibling clustering
- more specialized small-value modes

This rabbit hole does not really end. It just gets weirder.

Which, to be honest, is exactly why I like it.

:::callout{type="tip"}
The fun part of this project is that every time the assembly dump looks a little less embarrassing, the compressed size drops again.
:::

The goal was never “make SVG slightly smaller.”

The goal was to treat SVG like source code, compile it into something ruthless, and keep shaving until the remaining bytes had to justify their existence.

That is how you get from XML poetry to a tiny graphics VM.

And that is how you start turning SVG into something that has a real shot at being the most size-efficient image format in the room.
