---
title: "Turning SVG into the most size-efficient image format in the world"
description: "How I took SVG apart, treated it like source code, and kept removing repeated bytes until the compiled format beat svgz by a wide margin."
date: "2026-04-07"
tags: ["svg", "compression", "bytecode", "graphics", "compilers"]
---

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

That was the start of `svgvm`.

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

## SVG is expensive because it repeats itself

If you look at an SVG as data, the waste is not subtle.

The same attribute names appear on every sibling. The same path command patterns show up over and over. The same stroke widths and fills get restated on long runs of `<path>` elements. Numbers that would fit comfortably in a byte or two are written as several ASCII characters plus punctuation.

A browser can afford to be generous here. It is built to accept messy, verbose, irregular input.

A storage format should not be generous. It should be strict about what gets a byte and what does not.

That mindset drove every change that came after it.

## Step 1: stop paying for repeated strings

The first round of savings was straightforward.

Known tags and attributes became numeric codes. Repeated strings moved into tables. Anything common stopped being written as text over and over.

So instead of shipping `stroke-width` every time a path needs it, the file ships a small symbol. Instead of repeating `http://www.w3.org/2000/svg`, the file stores it once and refers to it.

This part is not clever, but it matters because it removes a tax that the rest of the format would otherwise keep paying.

## Step 2: split the document into sections

Early versions of the format still looked too much like the source SVG. They were binary, but they were still interleaving structure and payload in a way that was noisy.

The better layout was to separate the file into distinct sections:

- string table
- path pool
- transform pool
- node stream

And inside the path pool, split command bytes from numeric data.

That means the encoder is no longer writing something equivalent to:

- command
- numbers
- command
- numbers
- command
- numbers

It writes command streams together and numeric streams together.

That is better for two reasons.

First, it is smaller on its own because the representation gets simpler.

Second, it is easier for a general compressor to work with. Compressors like regularity. A run of similar bytes is more useful than a stream that keeps alternating between unrelated kinds of data.

## Step 3: separate path shape from path coordinates

This was one of the bigger format changes.

A path really contains two different things:

1. the command pattern
2. the numbers attached to it

For example, these paths all share the same pattern:

```text
M C S Q T L A Z
```

The coordinates differ, but the structure does not.

So `svgvm` stores path command patterns separately from path instances. Once I did that, I could stop repeating the same command stream for every similar path.

It also let me remove another chunk of useless metadata.

At one point I was storing a parallel stream of value counts for each path command. That turned out to be nonsense. The opcode already tells you the arity. A cubic curve always needs six numbers. A close-path needs none. The decoder already knows this.

So that extra bookkeeping disappeared.

## Step 4: treat coordinates like storage, not scripture

SVG files often carry far more numeric precision than the image needs.

That precision is convenient while editing, but it is expensive once the file becomes an asset.

So path coordinates moved into fixed-point storage with adaptive scaling.

In practice that means:

- coordinates are rounded
- the scale is chosen based on size, not on sentiment
- values are forced into small integer ranges wherever possible

If a control point is written as `10.5432` and `10.54` renders the same image, keeping the extra digits is just paying rent on dead precision.

Once coordinates are rounded into tighter integer ranges, two more things happen:

- the raw path payload shrinks
- delta encoding starts working much better because nearby paths stay numerically close

A lot of compression work ends up being number work.

## Step 5: give `<path>` a dedicated compact encoding

Generic element encoding is nice if you want maximum flexibility.

It is also wasteful when a file contains long runs of nearly identical `<path>` elements, which is common in real SVG art.

So `svgvm` gives `<path>` its own compact node form.

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

Once a file has dozens or hundreds of paths, that difference matters quickly.

## Step 6: reuse style across path runs

After the compact path node existed, another pattern became obvious.

A lot of neighboring paths share the same style, or almost the same style.

Maybe the fill stays `none` for a whole run. Maybe `stroke-width` is fixed. Maybe the stroke color shifts gradually instead of changing in unrelated jumps.

So the compact path encoding became stateful.

If a path can reuse style from the previous compact path node, it does. If the stroke color only changes a little, the file can store a small RGB delta instead of a full paint payload.

None of these tweaks is dramatic by itself. Together they cut a surprising amount of repetition out of path-heavy files.

## Step 7: pack small vocabularies below one byte

Once the bigger structural waste was gone, the fixed overheads started to matter more.

Path commands live in a small vocabulary. Some compact-path mode values do too. Spending a whole byte on each of them is convenient, but not justified.

So those streams got packed more tightly.

For example:

- path commands are packed into 5-bit codes
- compact path run metadata uses 4-bit values where that is enough

This is the sort of work that feels tedious when you are doing it, but it is real size reduction, and it compounds well with everything around it.

## Step 8: reorder for locality when it is safe

Two files can describe the same drawing and still behave very differently under compression.

Order matters.

If similar things sit next to each other, deltas get smaller and the outer compressor sees cleaner patterns.

So the encoder now does locality-friendly ordering in places where it is safe:

- path pools are grouped by command pattern
- paths inside a pattern group are ordered by numeric similarity
- transform pools are grouped by shape and ordered by value similarity
- some sibling runs of compact paths are reordered conservatively when the style makes that safe

That last part needs restraint because SVG draw order can affect the result.

I did not want a clever encoder that silently changes the image.

So the reordering rules stay conservative and only apply where the visual result is preserved.

## Step 9: delta-code whatever behaves predictably

Once similar records are adjacent, delta coding becomes useful.

A path index that would have been written as an absolute reference can often be stored as a small delta from the previous one. Similar paths with the same command pattern can store coordinate deltas instead of full coordinate lists. Similar transforms can do the same thing.

The current format uses delta or predictive coding in several places, including:

- path index deltas inside compact path runs
- coordinate delta mode for same-pattern paths
- transform delta mode for repeated transform shapes
- RGB deltas for nearby stroke colors

If the data becomes a stream of small signed changes instead of a stream of unrelated absolute values, the final compressor has less entropy to fight.

## Step 10: stop storing paint as text

SVG color syntax is useful for humans and bad for storage.

These are comfortable to write:

- `#00ff00`
- `black`
- `rgba(255,0,0,0.5)`

They are not efficient encodings.

Inside `svgvm`, paint becomes typed byte payloads.

That means:

- opaque colors use RGB
- alpha is stored only when it is needed
- special values like `none` and `currentColor` get dedicated representations

There is no reason to ship six hexadecimal characters when three bytes say the same thing.

## Step 11: only then compress it with zstd

The outer compression layer is Zstandard.

That helps, but it is the last step for a reason.

If the underlying representation is still noisy, switching from one general-purpose compressor to another does not solve the real problem. You just get a slightly smaller version of a messy format.

The useful work happened before zstd ever saw the file:

- deduplicate repeated structures
- separate commands from data
- tighten numeric encoding
- reuse style
- improve locality
- pack opcodes and metadata more aggressively

After that, zstd gets a much better byte stream to work with.

## Why `svgz` is the comparison that matters

Beating raw SVG is easy and not very interesting.

The real baseline is `svgz`, because gzip is already good at repetitive text, and SVG gives it plenty to work with.

That is why I ended up doing structural work instead of just playing with compressors. If you want a serious win over `svgz`, you have to remove the redundancy before the general-purpose compressor gets involved.

The format has to stop looking like source text and start looking like the drawing.

## Current results

On the current fixtures, `svgvm` beats `svgz` across the board.

| Fixture | SVGZ | svgvm | Improvement vs SVGZ |
|---|---:|---:|---:|
| `basic.svg` | 337 | 187 | 44.5% smaller |
| `repeated-basic.svg` | 350 | 197 | 43.7% smaller |
| `complex-paths.svg` | 761 | 442 | 41.9% smaller |
| `repeated-complex-paths.svg` | 180 | 113 | 37.2% smaller |

`complex-paths.svg` was the most useful one while iterating on the format.

It kept exposing the places where the representation was still sloppy: path metadata, style payloads, coordinate storage, ordering, and delta behavior. Each time that fixture refused to move, it usually meant there was still some structural waste hiding in the format.

## What the VM idea really bought me

Calling the project a VM was useful because it forced the right question.

Not "how do I zip XML a bit better?"

The real question was:

**What is the smallest representation that still describes the same drawing?**

Once you ask that, a lot of decisions become obvious:

- strings become symbols
- repeated structures become tables and pools
- paths become patterns plus numeric payloads
- generic numbers become fixed-point integers
- repeated path nodes get their own encoding
- repeated style becomes state
- predictable values become deltas
- small vocabularies get packed below a byte

That is a compiler mindset more than a markup mindset.

SVG is still the source language. It just is not the thing I want to ship anymore.

## This is not only about SVG

The same pattern shows up in a lot of formats.

Readable formats are often full of small conveniences that make authoring pleasant and storage expensive. That trade is usually correct. People need to work with the source format.

But if the job changes from authoring to distribution, you often get a better result by compiling the source format into something stricter and more specific.

That is what compilers do. That is what codecs do. This project ended up living somewhere between the two.

## There is still room left

There is still more I want to try:

- tighter compact style packing
- stronger transform predictors
- command-slot predictors for path geometry
- smarter safe sibling clustering
- more specialized small-value modes

This kind of project does not really finish. It just gets harder to find the next wasted byte.

That is fine. At this point the work is mostly about being honest.

Every byte that stays in the format should be there because it earns its keep, not because the encoder was lazy.
