---
title: "Hello World"
description: "First post on this blog. A quick test of all the features: markdown rendering, code highlighting, and custom Vue components."
date: "2026-04-06"
tags: ["meta", "test"]
---

This is the first post on this blog. It exists mainly to verify that everything works -- markdown rendering, syntax highlighting, custom components, and the overall visual design.

## Code Highlighting

Here's some TypeScript to test syntax highlighting:

```ts
interface Post {
  title: string
  date: string
  tags?: string[]
  draft?: boolean
}

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  })
}
```

And some Solidity, because why not:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SimpleStore {
    mapping(address => uint256) private balances;

    event Deposit(address indexed account, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }
}
```

## Inline Elements

Some **bold text**, some *italic text*, and some `inline code`. Here's a [link to the homepage](/).

## Blockquote

> The best way to predict the future is to invent it.
> -- Alan Kay

## Custom Components

::callout{type="tip"}
This is a tip callout rendered by a Vue component inside Markdown. MDC syntax makes this possible.
::

::callout{type="warning"}
This is a warning. Be careful out there.
::

::callout{type="info"}
This is an informational note. Nothing to worry about.
::

## Lists

Ordered:

1. First item
2. Second item
3. Third item

Unordered:

- Markdown parsing
- Syntax highlighting
- Vue components in content
- Glass aesthetic
- Sparkle background

## Table

| Feature | Status |
|---------|--------|
| Markdown | Working |
| Code highlighting | Working |
| MDC components | Working |
| Glass design | Working |
| Sparkles | Working |

---

That's it. If you're reading this, everything works.
