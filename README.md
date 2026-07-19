# k3ng.xyz

A static, Markdown-first personal website built with Astro.

## Develop

```bash
npm install
npm run dev
```

## Add content

- Add blog posts to `content/blog/<slug>.md`.
- Add writeups to `content/writeups/<year>/<competition>/<slug>.md`.
- Use `index.md` inside a competition directory for its landing page.
- Put images in `public/images` and reference them as `/images/...`.

Blog frontmatter:

```yaml
---
title: Post title
date: 2026-07-18
thumbnail: /images/example/thumbnail.jpg
description: A short summary.
---
```

Writeup frontmatter:

```yaml
---
title: Challenge name
icon: Fingerprint
tags: [memory-forensics, volatility, process-memory]
---
```

Supported writeup icons are `Fingerprint` (forensics), `Globe` (web), `Binary` (pwn), and `Server` (Boot2Root). Add two to five lowercase technique or technology tags. Navigation and listing pages are generated from the directory structure.
