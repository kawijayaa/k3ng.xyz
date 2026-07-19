import { unified } from '@astrojs/markdown-remark';
import { defineConfig } from 'astro/config';
import { remarkAlert } from 'remark-github-blockquote-alert';
import remarkAchievements from './src/lib/remark-achievements.mjs';

export default defineConfig({
  vite: {
    build: {
      chunkSizeWarningLimit: 550,
    },
  },
  markdown: {
    processor: unified({
      remarkPlugins: [remarkAchievements, [remarkAlert, { tagName: 'blockquote' }]],
    }),
    shikiConfig: {
      theme: 'github-dark-default',
      wrap: true,
    },
  },
});
