import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const preservePath = ({ entry }: { entry: string }) => entry.replace(/\.md$/, '');

const blog = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './content/blog', generateId: preservePath }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    thumbnail: z.string(),
    description: z.string().optional(),
  }),
});

const writeups = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './content/writeups', generateId: preservePath }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    date: z.coerce.date().optional(),
    endDate: z.coerce.date().optional(),
    icon: z.enum(['Fingerprint', 'Globe', 'Binary', 'Server']).optional(),
    tags: z.array(z.string().regex(/^[a-z0-9.-]+$/)).min(2).max(5).optional(),
  }),
});

const pages = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './content/pages', generateId: preservePath }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
  }),
});

export const collections = { blog, writeups, pages };
