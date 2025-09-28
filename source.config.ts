import {
  defineCollections,
  defineConfig,
  defineDocs,
  frontmatterSchema,
  metaSchema,
} from 'fumadocs-mdx/config';
import { z } from 'zod';

// You can customise Zod schemas for frontmatter and `meta.json` here
// see https://fumadocs.dev/docs/mdx/collections#define-docs
export const writeups = defineDocs({
  dir: './content/writeups/',
  docs: {
    schema: frontmatterSchema,
  },
  meta: {
    schema: metaSchema,
  },
});

export const blogs = defineCollections({
  type: 'doc',
  dir: './content/blog/',
  schema: frontmatterSchema.extend({
    date: z.date(),
    thumbnail: z.string(),
  }),
});

export default defineConfig({
  mdxOptions: {
    // MDX options
  },
});
