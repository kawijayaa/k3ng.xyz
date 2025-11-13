import { notFound } from 'next/navigation';
import Link from 'next/link';
import { InlineTOC } from 'fumadocs-ui/components/inline-toc';
import defaultMdxComponents from 'fumadocs-ui/mdx';
import { blog } from '@/lib/source';

export default async function Page(props: PageProps<'/blog/[slug]'>) {
  const params = await props.params;
  const page = blog.getPage([params.slug]);

  if (!page) notFound();
  const Mdx = page.data.body;

  return (
    <div className='py-16'>
      <div className="container max-w-4xl pb-8 px-4">
        <h1 className="mb-3 text-4xl font-extrabold leading-tight">{page.data.title}</h1>
        <p className="mb-6 text-fd-muted-foreground text-lg">{page.data.description}</p>
        <p className="text-fd-muted-foreground">
          {new Date(page.data.date).toLocaleDateString(undefined, {
            year: "numeric",
            month: "long",
            day: "numeric",
          })}
        </p>
      </div>

      <article className="container max-w-4xl flex flex-col md:flex-row gap-12 px-4 py-4">
        <section className="flex-1 prose max-w-none min-w-0">
          <InlineTOC items={page.data.toc} />
          <Mdx components={defaultMdxComponents} />
        </section>
      </article>
    </div>
  );
}

export function generateStaticParams(): { slug: string }[] {
  return blog.getPages().map((page) => ({
    slug: page.slugs[0],
  }));
}

export async function generateMetadata(props: {
  params: Promise<{ slug: string }>;
}) {
  const params = await props.params;
  const page = blog.getPage([params.slug]);

  if (!page) notFound();

  return {
    title: page.data.title,
    description: page.data.description,
  };
}
