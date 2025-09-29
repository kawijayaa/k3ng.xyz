import { source } from '@/lib/source';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
} from 'fumadocs-ui/page';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { createRelativeLink } from 'fumadocs-ui/mdx';
import { getMDXComponents } from '@/mdx-components';
import { flattenTree } from 'fumadocs-core/server';
import React, { ReactElement } from 'react';

export default async function Page(props: PageProps<'/writeups/[[...slug]]'>) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const pageItem = flattenTree(source.pageTree.children).filter(
    (item) => item.type === 'page' && item.url === page.url
  )[0]

  const MDXContent = page.data.body;
  const footerOptions = {
    enabled: false
  }

  var icon: any;
  if (pageItem) {
    icon = pageItem.icon ? React.cloneElement(pageItem.icon as any, {
      width: undefined,
      height: undefined,
    }) : null
  } else {
    icon = null
  }

  return (
    <DocsPage toc={page.data.toc} full={page.data.full} footer={footerOptions}>
      <DocsTitle className="font-black text-4xl flex items-center gap-3">
        {icon ? (
          <div className="size-8 md:size-10">
            {icon}
          </div>
        ) : (
          <></>
        )}
        {page.data.title}
      </DocsTitle>
      <DocsDescription>{page.data.description}</DocsDescription>
      <DocsBody>
        <MDXContent
          components={getMDXComponents({
            a: createRelativeLink(source, page),
          })}
        />
      </DocsBody>
    </DocsPage >
  );
}

export async function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(
  props: PageProps<'/writeups/[[...slug]]'>,
): Promise<Metadata> {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  return {
    title: page.data.title,
    description: page.data.description,
  };
}
