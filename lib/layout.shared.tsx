import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';

/**
 * Shared layout configurations
 *
 * you can customise layouts individually from:
 * Home Layout: app/(home)/layout.tsx
 * Docs Layout: app/docs/layout.tsx
 */
export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <>
          <img
            width="28"
            height="28"
            className="rounded-full"
            src="/profile.png"
          />
          k3ng
        </>
      ),
    },
    // see https://fumadocs.dev/docs/ui/navigation/links
    links: [
      {
        text: 'About',
        url: '/about'
      },
      {
        text: 'Writeups',
        url: '/writeups'
      },
      {
        text: 'Blog',
        url: '/blog'
      },
      {
        text: 'Challenge Archive',
        url: 'https://github.com/kawijayaa/ctf-challenges'
      }
    ],
  };
}
