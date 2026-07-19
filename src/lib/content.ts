import type { CollectionEntry } from 'astro:content';

export const cleanId = (id: string) => id.replace(/\.md$/, '');

export const writeupPath = (entry: CollectionEntry<'writeups'>) => {
  const id = cleanId(entry.id).replace(/\/index$/, '');
  return id === 'index' ? '/writeups' : `/writeups/${id}`;
};

export const categoryNames: Record<string, string> = {
  Fingerprint: 'Forensics',
  Globe: 'Web exploitation',
  Binary: 'Binary exploitation',
  Server: 'Boot2Root',
};

export const formatDate = (date: Date) =>
  new Intl.DateTimeFormat('en', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  }).format(date);
