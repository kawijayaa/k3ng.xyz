import Link from 'next/link';
import { blog } from '@/lib/source';

export default function Home() {
  const posts = blog.getPages().sort(
    (a, b) => new Date(b.data.date).getTime() - new Date(a.data.date).getTime()
  );

  return (
    <main className="grow container mx-auto max-w-5xl px-4 py-8">
      <h1 className="text-4xl font-extrabold mb-12">Blog Posts</h1>
      {posts.length === 0 ? (
        <p className="text-center text-fd-muted-foreground text-lg">
          No blog posts yet.
        </p>
      ) : (
        <div className="grid gap-10 grid-cols-2">
          {posts.map((post) => (
            <Link
              key={post.url}
              href={post.url}
              className="group flex flex-col rounded-lg shadow-md bg-fd-secondary overflow-hidden transition-shadow hover:shadow-xl"
            >
              <div className="w-full h-48 overflow-hidden rounded-t-lg">
                <img
                  src={post.data.thumbnail}
                  alt={post.data.title}
                  className="w-full h-full object-cover transition-transform duration-300 group-hover:scale-105"
                />
              </div>
              <div className="flex flex-col p-6 flex-grow gap-4">
                <div className="flex-grow">
                  <h2 className="text-2xl font-semibold mb-2 text-fd-foreground">{post.data.title}</h2>
                  <p className="mb-4 text-fd-muted-foreground line-clamp-3">{post.data.description}</p>
                </div>
                <time
                  dateTime={new Date(post.data.date).toISOString()}
                  className="text-sm text-fd-muted-foreground"
                >
                  {new Date(post.data.date).toLocaleDateString(undefined, {
                    year: "numeric",
                    month: "short",
                    day: "numeric",
                  })}
                </time>
              </div>
            </Link>
          ))}
        </div>
      )
      }
    </main >
  );
}
