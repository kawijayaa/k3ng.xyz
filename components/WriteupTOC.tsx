import { source } from "@/lib/source"
import { flattenTree, PageTree } from "fumadocs-core/server"

export function WriteupTOC(params: { url: string }) {
  const iconsCategory = {
    'Fingerprint': 'Forensics',
    'Globe': 'Web Exploitation',
    'Binary': 'Binary Exploitation (Pwn)',
    'Server': 'Boot2Root',
  };
  const children = flattenTree(source.pageTree.children).filter(
    (child) => child.type === 'page' && child.url != params.url && child.url.startsWith(params.url)
  ) as PageTree.Item[];

  return (
    <table>
      <thead>
        <tr>
          <th>Challenge Name</th>
          <th>Category</th>
        </tr>
      </thead>
      <tbody>
        {children.map((child) => (
          <tr key={child.name}>
            <td><a href={child.url}>{child.name}</a></td>
            <td>{iconsCategory[child.icon.type.render.displayName]}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
