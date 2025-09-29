import { source } from "@/lib/source"
import { flattenTree, PageTree } from "fumadocs-core/server"
import React, { ReactElement } from "react";

export function WriteupTOC(params: { url: string }) {
  type Icons = 'Fingerprint' | 'Globe' | 'Binary' | 'Server' | ""
  const iconsCategory: Record<Icons, string> = {
    'Fingerprint': 'Forensics',
    'Globe': 'Web Exploitation',
    'Binary': 'Binary Exploitation (Pwn)',
    'Server': 'Boot2Root',
    '': '',
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
        {children.map((child) => {
          let icon: ReactElement | undefined;
          let iconName: Icons = "";

          if (React.isValidElement(child.icon)) {
            icon = child.icon;

            const type = icon.type as any;

            if (type?.render?.displayName) {
              iconName = type.render.displayName as Icons;
            }
          }

          return (
            <tr key={child.url}>
              <td><a href={child.url}>{child.name}</a></td>
              <td>{iconsCategory[iconName]}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
