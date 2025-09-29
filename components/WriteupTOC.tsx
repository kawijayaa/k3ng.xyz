import { source } from "@/lib/source"
import { flattenTree, PageTree } from "fumadocs-core/server"
import { Binary, Fingerprint, Globe, Server } from "lucide-react";
import React, { ReactElement } from "react";

export function WriteupTOC(params: { url: string }) {
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
          var iconName;
          if (React.isValidElement(child.icon) && child.icon.type === Fingerprint) {
            iconName = 'Forensics'
          }
          if (React.isValidElement(child.icon) && child.icon.type === Binary) {
            iconName = 'Binary Exploitation (Pwn)'
          }
          if (React.isValidElement(child.icon) && child.icon.type === Globe) {
            iconName = 'Web Exploitation'
          }
          if (React.isValidElement(child.icon) && child.icon.type === Server) {
            iconName = 'Boot2Root'
          }

          return (
            <tr key={child.url}>
              <td><a href={child.url}>{child.name}</a></td>
              <td>{iconName}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  )
}
