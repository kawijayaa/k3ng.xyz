function text(node) {
  if (node.type === 'text') return node.value;
  return node.children?.map(text).join('') ?? '';
}

function container(tag, className, children) {
  return {
    type: 'blockquote',
    data: { hName: tag, hProperties: { className } },
    children,
  };
}

// Structure profile sections at render time; the authored Markdown stays intact.
export default function remarkAchievements() {
  return (tree) => {
    const output = [];
    for (let index = 0; index < tree.children.length; index++) {
      const node = tree.children[index];
      const section = node.type === 'heading' && node.depth === 2 ? text(node).toLowerCase() : '';
      if (section !== 'experience' && section !== 'achievements') {
        output.push(node);
        continue;
      }

      const entries = [];
      let entry;
      while (index + 1 < tree.children.length) {
        const next = tree.children[index + 1];
        if (next.type === 'heading' && next.depth <= 2) break;
        index++;
        if (next.type === 'heading' && next.depth === 3) {
          let rank = 'other';
          const title = text(next).toLowerCase();
          if (title.includes('winner') || title.includes('1st place')) rank = 'gold';
          else if (title.includes('2nd place')) rank = 'silver';
          else if (title.includes('3rd place')) rank = 'bronze';
          entry = container('section', `profile-entry ${section === 'experience' ? 'experience-entry' : `award-entry award-${rank}`}`, [next]);
          entries.push(entry);
        } else if (entry) {
          entry.children.push(next);
        } else {
          entries.push(next);
        }
      }
      output.push(container('section', `profile-section profile-${section}`, [
        node,
        container('div', 'profile-entries', entries),
      ]));
    }
    tree.children = output;
  };
}
