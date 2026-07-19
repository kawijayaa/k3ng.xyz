function text(node) {
  if (node.type === 'text') return node.value;
  return node.children?.map(text).join('') ?? '';
}

export default function remarkAchievements() {
  return (tree) => {
    let section = '';

    for (const node of tree.children) {
      if (node.type === 'heading' && node.depth === 2) {
        section = text(node).toLowerCase();
        continue;
      }
      if (node.type !== 'heading' || node.depth !== 3) continue;

      if (section === 'experience') {
        node.data ??= {};
        node.data.hProperties ??= {};
        node.data.hProperties.className = 'experience';
        continue;
      }

      if (section !== 'achievements') continue;

      const title = text(node).toLowerCase();
      let rank = 'other';
      if (title.includes('winner') || title.includes('1st place')) rank = 'gold';
      else if (title.includes('2nd place')) rank = 'silver';
      else if (title.includes('3rd place')) rank = 'bronze';

      node.data ??= {};
      node.data.hProperties ??= {};
      node.data.hProperties.className = `achievement achievement-${rank}`;
    }
  };
}
