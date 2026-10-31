const ROWS = [
  { source: 'src/index.js', pkg: 'src/index.js', label: 'Unchanged', note: 'same hash', cls: 'text-ok' },
  { source: 'package.json', pkg: 'package.json', label: 'Modified', note: 'different hash', cls: 'text-warn' },
  { source: null, pkg: 'scripts/setup.js', label: 'Added', note: 'only in the package', cls: 'text-warn' },
  { source: 'docs/guide.md', pkg: null, label: 'Removed', note: 'only in the source', cls: 'text-muted' },
] as const;

const File = ({ name }: { name: string | null }) =>
  name ? <span className="font-mono text-[13px]">{name}</span> : <span className="text-muted/60" aria-label="not present">—</span>;

export default function ComparisonIllustration() {
  return (
    <figure className="card overflow-hidden">
      <div className="grid grid-cols-[1fr_auto_1fr] items-center gap-x-4 border-b border-line bg-sunken/60 px-4 py-2.5 text-xs uppercase tracking-wide text-muted">
        <span>Source repository</span>
        <span className="text-center">Result</span>
        <span className="text-right">Published package</span>
      </div>
      <ul className="divide-y divide-line">
        {ROWS.map((r) => (
          <li key={r.pkg ?? r.source} className="grid grid-cols-[1fr_auto_1fr] items-center gap-x-4 px-4 py-3">
            <File name={r.source} />
            <span className="min-w-28 text-center">
              <span className={`block text-sm font-medium ${r.cls}`}>{r.label}</span>
              <span className="hidden text-xs text-muted sm:block">{r.note}</span>
            </span>
            <span className="text-right"><File name={r.pkg} /></span>
          </li>
        ))}
      </ul>
      <figcaption className="border-t border-line px-4 py-2.5 text-xs text-muted">Illustration with example file names. Files are matched by path, then compared by SHA-256 hash.</figcaption>
    </figure>
  );
}
