import { Fragment, useState } from 'react';
import { ChevronRight } from 'lucide-react';
import { RiskDot } from '../common/StatusBadge';
import type { FileChange, RiskLevel } from '../../types/analysis';

const ORDER: Record<RiskLevel, number> = { high: 0, medium: 1, low: 2, none: 3 };
const TYPE_CLS = { added: 'text-warn', removed: 'text-muted', modified: 'text-fg', unchanged: 'text-muted' };

function Diff({ text }: { text: string }) {
  return (
    <pre className="overflow-x-auto rounded-lg border border-line bg-sunken py-2 font-mono text-xs leading-5">
      {text.split('\n').map((line, i) => {
        const cls = line.startsWith('+') ? 'bg-ok/10 text-ok' : line.startsWith('-') ? 'bg-risk/10 text-risk' : 'text-muted';
        return <code key={i} className={`block min-w-max px-3 ${cls}`}>{line || ' '}</code>;
      })}
    </pre>
  );
}

export default function FileChangesTable({ files }: { files: FileChange[] }) {
  const [open, setOpen] = useState<string | null>(null);
  const rows = [...files].sort((a, b) => ORDER[a.risk] - ORDER[b.risk]);

  return (
    <div className="card overflow-x-auto">
      <table className="w-full min-w-[32rem] text-left text-sm">
        <thead className="bg-sunken/60 text-xs uppercase tracking-wide text-muted">
          <tr>
            <th className="px-4 py-3 font-medium">File</th>
            <th className="px-4 py-3 font-medium">Change</th>
            <th className="px-4 py-3 font-medium">Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((file) => {
            const isOpen = open === file.path;
            return (
              <Fragment key={file.path}>
                <tr className="border-t border-line">
                  <td className="px-4 py-3">
                    <button type="button" aria-expanded={isOpen} onClick={() => setOpen(isOpen ? null : file.path)} className="flex items-center gap-2 rounded font-mono text-[13px] hover:text-accent">
                      <ChevronRight className={`h-4 w-4 shrink-0 transition-transform ${isOpen ? 'rotate-90' : ''}`} aria-hidden />
                      {file.path}
                    </button>
                  </td>
                  <td className={`px-4 py-3 capitalize ${TYPE_CLS[file.changeType]}`}>{file.changeType}</td>
                  <td className="px-4 py-3"><RiskDot level={file.risk} /></td>
                </tr>
                {isOpen && (
                  <tr className="border-t border-line bg-sunken/50">
                    <td colSpan={3} className="space-y-3 px-4 py-4">
                      <p className="text-sm text-muted">{file.reason ?? (file.changeType === 'unchanged' ? 'This file is identical in the package and the repository.' : 'No notes for this file.')}</p>
                      {file.diff && <Diff text={file.diff} />}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
