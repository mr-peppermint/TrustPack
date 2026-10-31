import { BarChart3, FileText, GitCompareArrows, Hash, PackageSearch, Sparkles, TextCursorInput, type LucideIcon } from 'lucide-react';
import SectionHeading from './SectionHeading';

const STEPS: { icon: LucideIcon; title: string; text: string }[] = [
  { icon: TextCursorInput, title: 'Package Input', text: 'You provide the package ecosystem, name, version, and source repository URL.' },
  { icon: PackageSearch, title: 'Package Retrieval', text: 'The backend retrieves the published package and the corresponding source code.' },
  { icon: Hash, title: 'File Analysis', text: 'TrustPack builds file inventories and calculates cryptographic hashes.' },
  { icon: GitCompareArrows, title: 'Comparison Engine', text: 'It identifies added, removed, modified, and unchanged files.' },
  { icon: BarChart3, title: 'Risk Assessment', text: 'Unexpected differences and relevant verification evidence are evaluated.' },
  { icon: Sparkles, title: 'AI Explanation', text: 'GPT-OSS-120B helps explain the detected differences and their potential implications, using the analysis evidence.' },
  { icon: FileText, title: 'Final Report', text: 'You receive a structured report with risk indicators and file-level findings.' },
];

export default function WorkflowSection() {
  return (
    <section className="space-y-8">
      <SectionHeading eyebrow="How TrustPack works" title="From package name to report in seven steps" />
      <ol className="grid gap-7 xl:grid-cols-7 xl:gap-3">
        {STEPS.map(({ icon: Icon, title, text }, i) => (
          <li key={title} className="relative flex gap-4 xl:flex-col xl:gap-3">
            {i < STEPS.length - 1 && (
              <span aria-hidden className="absolute -bottom-7 left-5 top-10 w-px bg-line xl:-right-3 xl:bottom-auto xl:left-10 xl:top-5 xl:h-px xl:w-auto" />
            )}
            <span className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-full border border-line bg-panel text-accent">
              <Icon className="h-[18px] w-[18px]" aria-hidden />
            </span>
            <div>
              <p className="text-xs tabular-nums text-muted">Step {i + 1}</p>
              <h3 className="font-medium">{title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-muted">{text}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
