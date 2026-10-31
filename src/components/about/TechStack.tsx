import { Hash, Layout, Package, Sparkles, Terminal, type LucideIcon } from 'lucide-react';
import SectionHeading from './SectionHeading';

const STACK: { icon: LucideIcon; name: string; role: string }[] = [
  { icon: Layout, name: 'React + Vite', role: 'Frontend' },
  { icon: Terminal, name: 'Python', role: 'Backend and analysis engine' },
  { icon: Hash, name: 'SHA-256', role: 'File integrity comparison' },
  { icon: Sparkles, name: 'GPT-OSS-120B', role: 'AI-powered explanations' },
  { icon: Package, name: 'npm and PyPI', role: 'Supported package ecosystems' },
];

export default function TechStack() {
  return (
    <section className="space-y-6">
      <SectionHeading eyebrow="Technology behind TrustPack" title="What each piece contributes" />
      <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {STACK.map(({ icon: Icon, name, role }) => (
          <li key={name} className="rounded-xl border border-line bg-panel p-4">
            <Icon className="h-5 w-5 text-accent" aria-hidden />
            <p className="mt-3 font-medium">{name}</p>
            <p className="mt-0.5 text-xs leading-relaxed text-muted">{role}</p>
          </li>
        ))}
      </ul>
    </section>
  );
}
