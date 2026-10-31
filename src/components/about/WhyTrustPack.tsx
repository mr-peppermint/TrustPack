import { Clock, EyeOff, FileWarning, GitCompareArrows, type LucideIcon } from 'lucide-react';
import SectionHeading from './SectionHeading';
import { stagger } from '../../lib/motion';

const REASONS: { icon: LucideIcon; text: string }[] = [
  { icon: GitCompareArrows, text: 'Published packages may differ from their source code.' },
  { icon: EyeOff, text: 'Unexpected files or modifications can go unnoticed.' },
  { icon: Clock, text: 'Manual package verification is difficult and time-consuming.' },
  { icon: FileWarning, text: 'Developers need a clearer understanding of package integrity risks.' },
];

export default function WhyTrustPack() {
  return (
    <section className="space-y-6">
      <SectionHeading eyebrow="Why TrustPack?" title="The registry copy is not always the repository copy" />
      <ul className="grid gap-x-8 gap-y-5 sm:grid-cols-2">
        {REASONS.map(({ icon: Icon, text }, i) => (
          <li key={text} className="stagger-item flex items-start gap-3" style={stagger(i)}>
            <Icon className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden />
            <span className="leading-relaxed">{text}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
