import SectionHeading from './SectionHeading';
import ComparisonIllustration from './ComparisonIllustration';

const PARTS = [
  { title: 'Package Retrieval', text: 'Obtains the published package and its corresponding source.' },
  { title: 'Hashing', text: 'Uses SHA-256 hashes to identify file-content differences.' },
  { title: 'File Comparison', text: 'Detects added, removed, modified, and unchanged files.' },
  { title: 'Provenance Checks', text: 'Examines available evidence linking the package to its source and release.' },
  { title: 'Risk Assessment', text: 'Highlights suspicious or unexplained differences.' },
  { title: 'AI Explanation', text: 'Converts technical findings into understandable explanations.' },
];

export default function AnalysisEngine() {
  return (
    <section className="space-y-6">
      <SectionHeading eyebrow="Inside the analysis engine" title="Six components, one pipeline" />
      <ComparisonIllustration />
      <dl className="grid gap-x-8 gap-y-6 sm:grid-cols-2 lg:grid-cols-3">
        {PARTS.map(({ title, text }) => (
          <div key={title} className="border-t border-line pt-4">
            <dt className="font-medium">{title}</dt>
            <dd className="mt-1 text-sm leading-relaxed text-muted">{text}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
