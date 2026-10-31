import SectionHeading from './SectionHeading';
import { stagger } from '../../lib/motion';

const TERMS: { title: string; text: string }[] = [
  { title: 'Informational use', text: 'TrustPack reports differences between a published package and its source repository. Results are provided for information only and are not a security audit.' },
  { title: 'No guarantee of safety', text: 'A clean result does not prove a package is safe, and a warning does not prove it is malicious. Findings can include false positives and false negatives.' },
  { title: 'Your responsibility', text: 'You are responsible for any decision to install, publish or trust a package. Review important findings independently before acting on them.' },
  { title: 'Data you submit', text: 'Package names, versions and repository URLs you enter are sent to the analysis backend. Do not submit confidential or private information.' },
  { title: 'AI-generated explanations', text: 'Explanations are produced by a language model, can be incomplete or wrong, and are advisory only. The risk verdict comes from the deterministic checks, not from the model.' },
  { title: 'Third-party sources', text: 'Analysis depends on public registries and source hosts such as npm, PyPI and Git repositories. Their availability and accuracy are outside our control.' },
  { title: 'Acceptable use', text: 'Do not use TrustPack to overload third-party services, to probe systems you do not own, or to analyse content you have no right to access.' },
  { title: 'No warranty', text: 'TrustPack is provided "as is" and "as available", without warranties of any kind. To the extent the law allows, its authors are not liable for losses arising from its use.' },
];

export default function Terms() {
  return (
    <section className="space-y-6">
      <SectionHeading eyebrow="Terms and conditions" title="Using TrustPack responsibly" intro="By using TrustPack you agree to the terms below." />
      <ol className="card divide-y divide-line">
        {TERMS.map(({ title, text }, i) => (
          <li key={title} style={stagger(i)} className="stagger-item flex gap-4 px-4 py-4">
            <span className="w-6 shrink-0 text-sm tabular-nums text-muted">{i + 1}.</span>
            <div>
              <h3 className="font-medium">{title}</h3>
              <p className="mt-1 text-sm leading-relaxed text-muted">{text}</p>
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
