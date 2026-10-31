import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';

export default function AboutHero() {
  return (
    <section className="border-b border-line pb-10">
      <p className="eyebrow">About TrustPack</p>
      <h2 className="mt-2 max-w-2xl font-display text-4xl font-semibold tracking-tight sm:text-5xl">Understand What You Install.</h2>
      <div className="mt-5 max-w-2xl space-y-3 leading-relaxed text-muted">
        <p>
          TrustPack is a software supply-chain security tool that compares published npm and PyPI packages with their corresponding source repositories.
        </p>
        <p>
          The core problem: a published package can contain changes that are not present in its source repository. Reading the repository does not tell you what the registry actually ships.
        </p>
      </div>
      <Link to="/new" className="btn btn-primary mt-6">Start an analysis<ArrowRight className="h-4 w-4" aria-hidden /></Link>
    </section>
  );
}
