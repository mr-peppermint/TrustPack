import { Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import Wordmark from '../common/Wordmark';
import { after, heroDelay } from '../../lib/motion';

export default function AboutHero() {
  const d = heroDelay;
  return (
    <section className="relative isolate overflow-hidden border-b border-line pb-12 pt-4">
      <p className="eyebrow animate-rise" style={after(d)}>About TrustPack</p>
      <Wordmark className="mt-3 text-[2.5rem] min-[400px]:text-5xl sm:text-7xl lg:text-8xl xl:text-9xl" delay={d + 0.1} />
      <p className="mt-5 max-w-2xl animate-rise font-display text-2xl font-semibold tracking-tight sm:text-3xl" style={after(d + 0.7)}>Understand What You Install.</p>
      <div className="mt-5 max-w-2xl animate-rise space-y-3 leading-relaxed text-muted" style={after(d + 0.85)}>
        <p>
          TrustPack is a software supply-chain security tool that compares published packages and container images with corresponding source repositories across supported ecosystems.
        </p>
        <p>
          The core problem: a published package can contain changes that are not present in its source repository. Reading the repository does not tell you what the registry actually ships.
        </p>
      </div>
      <Link to="/new" className="btn btn-primary group mt-6 animate-rise" style={after(d + 1)}>
        Start an analysis<ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" aria-hidden />
      </Link>
    </section>
  );
}
