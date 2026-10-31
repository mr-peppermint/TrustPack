export default function SectionHeading({ eyebrow, title, intro }: { eyebrow: string; title: string; intro?: string }) {
  return (
    <div className="max-w-2xl">
      <p className="eyebrow">{eyebrow}</p>
      <h2 className="mt-1.5 font-display text-2xl font-semibold tracking-tight sm:text-3xl">{title}</h2>
      {intro && <p className="mt-2 text-sm leading-relaxed text-muted sm:text-base">{intro}</p>}
    </div>
  );
}
