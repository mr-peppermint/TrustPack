import { useState, type FormEvent } from 'react';
import { Loader2, Search } from 'lucide-react';
import type { AnalysisRequest, Ecosystem } from '../../types/analysis';

const NAME_RULES: Record<Ecosystem, RegExp> = {
  npm: /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/,
  PyPI: /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/,
};
const VERSION_RULE = /^v?\d+(\.\d+)*([-+.]?[0-9A-Za-z.-]+)?$/;

function validate(v: AnalysisRequest) {
  const e: Partial<Record<keyof AnalysisRequest, string>> = {};
  if (!v.name.trim()) e.name = 'Enter a package name.';
  else if (!NAME_RULES[v.ecosystem].test(v.name.trim())) e.name = `This is not a valid ${v.ecosystem} package name.`;
  if (!v.version.trim()) e.version = 'Enter a version, for example 1.2.3.';
  else if (!VERSION_RULE.test(v.version.trim())) e.version = 'Enter a valid version, for example 1.2.3.';
  try {
    const u = new URL(v.repoUrl.trim());
    if (u.protocol !== 'https:' || u.pathname.split('/').filter(Boolean).length < 2) throw new Error();
  } catch {
    e.repoUrl = 'Enter an https repository URL, for example https://github.com/owner/repo.';
  }
  return e;
}

interface Props { onSubmit: (req: AnalysisRequest) => void; loading?: boolean }

export default function AnalysisForm({ onSubmit, loading = false }: Props) {
  const [values, setValues] = useState<AnalysisRequest>({ ecosystem: 'npm', name: '', version: '', repoUrl: '' });
  const [errors, setErrors] = useState<ReturnType<typeof validate>>({});
  const set = (k: keyof AnalysisRequest, val: string) => setValues((p) => ({ ...p, [k]: val }));

  const submit = (ev: FormEvent) => {
    ev.preventDefault();
    const found = validate(values);
    setErrors(found);
    if (Object.keys(found).length === 0) {
      onSubmit({ ...values, name: values.name.trim(), version: values.version.trim().replace(/^v/, ''), repoUrl: values.repoUrl.trim().replace(/\/$/, '') });
    }
  };

  const field = (k: keyof AnalysisRequest) => ({
    'aria-invalid': !!errors[k],
    'aria-describedby': errors[k] ? `${k}-error` : undefined,
    disabled: loading,
  });
  const err = (k: keyof AnalysisRequest) => errors[k] && <p id={`${k}-error`} className="mt-1.5 text-xs text-risk">{errors[k]}</p>;

  return (
    <form onSubmit={submit} noValidate className="card space-y-5 p-5 sm:p-6">
      <div>
        <label htmlFor="ecosystem" className="label">Ecosystem</label>
        <select id="ecosystem" className="input" value={values.ecosystem} onChange={(e) => set('ecosystem', e.target.value)} disabled={loading}>
          <option value="npm">npm</option>
          <option value="PyPI" disabled>PyPI (planned)</option>
        </select>
        <p className="mt-1.5 text-xs text-muted">The initial implementation focuses on npm packages.</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-[1fr_9rem]">
        <div>
          <label htmlFor="name" className="label">Package name</label>
          <input id="name" className="input" placeholder={values.ecosystem === 'npm' ? 'axios' : 'requests'} value={values.name} onChange={(e) => set('name', e.target.value)} {...field('name')} />
          {err('name')}
        </div>
        <div>
          <label htmlFor="version" className="label">Version</label>
          <input id="version" className="input" placeholder="1.2.3" value={values.version} onChange={(e) => set('version', e.target.value)} {...field('version')} />
          {err('version')}
        </div>
      </div>
      <div>
        <label htmlFor="repoUrl" className="label">Source repository URL</label>
        <input id="repoUrl" type="url" className="input" placeholder="https://github.com/owner/repo" value={values.repoUrl} onChange={(e) => set('repoUrl', e.target.value)} {...field('repoUrl')} />
        {err('repoUrl')}
      </div>
      <button type="submit" className="btn btn-primary" disabled={loading}>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Search className="h-4 w-4" aria-hidden />}
        {loading ? 'Analyzing…' : 'Analyze'}
      </button>
    </form>
  );
}
