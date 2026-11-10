import { useState, type FormEvent } from 'react';
import { Loader2, Search } from 'lucide-react';
import type { AnalysisRequest, Ecosystem } from '../../types/analysis';

const NAME_RULES: Record<Ecosystem, RegExp> = {
  npm: /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/,
  PyPI: /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/,
};
const NPM_VERSION_RULE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PYPI_VERSION_RULE = /^(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*)?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i;

function validate(v: AnalysisRequest) {
  const e: Partial<Record<keyof AnalysisRequest, string>> = {};
  if (!v.name.trim()) e.name = 'Enter a package name.';
  else if (v.name.trim().length > 214 || !NAME_RULES[v.ecosystem].test(v.name.trim())) e.name = `Enter a valid ${v.ecosystem} package name${v.ecosystem === 'npm' ? ', such as axios or @babel/core' : ', such as requests'}.`;
  if (!v.version.trim()) e.version = 'Enter a version, for example 1.2.3.';
  else if (!(v.ecosystem === 'npm' ? NPM_VERSION_RULE : PYPI_VERSION_RULE).test(v.version.trim().replace(/^v/, ''))) {
    e.version = v.ecosystem === 'npm' ? 'Enter an exact npm version, for example 1.2.3.' : 'Enter an exact PyPI version, for example 2.32.0.';
  }
  if (v.repoUrl.trim()) {
    try {
      const u = new URL(v.repoUrl.trim());
      const parts = u.pathname.split('/').filter(Boolean);
      if (u.protocol !== 'https:' || !['github.com', 'www.github.com'].includes(u.hostname.toLowerCase()) || u.username || u.password || u.search || u.hash || parts.length !== 2 || parts.some((part) => part === '.' || part === '..')) throw new Error();
    } catch {
      e.repoUrl = 'Enter a GitHub repository link in the form https://github.com/owner/repo, or leave it blank to use package metadata.';
    }
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
          <option value="PyPI">PyPI</option>
        </select>
        <p className="mt-1.5 text-xs text-muted">Analyze a published npm or PyPI package.</p>
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
        <input id="repoUrl" type="url" className="input" placeholder="https://github.com/owner/repo (optional)" value={values.repoUrl} onChange={(e) => set('repoUrl', e.target.value)} {...field('repoUrl')} />
        {err('repoUrl')}
        <p className="mt-1.5 text-xs text-muted">Optional. Leave blank to use the repository listed in package metadata.</p>
      </div>
      <button type="submit" className="btn btn-primary" disabled={loading}>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Search className="h-4 w-4" aria-hidden />}
        {loading ? 'Analyzing…' : 'Analyze'}
      </button>
    </form>
  );
}
