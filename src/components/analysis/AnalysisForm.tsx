import { useEffect, useState, type FormEvent } from 'react';
import { Loader2, Search } from 'lucide-react';
import { detectRepository } from '../../services/analysisService';
import type { AnalysisRequest, DetectedPackage, Ecosystem } from '../../types/analysis';

const ECOSYSTEMS: { value: Ecosystem; label: string }[] = [
  { value: 'npm', label: 'npm (JavaScript)' }, { value: 'PyPI', label: 'PyPI (Python)' },
  { value: 'maven', label: 'Maven Central (Java/JVM)' }, { value: 'nuget', label: 'NuGet (.NET)' },
  { value: 'cargo', label: 'crates.io (Rust)' }, { value: 'go', label: 'Go modules' },
  { value: 'rubygems', label: 'RubyGems (Ruby)' }, { value: 'packagist', label: 'Packagist (PHP)' },
  { value: 'pub', label: 'pub.dev (Dart/Flutter)' }, { value: 'hex', label: 'Hex (Elixir/Erlang)' },
  { value: 'cocoapods', label: 'CocoaPods (Apple)' }, { value: 'swiftpm', label: 'SwiftPM (GitHub tags)' },
  { value: 'conda', label: 'Conda-forge' }, { value: 'linux', label: 'Linux packages (Debian/Alpine)' }, { value: 'oci', label: 'OCI image (Docker Hub)' },
];
const NAME_RULES: Partial<Record<Ecosystem, RegExp>> = {
  npm: /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/,
  PyPI: /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/,
  maven: /^[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+$/,
  nuget: /^[A-Za-z0-9_.-]{1,128}$/,
  cargo: /^[A-Za-z0-9_-]{1,64}$/,
  go: /^[A-Za-z0-9._~/-]{1,300}$/,
  rubygems: /^[A-Za-z0-9_-]{1,128}$/,
  packagist: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
  pub: /^[a-z][a-z0-9_]{0,62}$/,
  hex: /^[A-Za-z0-9_.-]{1,128}$/,
  cocoapods: /^[A-Za-z0-9_.+-]{1,128}$/,
  swiftpm: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/,
  conda: /^[A-Za-z0-9_.-]{1,128}$/,
  linux: /^[A-Za-z0-9_.+:-]{1,256}$/,
  oci: /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/,
};
const NPM_VERSION_RULE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PYPI_VERSION_RULE = /^(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*)?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i;
const ECOSYSTEM_HINTS: Partial<Record<Ecosystem, string>> = {
  swiftpm: 'SwiftPM release lookup uses the package GitHub owner/repository and its version tag.',
  conda: 'Conda releases are looked up on conda-forge; currently supported artifacts are .tar.bz2 packages.',
  linux: 'Use debian:package or alpine:package. Fedora/RPM packages are not available yet.',
  oci: 'Enter a public Docker Hub image name and tag, for example library/nginx and latest. Images are read as linux/amd64.',
};

function githubRepositoryRoot(value: string): string | null {
  try {
    const url = new URL(value.trim());
    const parts = url.pathname.split('/').filter(Boolean);
    if (url.protocol !== 'https:' || !['github.com', 'www.github.com'].includes(url.hostname.toLowerCase()) || url.username || url.password || url.search || url.hash || parts.length < 2) return null;
    if (parts.length > 2 && (!['tree', 'blob'].includes(parts[2]) || parts.length < 4)) return null;
    return `https://github.com/${parts[0]}/${parts[1].replace(/\.git$/, '')}`;
  } catch {
    return null;
  }
}

function validate(v: AnalysisRequest) {
  const e: Partial<Record<keyof AnalysisRequest, string>> = {};
  if (!v.name.trim()) e.name = 'Enter a package name.';
  else if (v.name.trim().length > 300 || !NAME_RULES[v.ecosystem]?.test(v.name.trim())) e.name = `Enter a valid package identifier for ${ECOSYSTEMS.find((item) => item.value === v.ecosystem)?.label ?? v.ecosystem}.`;
  if (!v.version.trim()) e.version = 'Enter a version, for example 1.2.3.';
  else if ((v.ecosystem === 'npm' && !NPM_VERSION_RULE.test(v.version.trim().replace(/^v/, ''))) || (v.ecosystem === 'PyPI' && !PYPI_VERSION_RULE.test(v.version.trim().replace(/^v/, ''))) || (v.ecosystem !== 'npm' && v.ecosystem !== 'PyPI' && !/^[A-Za-z0-9][A-Za-z0-9.+_!~:-]{0,127}$/.test(v.version.trim()))) {
    e.version = 'Enter an exact published version for the selected ecosystem.';
  }
  if (v.repoUrl.trim()) {
    if (!githubRepositoryRoot(v.repoUrl)) e.repoUrl = 'Enter a GitHub repository or directory URL, such as https://github.com/owner/repo/tree/main/packages/lib, or leave it blank to use package metadata.';
  }
  return e;
}

interface Props { onSubmit: (req: AnalysisRequest) => void; loading?: boolean }

export default function AnalysisForm({ onSubmit, loading = false }: Props) {
  const [values, setValues] = useState<AnalysisRequest>({ ecosystem: 'npm', name: '', version: '', repoUrl: '' });
  const [errors, setErrors] = useState<ReturnType<typeof validate>>({});
  const [detected, setDetected] = useState<DetectedPackage[]>([]);
  const [scanTruncated, setScanTruncated] = useState(false);
  const [detecting, setDetecting] = useState(false);
  const [detectionError, setDetectionError] = useState<string | null>(null);
  const set = (k: keyof AnalysisRequest, val: string) => setValues((p) => ({ ...p, [k]: val }));

  useEffect(() => {
    const url = values.repoUrl.trim();
    let valid = false;
    try {
      valid = githubRepositoryRoot(url) !== null;
    } catch { /* wait until the user has entered a complete URL */ }
    if (!valid) {
      setDetected([]);
      setScanTruncated(false);
      setDetectionError(null);
      setDetecting(false);
      return;
    }
    let cancelled = false;
    const timer = setTimeout(async () => {
      setDetecting(true);
      setDetectionError(null);
      try {
        const result = await detectRepository(url);
        if (!cancelled) {
          setDetected(result.packages);
          setScanTruncated(result.truncated);
        }
      } catch (e) {
        if (!cancelled) {
          setDetected([]);
          setScanTruncated(false);
          setDetectionError((e as Error).message || 'Could not inspect this GitHub repository.');
        }
      } finally {
        if (!cancelled) setDetecting(false);
      }
    }, 650);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [values.repoUrl]);

  const selectDetected = (candidate: DetectedPackage) => {
    const ecosystem = candidate.ecosystem === 'pypi' ? 'PyPI' : candidate.ecosystem as Ecosystem;
    setValues((current) => ({ ...current, ecosystem, name: candidate.name, version: candidate.version }));
  };

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
        <select id="ecosystem" className="input" value={values.ecosystem} onChange={(e) => set('ecosystem', e.target.value as Ecosystem)} disabled={loading}>
          {ECOSYSTEMS.map((ecosystem) => <option key={ecosystem.value} value={ecosystem.value}>{ecosystem.label}</option>)}
        </select>
        <p className="mt-1.5 text-xs text-muted">Choose an ecosystem or paste a GitHub URL below to scan its package manifests.</p>
        {ECOSYSTEM_HINTS[values.ecosystem] && <p className="mt-1.5 text-xs text-muted">{ECOSYSTEM_HINTS[values.ecosystem]}</p>}
      </div>
      <div className="grid gap-4 sm:grid-cols-[1fr_9rem]">
        <div>
          <label htmlFor="name" className="label">Package name</label>
          <input id="name" className="input" placeholder={values.ecosystem === 'npm' ? 'axios' : values.ecosystem === 'PyPI' ? 'requests' : values.ecosystem === 'maven' ? 'org.example:library' : values.ecosystem === 'packagist' || values.ecosystem === 'swiftpm' ? 'owner/package' : values.ecosystem === 'oci' ? 'owner/image' : values.ecosystem === 'linux' ? 'debian:curl' : 'package-name'} value={values.name} onChange={(e) => set('name', e.target.value)} {...field('name')} />
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
        <input id="repoUrl" type="url" className="input" placeholder="https://github.com/owner/repo/tree/main/packages/lib (optional)" value={values.repoUrl} onChange={(e) => set('repoUrl', e.target.value)} {...field('repoUrl')} />
        {err('repoUrl')}
        <p className="mt-1.5 text-xs text-muted">Optional. Leave blank to use the repository listed in package metadata.</p>
        {detecting && <p className="mt-2 text-xs text-muted">Scanning repository manifests…</p>}
        {detectionError && <p role="status" className="mt-2 text-xs text-muted">{detectionError}</p>}
        {scanTruncated && <p role="status" className="mt-2 text-xs text-muted">GitHub returned a partial file list for this large repository; some packages may not appear.</p>}
        {detected.length > 0 && (
          <div className="mt-3 space-y-2 rounded-lg border border-line p-3">
            <p className="text-xs font-medium">Packages detected in this repository</p>
            <div className="flex flex-wrap gap-2">
              {detected.map((candidate) => {
                const eco = candidate.ecosystem === 'pypi' ? 'PyPI' : candidate.ecosystem as Ecosystem;
                const label = ECOSYSTEMS.find((item) => item.value === eco)?.label ?? eco;
                return <button key={`${candidate.ecosystem}:${candidate.name}:${candidate.manifest}`} type="button" className="btn text-xs" onClick={() => selectDetected(candidate)} disabled={loading}>
                  {candidate.name} · {label}{candidate.version ? ` · ${candidate.version}` : ' · version needed'}
                </button>;
              })}
            </div>
          </div>
        )}
      </div>
      <button type="submit" className="btn btn-primary" disabled={loading}>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <Search className="h-4 w-4" aria-hidden />}
        {loading ? 'Analyzing…' : 'Analyze'}
      </button>
    </form>
  );
}
