from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class ComparisonStatus(str, Enum):
    IDENTICAL = "IDENTICAL"
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    EXPECTED_GENERATED = "EXPECTED_GENERATED"
    # Looks like build output but could not be confidently tied to the source: never treated as safe.
    UNCERTAIN = "UNCERTAIN"
    UNEXPLAINED = "UNEXPLAINED"


class CorrespondenceStatus(str, Enum):
    EXACT = "EXACT"
    INFERRED = "INFERRED"
    NONE = "NONE"


class ProvenanceStatus(str, Enum):
    """Provenance verification outcome.

    VERIFIED is reserved for a full cryptographic chain-of-trust check
    (Fulcio certificate + Rekor transparency log), which this MVP does not
    perform (see README limitations) — so in practice this implementation
    only ever emits NOT_AVAILABLE, NOT_VERIFIED, INVALID, or UNKNOWN. The
    VERIFIED value exists so the schema does not need to change if that
    capability is added later.
    """
    VERIFIED = "VERIFIED"
    NOT_VERIFIED = "NOT_VERIFIED"
    INVALID = "INVALID"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    INCONCLUSIVE = "INCONCLUSIVE"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Verdict(str, Enum):
    """Final deterministic verdict. VERIFIED means 'no concerning differences were identified by the
    implemented checks' — never 'proven safe'."""
    VERIFIED = "VERIFIED"
    WARNING = "WARNING"
    HIGH_RISK = "HIGH_RISK"


class PackageInfo(BaseModel):
    name: str
    version: str
    ecosystem: str = "npm"


class SourceInfo(BaseModel):
    repository: Optional[str] = None
    commit: Optional[str] = None
    resolution_method: Optional[str] = None
    correspondence: CorrespondenceStatus = CorrespondenceStatus.NONE
    directory: Optional[str] = None
    confidence: Optional[str] = None
    notes: List[str] = []


class DistributionInfo(BaseModel):
    """The release artifact that was downloaded and analysed, and why it was chosen."""
    kind: str  # tarball | sdist | wheel
    filename: str
    url: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    selection_reason: str
    alternatives: List[Dict[str, Any]] = []
    published_at: Optional[str] = None


class IntegrityInfo(BaseModel):
    tarball_verified: Optional[bool] = None
    verification_algorithm: Optional[str] = None
    provenance_status: ProvenanceStatus = ProvenanceStatus.UNKNOWN
    registry_signature_present: Optional[bool] = None
    provenance_detail: Optional[str] = None
    provenance_claims: Optional[Dict[str, Any]] = None


class ComparisonSummary(BaseModel):
    identical: int = 0
    modified: int = 0
    added: int = 0
    removed: int = 0
    expected_generated: int = 0
    uncertain: int = 0
    unexplained: int = 0


class ComparisonEntry(BaseModel):
    path: str
    status: ComparisonStatus
    source_sha256: Optional[str] = None
    published_sha256: Optional[str] = None
    source_size: Optional[int] = None
    published_size: Optional[int] = None
    reason: Optional[str] = None
    # Evidence behind a generated-file classification (EXPECTED_GENERATED / UNCERTAIN).
    evidence: List[str] = []


class Finding(BaseModel):
    id: Optional[str] = None
    rule_id: str
    file: Optional[str] = None
    category: str
    severity: Severity
    confidence: Confidence
    evidence: str
    explanation: str
    recommendation: str


class RiskInfo(BaseModel):
    level: RiskLevel
    score: Optional[int] = None
    rationale: List[str] = []
    verdict: Optional[Verdict] = None
    confidence: Optional[Confidence] = None


class AIKeyFinding(BaseModel):
    file: Optional[str] = None
    explanation: str
    severity: str
    evidence_reference: str


class AIExplanationContent(BaseModel):
    summary: str
    key_findings: List[AIKeyFinding] = []
    recommended_actions: List[str] = []
    limitations: List[str] = []


class AIExplanation(BaseModel):
    """Advisory text from the language model. Kept apart from the deterministic findings and never
    used to compute the risk score or verdict."""
    status: str  # ok | disabled | unavailable | invalid_response
    provider: Optional[str] = None
    model: Optional[str] = None
    content: Optional[AIExplanationContent] = None
    error: Optional[str] = None
    dropped_references: int = 0


class AnalyzeResponse(BaseModel):
    report_id: str
    created_at: Optional[float] = None
    package: PackageInfo
    source: SourceInfo
    distribution: Optional[DistributionInfo] = None
    integrity: IntegrityInfo
    summary: ComparisonSummary
    risk: RiskInfo
    findings: List[Finding] = []
    comparison: List[ComparisonEntry] = []
    limitations: List[str] = []
    analysis_complete: bool
    ai_explanation: Optional[AIExplanation] = None
    # Present when the report was served from the shared cache: {"hit": true, "analyzed_at": <epoch>}.
    cache: Optional[Dict[str, Any]] = None
