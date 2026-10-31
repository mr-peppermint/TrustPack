from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class ComparisonStatus(str, Enum):
    IDENTICAL = "IDENTICAL"
    MODIFIED = "MODIFIED"
    ADDED = "ADDED"
    REMOVED = "REMOVED"
    EXPECTED_GENERATED = "EXPECTED_GENERATED"
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


class PackageInfo(BaseModel):
    name: str
    version: str


class SourceInfo(BaseModel):
    repository: Optional[str] = None
    commit: Optional[str] = None
    resolution_method: Optional[str] = None
    correspondence: CorrespondenceStatus = CorrespondenceStatus.NONE
    directory: Optional[str] = None


class IntegrityInfo(BaseModel):
    tarball_verified: Optional[bool] = None
    verification_algorithm: Optional[str] = None
    provenance_status: ProvenanceStatus = ProvenanceStatus.UNKNOWN
    registry_signature_present: Optional[bool] = None
    provenance_detail: Optional[str] = None


class ComparisonSummary(BaseModel):
    identical: int = 0
    modified: int = 0
    added: int = 0
    removed: int = 0
    expected_generated: int = 0
    unexplained: int = 0


class ComparisonEntry(BaseModel):
    path: str
    status: ComparisonStatus
    source_sha256: Optional[str] = None
    published_sha256: Optional[str] = None
    source_size: Optional[int] = None
    published_size: Optional[int] = None
    reason: Optional[str] = None


class Finding(BaseModel):
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


class AnalyzeResponse(BaseModel):
    report_id: str
    package: PackageInfo
    source: SourceInfo
    integrity: IntegrityInfo
    summary: ComparisonSummary
    risk: RiskInfo
    findings: List[Finding] = []
    comparison: List[ComparisonEntry] = []
    limitations: List[str] = []
    analysis_complete: bool
