from typing import Any, Literal, Optional, List
from pydantic import BaseModel, ConfigDict, Field

RiskLevel = Literal["low", "medium", "high", "critical"]
VerdictType = Literal["Safe", "Suspicious", "Dangerous"]
PortStateType = Literal["Open", "Closed", "Filtered"]
HeaderStatusType = Literal["Pass", "Fail"]

class AppBaseModel(BaseModel):
    """Base model that allows population by both field name and camelCase alias."""
    model_config = ConfigDict(
        populate_by_name=True,
        serialize_by_alias=True
    )


# ---------------------------------------------------------------------------
# 1. IP Check Models
# ---------------------------------------------------------------------------

class IpCheckRequest(AppBaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to check", examples=["8.8.8.8"])


class IpCheckResponse(AppBaseModel):
    ip: str
    country: str
    city: str
    isp: str
    asn: str
    is_vpn: bool = Field(..., alias="isVpn")
    is_proxy: bool = Field(..., alias="isProxy")
    is_tor: bool = Field(..., alias="isTor")
    is_hosting: bool = Field(default=False, alias="isHosting")
    abuse_score: int = Field(..., alias="abuseScore", ge=0, le=100)
    verdict: VerdictType
    risk_level: RiskLevel = Field(..., alias="riskLevel")
    explanation: str
    timestamp: str
    source: str = "live"


# ---------------------------------------------------------------------------
# 2. Link Check Models
# ---------------------------------------------------------------------------

class LinkCheckRequest(AppBaseModel):
    url: str = Field(..., description="Full URL with http/https", examples=["https://example.com/login"])


class RedirectHop(AppBaseModel):
    step: int
    url: str
    status: int
    note: Optional[str] = None


class DnsRecords(AppBaseModel):
    a: List[str] = Field(default_factory=list)
    mx: List[str] = Field(default_factory=list)
    txt: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)


class LinkCheckResponse(AppBaseModel):
    url: str
    domain: str
    domain_age: str = Field(..., alias="domainAge")
    domain_age_days: Optional[int] = Field(default=None, alias="domainAgeDays")
    dns_records: DnsRecords = Field(..., alias="dnsRecords")
    ssl_valid: bool = Field(..., alias="sslValid")
    ssl_issuer: Optional[str] = Field(default=None, alias="sslIssuer")
    ssl_expires_on: Optional[str] = Field(default=None, alias="sslExpiresOn")
    redirect_chain: List[RedirectHop] = Field(default_factory=list, alias="redirectChain")
    reputation_score: int = Field(..., alias="reputationScore", ge=0, le=100)
    verdict: VerdictType
    risk_level: RiskLevel = Field(..., alias="riskLevel")
    explanation: str
    timestamp: str


# ---------------------------------------------------------------------------
# 3. Website Check Models
# ---------------------------------------------------------------------------

class WebsiteCheckRequest(AppBaseModel):
    domain: str = Field(..., description="Website domain or hostname", examples=["google.com"])


class PortCheck(AppBaseModel):
    port: int
    service: str
    state: PortStateType
    risk: RiskLevel
    note: str


class SecurityHeaderCheck(AppBaseModel):
    header: str
    status: HeaderStatusType
    description: str


class WebsiteCheckResponse(AppBaseModel):
    domain: str
    ports: List[PortCheck]
    open_ports: List[int] = Field(default_factory=list, alias="openPorts")
    ssl_expiry: str = Field(..., alias="sslExpiry")
    ssl_expires_on: Optional[str] = Field(default=None, alias="sslExpiresOn")
    ssl_days_remaining: int = Field(..., alias="sslDaysRemaining")
    security_headers: List[SecurityHeaderCheck] = Field(..., alias="securityHeaders")
    risk_score: int = Field(..., alias="riskScore", ge=0, le=100)
    risk_level: RiskLevel = Field(..., alias="riskLevel")
    verdict: VerdictType
    explanation: str
    timestamp: str


# ---------------------------------------------------------------------------
# 4. Repo Check Models
# ---------------------------------------------------------------------------

RepoFindingCategory = Literal["secrets", "dependencies", "code", "network"]

class RepoFinding(AppBaseModel):
    id: str
    category: RepoFindingCategory
    severity: RiskLevel
    title: str
    file_path: str = Field(..., alias="filePath")
    line_number: int = Field(..., alias="lineNumber")
    explanation: str
    suggested_fix: str = Field(..., alias="suggestedFix")
    code_snippet: Optional[str] = Field(default=None, alias="codeSnippet")


class FindingCounts(AppBaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    total: int = 0


class RepoScanRequest(AppBaseModel):
    repo_url: str = Field(..., alias="repoUrl", description="GitHub repository URL", examples=["https://github.com/owner/repository"])


class RepoScanResponse(AppBaseModel):
    repo_url: str = Field(..., alias="repoUrl")
    repo_name: str = Field(..., alias="repoName")
    risk_score: int = Field(..., alias="riskScore", ge=0, le=100)
    risk_level: RiskLevel = Field(..., alias="riskLevel")
    summary: str
    counts: FindingCounts
    findings: List[RepoFinding]
    timestamp: str
    branch: str = "main"
    scanned_files_count: int = Field(default=0, alias="scannedFilesCount")


# ---------------------------------------------------------------------------
# 5. Telegram Check Models
# ---------------------------------------------------------------------------

TelegramFindingType = Literal[
    "unknown_device",
    "foreign_login",
    "impossible_travel",
    "no_2fa",
    "suspicious_link",
]

class TelegramSession(AppBaseModel):
    id: str
    device: str
    app: str
    ip: str
    country: str
    last_active: str = Field(..., alias="lastActive")
    is_suspicious: bool = Field(..., alias="isSuspicious")
    is_current: Optional[bool] = Field(default=None, alias="isCurrent")
    flag_note: Optional[str] = Field(default=None, alias="flagNote")


class TelegramFinding(AppBaseModel):
    id: str
    type: TelegramFindingType
    title: str
    explanation: str
    risk: RiskLevel
    date: Optional[str] = None


class TelegramScanResult(AppBaseModel):
    phone: str
    account_name: str = Field(..., alias="accountName")
    risk_score: int = Field(..., alias="riskScore", ge=0, le=100)
    risk_level: RiskLevel = Field(..., alias="riskLevel")
    summary: str
    sessions: List[TelegramSession]
    findings: List[TelegramFinding]
    how_it_happened: str = Field(..., alias="howItHappened")
    action_checklist: List[str] = Field(..., alias="actionChecklist")
    timestamp: str
    two_factor_enabled: bool = Field(..., alias="twoFactorEnabled")


class TelegramSendCodeRequest(AppBaseModel):
    phone: str = Field(..., description="Phone number in international E.164 format (+1234567890)")


class TelegramSendCodeResponse(AppBaseModel):
    flow_id: str = Field(..., alias="flowId")
    message: str = "Verification code requested from Telegram"


class TelegramVerifyRequest(AppBaseModel):
    flow_id: str = Field(..., alias="flowId")
    code: str
    password: Optional[str] = None


class TelegramVerifyResponse(AppBaseModel):
    status: str
    flow_id: str = Field(..., alias="flowId")
    needs_password: bool = Field(default=False, alias="needsPassword")


class TelegramAnalyzeRequest(AppBaseModel):
    flow_id: str = Field(..., alias="flowId")


class TelegramCancelRequest(AppBaseModel):
    flow_id: str = Field(..., alias="flowId")


class TelegramCancelResponse(AppBaseModel):
    status: str = "cancelled"


# ---------------------------------------------------------------------------
# 6. Report Generation Models
# ---------------------------------------------------------------------------

class NetworkScanInput(AppBaseModel):
    ip_result: Optional[IpCheckResponse] = Field(default=None, alias="ipResult")
    link_result: Optional[LinkCheckResponse] = Field(default=None, alias="linkResult")
    website_result: Optional[WebsiteCheckResponse] = Field(default=None, alias="websiteResult")


class GenerateReportRequest(AppBaseModel):
    telegram: Optional[TelegramScanResult] = None
    repo: Optional[RepoScanResponse] = None
    network: Optional[Any] = None
    demo_modules: List[str] = Field(default_factory=list, alias="demoModules")


class ModuleScore(AppBaseModel):
    module: str
    name: str
    scanned: bool
    score: Optional[int] = None
    risk_level: Optional[RiskLevel] = Field(default=None, alias="riskLevel")
    is_demo: bool = Field(default=False, alias="isDemo")
    details: Optional[str] = None


class NetworkFindingItem(AppBaseModel):
    id: str
    source: str
    title: str
    detail: str
    severity: RiskLevel
    target: Optional[str] = None


class ActionPlanItem(AppBaseModel):
    id: int
    title: str
    detail: str
    priority: RiskLevel
    completed: bool = False


class ConnectedAccountItem(AppBaseModel):
    name: str
    service: str
    connected_at: str = Field(..., alias="connectedAt")
    status: str
    is_demo: bool = Field(default=False, alias="isDemo")


class GenerateReportResponse(AppBaseModel):
    id: str
    generated_at: str = Field(..., alias="generatedAt")
    overall_score: Optional[int] = Field(default=None, alias="overallScore", ge=0, le=100)
    overall_risk: Optional[RiskLevel] = Field(default=None, alias="overallRisk")
    summary: str
    how_it_happened: List[str] = Field(default_factory=list, alias="howItHappened")
    what_to_do_now: List[ActionPlanItem] = Field(default_factory=list, alias="whatToDoNow")
    action_plan: List[ActionPlanItem] = Field(default_factory=list, alias="actionPlan")
    modules: List[ModuleScore]
    network_findings: List[NetworkFindingItem] = Field(default_factory=list, alias="networkFindings")
    limitations: List[str]
    methodology: str
    demo_modules: List[str] = Field(default_factory=list, alias="demoModules")
    telegram: Optional[TelegramScanResult] = None
    repo: Optional[RepoScanResponse] = None
    network: Optional[Any] = None
    connected_accounts: List[ConnectedAccountItem] = Field(default_factory=list, alias="connectedAccounts")


# ---------------------------------------------------------------------------
# 7. System Health & Configuration Status Models
# ---------------------------------------------------------------------------

class SystemStatusResponse(AppBaseModel):
    telegram: bool = Field(..., description="Whether Telegram API credentials are configured")
    github_token: bool = Field(..., alias="githubToken", description="Whether optional GitHub token is configured")
    abuseipdb: bool = Field(..., description="Whether optional AbuseIPDB API key is configured")
    virustotal: bool = Field(..., description="Whether optional VirusTotal API key is configured")
    git_installed: bool = Field(..., alias="gitInstalled", description="Whether Git CLI is installed and available")
    bandit_available: bool = Field(..., alias="banditAvailable", description="Whether Bandit SAST analyzer is available")


class HealthResponse(AppBaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    environment: str = "development"
