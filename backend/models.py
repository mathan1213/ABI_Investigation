from typing import Literal, Optional, List
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
# 4. Health Check Model
# ---------------------------------------------------------------------------

class HealthResponse(AppBaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    environment: str = "development"
