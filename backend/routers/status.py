import importlib.util
import shutil
import subprocess
from fastapi import APIRouter
from config import settings
from models import SystemStatusResponse

router = APIRouter(prefix="/api/status", tags=["System Status"])


@router.get("", response_model=SystemStatusResponse)
async def get_system_status() -> SystemStatusResponse:
    """
    Returns which integrations and tools are configured.
    Never returns actual API keys or secret values.
    """
    # 1. Telegram configuration (required for telegram forensics)
    tg_configured = bool(settings.TELEGRAM_API_ID and settings.TELEGRAM_API_HASH)

    # 2. GitHub Token (optional, raises public API rate limit)
    gh_configured = bool(settings.GITHUB_TOKEN and str(settings.GITHUB_TOKEN).strip())

    # 3. Threat Intelligence: AbuseIPDB Key (optional)
    abuse_configured = bool(settings.ABUSEIPDB_KEY and str(settings.ABUSEIPDB_KEY).strip())

    # 4. Threat Intelligence: VirusTotal Key (optional)
    vt_configured = bool(settings.VIRUSTOTAL_KEY and str(settings.VIRUSTOTAL_KEY).strip())

    # 5. Git CLI installed
    git_installed = False
    if shutil.which("git"):
        try:
            res = subprocess.run(
                ["git", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2.5,
            )
            git_installed = (res.returncode == 0)
        except Exception:
            git_installed = False

    # 6. Bandit available for static code security analysis
    bandit_available = False
    try:
        if importlib.util.find_spec("bandit") is not None or shutil.which("bandit") is not None:
            bandit_available = True
    except Exception:
        bandit_available = False

    return SystemStatusResponse(
        telegram=tg_configured,
        githubToken=gh_configured,
        abuseipdb=abuse_configured,
        virustotal=vt_configured,
        gitInstalled=git_installed,
        banditAvailable=bandit_available,
    )
