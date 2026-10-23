import {
  TelegramScanResult,
  RepoScanResult,
  IpCheckResult,
  LinkCheckResult,
  WebsiteCheckResult,
  FullReport,
} from './types';

// API Base URL constant for future connection to the Python FastAPI backend
export const API_BASE = "http://localhost:8000";

// Helper delay simulating network latency (1.2 to 1.8 seconds)
const wait = (ms = 1400) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Analyzes a Telegram account for suspicious logins, unexpected sessions, and security weaknesses.
 * Backend equivalent: POST /api/v1/telegram/analyze { phone, otp }
 */
export async function analyzeTelegram(phone: string, otp: string): Promise<TelegramScanResult> {
  await wait(1600);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/telegram/analyze`, {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify({ phone, otp }),
  // });
  // if (!res.ok) throw new Error('Failed to analyze Telegram account');
  // return await res.json();

  const isDemoClean = phone.endsWith('0000');

  if (isDemoClean) {
    return {
      phone,
      accountName: "Alex Rivera",
      riskScore: 12,
      riskLevel: "low",
      summary: "Your Telegram account looks safe. All active logins are from your own devices in your home region.",
      twoFactorEnabled: true,
      timestamp: new Date().toISOString(),
      sessions: [
        {
          id: 'sess-1',
          device: 'Apple iPhone 15 Pro',
          app: 'Telegram iOS 10.8',
          ip: '198.51.100.24',
          country: 'United States',
          lastActive: 'Just now',
          isSuspicious: false,
          isCurrent: true,
          flagNote: 'Current device',
        },
        {
          id: 'sess-2',
          device: 'MacBook Pro 16" M3',
          app: 'Telegram Desktop 4.16',
          ip: '198.51.100.24',
          country: 'United States',
          lastActive: '3 hours ago',
          isSuspicious: false,
        }
      ],
      findings: [
        {
          id: 'find-clean-1',
          type: 'no_2fa',
          title: 'Two-Step Verification is Active',
          explanation: 'Your account has an extra password set up, protecting you even if someone intercepts an SMS code.',
          risk: 'low',
        }
      ],
      howItHappened: "No compromise detected. Your devices match your standard location, and two-step verification is active.",
      actionChecklist: [
        "Keep Two-Step Verification enabled.",
        "Review your active sessions once every month.",
        "Never share login verification codes with anyone, including people claiming to be Telegram Support."
      ]
    };
  }

  // Realistic breach scenario
  return {
    phone,
    accountName: "Alex Rivera (@arivera)",
    riskScore: 78,
    riskLevel: "critical",
    summary: "Someone logged into your Telegram account from another country without your permission, and your account lacks two-step password protection.",
    twoFactorEnabled: false,
    timestamp: new Date().toISOString(),
    sessions: [
      {
        id: 'sess-1',
        device: 'Apple iPhone 15 Pro',
        app: 'Telegram iOS 10.8',
        ip: '73.189.44.12',
        country: 'United States (California)',
        lastActive: 'Just now',
        isSuspicious: false,
        isCurrent: true,
        flagNote: 'Your current device',
      },
      {
        id: 'sess-2',
        device: 'Linux PC / Ubuntu',
        app: 'Telegram Desktop 4.9.2 (Old version)',
        ip: '185.220.101.5',
        country: 'Germany (Frankfurt am Main)',
        lastActive: '42 minutes ago',
        isSuspicious: true,
        flagNote: 'Unknown device in a foreign country',
      },
      {
        id: 'sess-3',
        device: 'Samsung Galaxy A12',
        app: 'Telegram Android 10.2',
        ip: '91.240.118.88',
        country: 'Netherlands (Amsterdam)',
        lastActive: 'Yesterday at 11:15 PM',
        isSuspicious: true,
        flagNote: 'Impossible travel: logged in 20 minutes after California',
      }
    ],
    findings: [
      {
        id: 'tg-1',
        type: 'unknown_device',
        title: 'Unknown Computer Logged In',
        explanation: 'A computer running Linux in Frankfurt, Germany logged into your account 42 minutes ago. If this was not you or your VPN, someone else has your chats.',
        risk: 'critical',
        date: '42 minutes ago',
      },
      {
        id: 'tg-2',
        type: 'foreign_login',
        title: 'Login from Another Country',
        explanation: 'We detected access from Germany and the Netherlands, while your main phone is active in the United States.',
        risk: 'high',
        date: 'Today',
      },
      {
        id: 'tg-3',
        type: 'impossible_travel',
        title: 'Physically Impossible Travel Detected',
        explanation: 'Your account was used in California and Amsterdam just 20 minutes apart. A person cannot travel that fast, meaning two different people were logged in.',
        risk: 'critical',
        date: 'Yesterday',
      },
      {
        id: 'tg-4',
        type: 'no_2fa',
        title: 'Two-Step Verification is Turned Off',
        explanation: 'Your account is only guarded by SMS text codes. If someone steals or intercepts your text code, they can take over your account immediately.',
        risk: 'high',
      },
      {
        id: 'tg-5',
        type: 'suspicious_link',
        title: 'Suspicious Bot Authorization Found',
        explanation: 'An external automation bot with broad message-reading permissions was linked to your profile.',
        risk: 'medium',
      }
    ],
    howItHappened: "An intruder likely intercepted or tricked you into providing an SMS login code (or intercepted it via an infected app), then logged in from a remote server. Because no two-step password was set, they gained instant access to your chats and contacts.",
    actionChecklist: [
      "Open Telegram Settings > Devices > Tap 'Terminate all other sessions' immediately.",
      "Turn on Two-Step Verification right now: Settings > Privacy and Security > Two-Step Verification.",
      "Check your Telegram cloud chat backups and saved messages for any sensitive passwords or photos.",
      "Warn close friends or family if the intruder may have sent them phishing requests posing as you."
    ]
  };
}

/**
 * Scans a public GitHub repository for leaked passwords, API keys, vulnerable packages, and unsafe code.
 * Backend equivalent: POST /api/v1/repo/scan { repo_url }
 */
export async function scanRepo(repoUrl: string): Promise<RepoScanResult> {
  await wait(1800);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/repo/scan`, {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify({ repo_url: repoUrl }),
  // });
  // return await res.json();

  const repoName = repoUrl.replace(/^https?:\/\/github\.com\//i, '').replace(/\/$/, '') || 'my-project/api-backend';

  return {
    repoUrl,
    repoName,
    riskScore: 72,
    riskLevel: 'high',
    summary: 'We found an exposed API password in a public file, an outdated software component with known security flaws, and an insecure web connection.',
    branch: 'main',
    scannedFilesCount: 84,
    timestamp: new Date().toISOString(),
    counts: {
      critical: 1,
      high: 2,
      medium: 1,
      low: 1,
      total: 5,
    },
    findings: [
      {
        id: 'repo-1',
        category: 'secrets',
        severity: 'critical',
        title: 'Secret API Password Left in Code',
        filePath: 'config/settings.py',
        lineNumber: 42,
        explanation: 'A live Stripe API secret key was written directly into this file. Anyone browsing this public repository can copy it and charge cards or access customer billing.',
        suggestedFix: 'Revoke this API key inside your Stripe Dashboard immediately. Move secrets into private environment variables (.env) and add .env to your .gitignore file.',
        codeSnippet: 'STRIPE_SECRET_KEY = "sk_test_mock_secret_key_placeholder..."',
      },
      {
        id: 'repo-2',
        category: 'dependencies',
        severity: 'high',
        title: 'Vulnerable "requests" Library (Security Bug CVE-2023-32681)',
        filePath: 'requirements.txt',
        lineNumber: 14,
        explanation: 'This project uses an old version of the "requests" helper package (v2.28.1). Hackers can trick it into leaking login credentials when visiting redirected websites.',
        suggestedFix: 'Update "requests" to version 2.31.0 or newer by running "pip install --upgrade requests".',
        codeSnippet: 'requests==2.28.1',
      },
      {
        id: 'repo-3',
        category: 'code',
        severity: 'high',
        title: 'Dangerous eval() Command Used',
        filePath: 'services/parser.py',
        lineNumber: 88,
        explanation: 'The code uses "eval()", which executes incoming text as raw computer code. If an attacker inputs malicious text, your server will run their commands.',
        suggestedFix: 'Replace eval() with safe alternatives like json.loads() or ast.literal_eval(). Never run eval() on untrusted user data.',
        codeSnippet: 'user_formula = eval(request.GET.get("calc"))',
      },
      {
        id: 'repo-4',
        category: 'network',
        severity: 'medium',
        title: 'Insecure Unencrypted Web Address (HTTP)',
        filePath: 'src/api/client.ts',
        lineNumber: 19,
        explanation: 'Your app connects to "http://api.internal-sync.io" without encryption. Anyone on the same Wi-Fi network can view or modify the data being sent.',
        suggestedFix: 'Change the address to use secure HTTPS: "https://api.internal-sync.io".',
        codeSnippet: 'const BASE_URL = "http://api.internal-sync.io/v1";',
      },
      {
        id: 'repo-5',
        category: 'network',
        severity: 'low',
        title: 'Database Port Exposed in Compose File',
        filePath: 'docker-compose.yml',
        lineNumber: 27,
        explanation: 'The PostgreSQL database port (5432) is mapped to the public internet instead of staying inside your private server network.',
        suggestedFix: 'Bind the port to localhost only: "127.0.0.1:5432:5432" or remove the public ports directive if only other containers need access.',
        codeSnippet: 'ports:\n  - "0.0.0.0:5432:5432"',
      }
    ]
  };
}

/**
 * Checks an IP address for bad reputation, proxy/VPN/Tor usage, and malicious history.
 * Backend equivalent: GET /api/v1/network/ip?ip={ip}
 */
export async function checkIp(ip: string): Promise<IpCheckResult> {
  await wait(1300);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/network/ip?ip=${encodeURIComponent(ip)}`);
  // return await res.json();

  const isTorOrSuspicious = ip.includes('185') || ip.includes('91') || ip.includes('194') || ip.toLowerCase().includes('bad');

  if (isTorOrSuspicious) {
    return {
      ip,
      country: 'Germany',
      city: 'Frankfurt am Main',
      isp: 'M247 Europe Cyber Services',
      asn: 'AS9009 (M247 Ltd)',
      isVpn: true,
      isProxy: true,
      isTor: true,
      abuseScore: 89,
      verdict: 'Dangerous',
      riskLevel: 'critical',
      explanation: 'This IP address is a known Tor anonymizer and proxy node commonly used by automated attack scripts. It has been reported 1,420 times for unauthorized login attempts.',
      timestamp: new Date().toISOString(),
    };
  }

  return {
    ip,
    country: 'United States',
    city: 'San Jose, California',
    isp: 'Comcast Cable Communications',
    asn: 'AS7922 (Comcast)',
    isVpn: false,
    isProxy: false,
    isTor: false,
    abuseScore: 0,
    verdict: 'Safe',
    riskLevel: 'low',
    explanation: 'This IP address is a standard home residential internet connection with a clean reputation and zero attack reports.',
    timestamp: new Date().toISOString(),
  };
}

/**
 * Checks a suspicious link or URL for phishing redirects, domain age, and fake identity.
 * Backend equivalent: GET /api/v1/network/link?url={url}
 */
export async function checkLink(url: string): Promise<LinkCheckResult> {
  await wait(1500);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/network/link?url=${encodeURIComponent(url)}`);
  // return await res.json();

  const isPhishingSample = !url.includes('google.com') && !url.includes('github.com') && !url.includes('apple.com');

  if (isPhishingSample) {
    return {
      url,
      domainAge: '3 days old (Registered October 20, 2026)',
      dnsRecords: {
        a: ['104.21.55.19', '172.67.182.201'],
        mx: ['mail.private-relay-shield.cc'],
        txt: ['v=spf1 ~all', 'verification=phish-hunter-flagged'],
      },
      sslValid: true,
      sslIssuer: "Let's Encrypt Free Authority (Generated 3 days ago)",
      redirectChain: [
        { step: 1, url: url, status: 301, note: 'Initial link shortener redirect' },
        { step: 2, url: 'https://security-verify-telegram-login.cc/login', status: 302, note: 'Cloaked redirect to fake portal' },
        { step: 3, url: 'https://auth-session-harvest.ru/verify', status: 200, note: 'Final fake login page that steals passwords' }
      ],
      reputationScore: 14,
      verdict: 'Dangerous',
      riskLevel: 'critical',
      explanation: 'This link is a fake phishing scam! It pretends to be an official security verification page to trick you into entering your phone number and SMS code.',
      timestamp: new Date().toISOString(),
    };
  }

  return {
    url,
    domainAge: '14 years old',
    dnsRecords: {
      a: ['140.82.112.3'],
      mx: ['aspmx.l.google.com'],
      txt: ['v=spf1 include:_spf.google.com ~all']
    },
    sslValid: true,
    sslIssuer: 'DigiCert Global Root G2',
    redirectChain: [
      { step: 1, url: url, status: 200, note: 'Direct secure connection' }
    ],
    reputationScore: 98,
    verdict: 'Safe',
    riskLevel: 'low',
    explanation: 'This is a genuine, well-established website with a verified SSL certificate and no reports of malicious behavior.',
    timestamp: new Date().toISOString(),
  };
}

/**
 * Checks a website domain for open doors (ports), certificate expiration, and browser safety shields.
 * Backend equivalent: GET /api/v1/network/website?domain={domain}
 */
export async function checkWebsite(domain: string): Promise<WebsiteCheckResult> {
  await wait(1600);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/network/website?domain=${encodeURIComponent(domain)}`);
  // return await res.json();

  const isFlawed = domain.includes('demo') || domain.includes('test') || domain.includes('portal') || !domain.includes('google.com');

  if (isFlawed) {
    return {
      domain,
      riskScore: 65,
      riskLevel: 'medium',
      verdict: 'Suspicious',
      explanation: 'The website has unencrypted ports open and is missing modern browser security shields that stop hackers from spoofing or stealing customer cookies.',
      sslExpiry: 'November 14, 2026',
      sslDaysRemaining: 22,
      timestamp: new Date().toISOString(),
      ports: [
        { port: 80, service: 'HTTP (Web)', state: 'Open', risk: 'medium', note: 'Does not automatically forward visitors to secure HTTPS.' },
        { port: 443, service: 'HTTPS (Secure Web)', state: 'Open', risk: 'low', note: 'Secure web server is working.' },
        { port: 22, service: 'SSH (Remote Administration)', state: 'Open', risk: 'high', note: 'Remote server login port is exposed to the entire internet.' },
        { port: 21, service: 'FTP (File Transfer)', state: 'Closed', risk: 'low', note: 'Insecure file transfer port is safely closed.' }
      ],
      securityHeaders: [
        { header: 'Content-Security-Policy', status: 'Fail', description: 'Stops malicious scripts and hacker popups from running in visitors\' browsers.' },
        { header: 'Strict-Transport-Security (HSTS)', status: 'Fail', description: 'Forces all web browsers to use encrypted connections exclusively.' },
        { header: 'X-Frame-Options', status: 'Fail', description: 'Prevents hackers from embedding your site inside invisible clickjacking frames.' },
        { header: 'X-Content-Type-Options', status: 'Pass', description: 'Stops browsers from mistakenly executing images as computer code.' }
      ]
    };
  }

  return {
    domain,
    riskScore: 10,
    riskLevel: 'low',
    verdict: 'Safe',
    explanation: 'This website is securely configured with strong encryption, modern safety headers, and zero open administrative ports.',
    sslExpiry: 'October 15, 2027',
    sslDaysRemaining: 357,
    timestamp: new Date().toISOString(),
    ports: [
      { port: 80, service: 'HTTP (Web)', state: 'Open', risk: 'low', note: 'Properly redirects all traffic to HTTPS.' },
      { port: 443, service: 'HTTPS (Secure Web)', state: 'Open', risk: 'low', note: 'Modern TLS 1.3 encryption enabled.' },
      { port: 22, service: 'SSH (Server Control)', state: 'Closed', risk: 'low', note: 'Safely protected behind a firewall.' },
      { port: 21, service: 'FTP (File Transfer)', state: 'Closed', risk: 'low', note: 'Port closed.' }
    ],
    securityHeaders: [
      { header: 'Content-Security-Policy', status: 'Pass', description: 'Strict script boundaries active.' },
      { header: 'Strict-Transport-Security (HSTS)', status: 'Pass', description: 'Browser enforces HTTPS at all times.' },
      { header: 'X-Frame-Options', status: 'Pass', description: 'Clickjacking protection is active.' },
      { header: 'X-Content-Type-Options', status: 'Pass', description: 'MIME-sniffing protection enabled.' }
    ]
  };
}

/**
 * Compiles a comprehensive full investigation report across all scanned channels.
 * Backend equivalent: GET /api/v1/report
 */
export async function getReport(): Promise<FullReport> {
  await wait(1200);

  // In production with FastAPI:
  // const res = await fetch(`${API_BASE}/api/v1/report`);
  // return await res.json();

  return {
    id: `REP-${Math.floor(100000 + Math.random() * 900000)}`,
    generatedAt: new Date().toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }),
    overallScore: 78,
    overallRisk: 'critical',
    summary: 'High likelihood of account unauthorized access: an unknown device in Germany accessed Telegram, and a public code repository leaked credentials.',
    howItHappened: [
      "Step 1: Your GitHub repository accidentally published an API credential in settings.py.",
      "Step 2: Automated internet bots found this credential within minutes of publication.",
      "Step 3: An intruder in Frankfurt, Germany logged into your Telegram session using an intercepted verification code.",
      "Step 4: Because Two-Step Verification was not turned on, the intruder accessed your account without needing an extra password."
    ],
    actionPlan: [
      {
        id: 1,
        title: "Kick out unknown Telegram devices",
        detail: "Open Telegram > Settings > Devices > Tap 'Terminate all other sessions' to kick out the intruder in Germany.",
        completed: false,
      },
      {
        id: 2,
        title: "Turn on Telegram Two-Step Password",
        detail: "Go to Settings > Privacy and Security > Two-Step Verification. Set a strong password so SMS alone cannot access your account.",
        completed: false,
      },
      {
        id: 3,
        title: "Revoke the leaked Stripe secret key",
        detail: "Log in to your Stripe dashboard, roll the leaked key immediately, and check recent charges for fraudulent activity.",
        completed: false,
      },
      {
        id: 4,
        title: "Close exposed port 22 on your web server",
        detail: "Adjust your cloud firewall (AWS/DigitalOcean/Hetzner) to block public access to port 22 except from your personal IP address.",
        completed: false,
      }
    ],
    connectedAccounts: [
      { name: "Telegram Messenger", service: "Telegram", connectedAt: "Today at 10:14 PM", status: "Active (Critical Risk)" },
      { name: "my-project/api-backend", service: "GitHub", connectedAt: "Today at 09:30 PM", status: "Scanned (High Risk)" },
      { name: "185.220.101.5", service: "Network IP", connectedAt: "Today at 09:45 PM", status: "Tor Exit Node (Dangerous)" }
    ]
  };
}
