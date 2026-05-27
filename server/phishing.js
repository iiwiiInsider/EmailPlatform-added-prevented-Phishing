import { parse as parseDomain } from 'tldts';

const SUSPICIOUS_KEYWORDS = [
  'verify account',
  'urgent action required',
  'suspended',
  'click here immediately',
  'password expires',
  'crypto giveaway',
  'wire transfer',
  'gift card',
  'login alert'
];

const BRAND_TERMS = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'bank', 'metamask'];

function extractUrls(text = '') {
  const matches = text.match(/https?:\/\/[^\s"'<>]+/gi);
  return matches ?? [];
}

function getHost(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function hasCyrillic(text = '') {
  return /[\u0400-\u04FF]/.test(text);
}

function isIPv4Host(host = '') {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function baseDomain(host = '') {
  const parsed = parseDomain(host);
  return parsed.domain || host;
}

export function analyzePhishing({ from = '', subject = '', text = '', html = '' }) {
  const combined = `${subject}\n${text}\n${html}`.toLowerCase();
  const warnings = [];
  let score = 0;

  const urls = extractUrls(`${text}\n${html}`);
  if (urls.length > 25) {
    score += 15;
    warnings.push('Unusually high number of links.');
  }

  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (combined.includes(keyword)) {
      score += 8;
      warnings.push(`Suspicious phrase detected: "${keyword}".`);
    }
  }

  for (const url of urls) {
    const host = getHost(url);
    if (!host) {
      score += 5;
      warnings.push(`Malformed URL detected: ${url}`);
      continue;
    }

    if (isIPv4Host(host)) {
      score += 12;
      warnings.push(`IP-based URL detected: ${url}`);
    }

    if (host.includes('xn--') || hasCyrillic(host)) {
      score += 18;
      warnings.push(`Potential homograph domain: ${host}`);
    }

    const d = baseDomain(host);
    for (const brand of BRAND_TERMS) {
      if (host.includes(brand) && d !== `${brand}.com`) {
        score += 10;
        warnings.push(`Brand impersonation pattern detected in host: ${host}`);
        break;
      }
    }
  }

  if (/reply\s*to:\s*[^\n]+/i.test(text) && from) {
    score += 6;
    warnings.push('Message body contains reply-to text, verify sender identity.');
  }

  const riskLevel = score >= 40 ? 'high' : score >= 20 ? 'medium' : 'low';
  return {
    score,
    riskLevel,
    warnings: Array.from(new Set(warnings)),
    urlCount: urls.length
  };
}
