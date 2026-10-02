/**
 * Markdown / SKILL.md Analyzer
 *
 * Agent skills are mostly instructions, not code. The agent reads SKILL.md and
 * follows it with your permissions, so the text itself is the attack surface:
 * "paste this into your terminal", a hidden HTML comment, an invisible Unicode
 * payload. This analyzer reads markdown the way an agent would and flags the
 * techniques seen in real malicious skills (ClawHavoc campaign, Jan 2026;
 * Snyk ToxicSkills study, Feb 2026).
 *
 * Rules were tuned against real, trusted skills (Anthropic's skills repo,
 * obra/superpowers, a large personal skill library) to keep false alarms low.
 *
 * Every rule is a single-line regex without nested quantifiers, so a hostile
 * file can't make the scan hang.
 */

import * as fs from 'fs';
import { Finding, LanguageAnalyzer, Language, RiskSeverity } from '../types';
import { getConfigLoader } from '../config';

interface MarkdownRule {
  /** Stable id, usable in .skillguardrc patternOverrides */
  name: string;
  severity: RiskSeverity;
  category: string;
  description: string;
  pattern: RegExp;
  /** Skip the match if the line also matches this (cuts false positives) */
  unless?: RegExp;
  /** Mask the matched text in the report (never print secrets) */
  redact?: boolean;
  /**
   * Phrase rules (prompt injection wording). When the phrase is quoted, it is
   * usually being discussed ("avoid phrases like 'ignore previous
   * instructions'"), so it's reported softly instead of as an attack.
   */
  phrase?: boolean;
  /** Ignore matches inside code blocks / inline code (template syntax etc.) */
  proseOnly?: boolean;
}

// Credential stores an agent can be told to read.
const SECRET_FILES = String.raw`(?:~\/\.ssh\/|\.ssh\/id_|\bid_rsa\b|\bid_ed25519\b|\.aws\/credentials|\.config\/gcloud\/|\.kube\/config|\.docker\/config\.json|\.git-credentials|\.netrc\b|\.pypirc\b|wallet\.dat|Login Data|Cookies\.binarycookies|login\.keychain|\.clawdbot\/)`;
// ...plus .env files, which legit skills read for their own keys. Only counted when sent out.
const SECRET_OR_ENV = String.raw`(?:${SECRET_FILES}|[\w~\/.-]*\.env\b)`;

// Hosts used to serve payloads or catch stolen data. Legit skills rarely need them.
const DROP_HOSTS = String.raw`(?:glot\.io|pastebin\.com|paste\.ee|hastebin\.|ghostbin\.|rentry\.co|transfer\.sh|file\.io|0x0\.st|webhook\.site|requestbin\.|pipedream\.net|beeceptor\.com|interact\.sh|oast\.(?:fun|me|pro|live|site|online)|burpcollaborator\.net|ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|serveo\.net)`;

const MARKDOWN_RULES: MarkdownRule[] = [
  // ── Running code from the internet ──────────────────────────────────────
  {
    name: 'pipe-to-shell',
    severity: 'high',
    category: 'Remote Script',
    description:
      'Downloads a script and runs it straight away. Common for installers, but nobody reviews what executes and the server can change it any time.',
    // `curl api | python -c "..."` just parses JSON, so -c/-m/-e after the interpreter is excluded.
    pattern:
      /\b(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:(?:ba|z|da|k|fi)?sh\b(?!\s+-c\b)|python3?\b(?!\s+-[cm]\b)|node\b(?!\s+-[ep]\b)|perl\b(?!\s+-[nep]\b)|ruby\b(?!\s+-e\b)|iex\b|Invoke-Expression\b)/i,
  },
  {
    name: 'shell-from-download',
    severity: 'medium',
    category: 'Remote Script',
    description: 'Runs a shell on downloaded content (process or command substitution).',
    pattern:
      /\b(?:(?:ba|z|da|k)?sh|source)\s+(?:-c\s+)?["']?(?:<\(|\$\()\s*(?:curl|wget)\b|\biex\s*\(\s*(?:iwr|irm|\(?New-Object\s+Net\.WebClient)/i,
  },
  {
    name: 'download-then-execute',
    severity: 'medium',
    category: 'Remote Script',
    description: 'Downloads a file, makes it executable and runs it in one go.',
    pattern:
      /\b(?:curl|wget)\b[^\n]*(?:\s-o\s?|\s-O\b|--output\s)[^\n]*(?:&&|;)\s*chmod\s+\+x[^\n]*(?:&&|;)\s*(?:sudo\s+)?(?:\.\/|\/tmp\/|(?:ba|z)?sh\s)/i,
  },

  // ── Obfuscation ─────────────────────────────────────────────────────────
  {
    name: 'decode-and-run',
    severity: 'critical',
    category: 'Evasion Technique',
    description:
      'Decodes hidden (base64/hex) content and runs it. Honest instructions have no reason to hide what they execute.',
    pattern:
      /base64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z)?sh|python3?|node|perl)\b|\b(?:eval|exec)\b[^\n]*\$\([^\n]*base64\s+(?:-d|--decode|-D)|FromBase64String[^\n]*(?:iex|Invoke-Expression)|(?:iex|Invoke-Expression)[^\n]*FromBase64String|xxd\s+-r\s+-p[^\n]*\|\s*(?:ba|z)?sh\b/i,
  },
  {
    name: 'long-encoded-blob',
    severity: 'medium',
    category: 'Hidden Content',
    description:
      'Long encoded string in the instructions. Could be a hidden payload; decode it before trusting this skill.',
    pattern: /[A-Za-z0-9+/]{200,}={0,2}/,
    unless: /data:[\w/+.-]+;base64,|sha(?:256|384|512)-|integrity=/i,
  },

  // ── Suspicious downloads ────────────────────────────────────────────────
  {
    name: 'password-protected-archive',
    severity: 'critical',
    category: 'Suspicious Download',
    description:
      'Password-protected archive. A classic trick to stop antivirus and scanners looking inside (used in the ClawHavoc campaign).',
    pattern:
      /\bunzip\s+(?:-[a-zA-Z]+\s+)*-P\s*\S|\b7z\s+x\b[^\n]*\s-p\S|\.(?:zip|rar|7z)\b[^\n]{0,80}\b(?:password|passcode|pwd)\b\s*(?:is|:|=)|\b(?:password|passcode|pwd)\b\s*(?:is|:|=)\s*\S+[^\n]{0,80}\.(?:zip|rar|7z)\b/i,
  },
  {
    name: 'payload-host',
    severity: 'high',
    category: 'Suspicious Download',
    description:
      'Points the agent at a paste site, tunnel or request catcher. These are used to serve payloads and collect stolen data.',
    pattern: new RegExp(String.raw`\b${DROP_HOSTS}`, 'i'),
  },
  {
    name: 'raw-ip-url',
    severity: 'high',
    category: 'Suspicious Download',
    description:
      'URL with a bare public IP address instead of a domain. Typical for attacker servers (ClawHavoc ran all 335 skills from one IP).',
    pattern: /\b(?:https?|ftp):\/\/(?:\d{1,3}\.){3}\d{1,3}\b/i,
    unless:
      /\b(?:https?|ftp):\/\/(?:127\.|0\.0\.0\.0|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)/i,
  },

  // ── Credential theft & exfiltration ─────────────────────────────────────
  {
    name: 'prose-exfiltration',
    severity: 'critical',
    category: 'Data Exfiltration',
    description:
      'Tells the agent, in plain words, to send a credential or .env file to a web address.',
    pattern: new RegExp(
      String.raw`\b(?:upload|send|post|exfiltrate|forward|transmit|sync|copy|beacon)\b[^\n]{0,40}?${SECRET_OR_ENV}[^\n]{0,60}?\b(?:to|at|into)\s+(?:https?:\/\/|[\w-]+\.[\w.-]+\/)`,
      'i',
    ),
  },
  {
    name: 'secret-exfiltration',
    severity: 'critical',
    category: 'Data Exfiltration',
    description:
      'Reads credentials or environment variables and sends them over the network in the same command.',
    pattern: new RegExp(
      [
        // cat ~/.ssh/id_rsa | curl ...   /   env | curl ...
        String.raw`(?:\b(?:cat|base64|xxd|tar|zip|gzip)\b[^\n|]*${SECRET_OR_ENV}[^\n|]*|\b(?:env|printenv|set)\s*)\|\s*(?:\S+\s*\|\s*)?(?:curl|wget|nc|ncat|socat|iwr|Invoke-WebRequest)\b`,
        // curl -d @~/.aws/credentials   /   curl -T .env
        String.raw`\b(?:curl|wget)\b[^\n]*(?:@|-T\s+|--upload-file\s+|--post-file=)["']?[^\s"']*${SECRET_OR_ENV}`,
        // curl "...$(cat ~/.ssh/id_rsa)"   /   curl "...$(env)"
        String.raw`\b(?:curl|wget|iwr|Invoke-WebRequest)\b[^\n]*\$\(\s*(?:(?:cat|base64)\s+[^)]*${SECRET_OR_ENV}|env|printenv)`,
        // scp ~/.ssh/id_rsa user@host:
        String.raw`\b(?:scp|rsync)\b[^\n]*${SECRET_FILES}[^\n]*\s\S+@?[\w.-]+:`,
      ].join('|'),
      'i',
    ),
  },
  {
    name: 'credential-file-access',
    severity: 'high',
    category: 'Credential Theft',
    description:
      'Tells the agent to read, copy or encode a credential file (SSH keys, cloud credentials, browser or wallet data).',
    pattern: new RegExp(
      String.raw`\b(?:cat|less|more|head|tail|cp|scp|base64|xxd|tar|zip)\s+(?:-\S+\s+)*["']?[^\s"']*${SECRET_FILES}|\b(?:read|copy|upload|send|collect|grab)\s+(?:the\s+)?(?:contents?\s+of\s+)?(?:the\s+user'?s\s+)?["'\x60]?${SECRET_FILES}`,
      'i',
    ),
    unless: /\.pub\b/i,
  },
  {
    name: 'keychain-dump',
    severity: 'critical',
    category: 'Credential Theft',
    description: 'Dumps every password in the macOS keychain.',
    pattern: /\bsecurity\s+dump-keychain\b/i,
  },
  {
    name: 'hardcoded-secret',
    severity: 'high',
    category: 'Hardcoded Secret',
    description:
      'A real-looking API key or private key is written into the skill. It leaks to everyone who installs it (value hidden in this report).',
    pattern:
      /\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}|\bxox[baprs]-\d{6,}-[A-Za-z0-9-]{10,}|\bsk-(?:proj-|ant-(?:api\d\d-)?)?(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Z])(?=[A-Za-z0-9_-]*[a-z])[A-Za-z0-9_-]{32,}|\bAIza[0-9A-Za-z_-]{35}\b|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    unless: /EXAMPLE|example|xxxx|XXXX|\.\.\.|your[-_]?(?:api[-_]?)?key/i,
    redact: true,
  },
  {
    name: 'secret-echo',
    severity: 'low',
    category: 'Credential Handling',
    description: 'Prints a secret in full, where it ends up in terminal logs and chat transcripts.',
    pattern:
      /\b(?:echo|printf|print|console\.log)\b[^\n]{0,20}\$\{?\w*(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD)\w*\}?/i,
    // ${TOKEN:0:8} only shows a prefix, which is the safe way to check a key.
    unless: /\$\{\w+:\d+:\d+\}/,
  },
  {
    name: 'secret-request',
    severity: 'medium',
    category: 'Credential Handling',
    description: 'Asks the user to paste a password, seed phrase or private key into the chat.',
    pattern:
      /\b(?:paste|share|send|give|reveal|tell)\s+(?:me|us)?\s*(?:your|the\s+user'?s)\s+(?:[a-z]+\s+){0,3}(?:password|seed\s+phrase|recovery\s+phrase|mnemonic|private\s+key|2fa\s+code|one[- ]time\s+code)/i,
  },

  // ── Prompt injection ────────────────────────────────────────────────────
  {
    name: 'instruction-override',
    severity: 'critical',
    category: 'Prompt Injection',
    description:
      'Tries to override the agent\'s existing instructions ("ignore previous instructions").',
    pattern:
      /\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|every\s+)?(?:of\s+)?(?:the\s+|your\s+|my\s+)?(?:previous|prior|above|earlier|preceding|system|original|existing|safety)\s+(?:instructions?|prompts?|rules|guidelines|directives|policies|guardrails)/i,
    phrase: true,
  },
  {
    name: 'fake-system-message',
    severity: 'critical',
    category: 'Prompt Injection',
    description:
      'Pretends to be a system or developer message so the agent gives it more authority.',
    pattern:
      /<\|im_start\|>\s*system|<\|system\|>|\[\s*(?:SYSTEM|SYSTEM_PROMPT)\s*\]|<\/?\s*system(?:[-_]prompt)?\s*>|^\s*#{0,3}\s*(?:SYSTEM|DEVELOPER)\s+(?:MESSAGE|OVERRIDE|PROMPT)\s*:/im,
    // Chat-template docs show these tokens inside code. In prose they're an attack.
    proseOnly: true,
    phrase: true,
  },
  {
    name: 'jailbreak-phrase',
    severity: 'high',
    category: 'Prompt Injection',
    description: "Jailbreak wording aimed at switching off the agent's safety rules.",
    pattern:
      /\b(?:DAN\s+mode|do\s+anything\s+now|developer\s+mode\s+(?:enabled|activated|on)|god\s?mode\s+(?:enabled|activated|on)|no\s+(?:ethical|safety|moral)\s+(?:guidelines|restrictions|limits))\b/i,
    phrase: true,
  },
  {
    name: 'conceal-from-user',
    severity: 'high',
    category: 'Prompt Injection',
    description:
      'Tells the agent to hide what it does from the user. Honest skills have no reason to keep secrets from the person running them.',
    pattern:
      /\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|notify|alert|show)\s+(?:the\s+)?(?:user|human|operator|owner)\s+(?:about\s+(?:this|it|that|what)|that\s+you|what\s+you|you\s+(?:have|are|did|ran|sent))|\b(?:hide|conceal)\s+(?:this|it|these|that|the\s+\w+)\s+from\s+(?:the\s+)?(?:user|human|operator)\b|(?<!\b(?:not|never|n't)\s)\b(?:silently|secretly|covertly)\s+(?:run|execute|send|upload|install|download|copy|post|exfiltrate|forward)\b|\bwithout\s+(?:the\s+)?(?:user|human)(?:'s)?\s+(?:knowing|knowledge|noticing)\b/i,
    phrase: true,
  },

  // ── Safety bypass ───────────────────────────────────────────────────────
  {
    name: 'disable-os-security',
    severity: 'critical',
    category: 'Safety Bypass',
    description:
      'Switches off operating-system protection (Gatekeeper, SIP, antivirus, SELinux, firewall). Malware installers ask for this.',
    pattern:
      /\bspctl\s+--master-disable|\bcsrutil\s+disable|Set-MpPreference\s+[^\n]*-Disable\w*\s+\$?true|Add-MpPreference\s+[^\n]*-ExclusionPath|\bsetenforce\s+0\b|\bufw\s+disable\b|\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off/i,
  },
  {
    name: 'remove-quarantine',
    severity: 'medium',
    category: 'Safety Bypass',
    description:
      "Removes macOS's download quarantine flag, so Gatekeeper never checks the file. The ClawHavoc malware used this. Fine for a binary you installed yourself, risky for anything downloaded.",
    pattern: /\bxattr\s+(?:-[a-z]+\s+)*(?:-d\s+com\.apple\.quarantine|-[a-z]*c[a-z]*\s)/i,
  },
  {
    name: 'skip-agent-permissions',
    severity: 'medium',
    category: 'Permission Bypass',
    description:
      'Runs an agent with its permission prompts turned off, so nothing it does asks for your approval.',
    pattern:
      /--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|"(?:permissionMode|defaultMode)"\s*:\s*"bypassPermissions"/i,
  },

  // ── Persistence & destruction ───────────────────────────────────────────
  {
    name: 'memory-trust-injection',
    severity: 'critical',
    category: 'Persistence',
    description:
      'Writes a standing order into the agent\'s memory or instruction files ("always trust ...", "ignore ...", "never ask ..."). That changes how the agent behaves in every future session.',
    pattern:
      /\b(?:always|never|ignore|trust|allow|auto-?approve|skip|do\s+not\s+(?:ask|tell|warn))\b[^\n>]*(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?[^\s"'|]*(?:MEMORY\.md|SOUL\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md)\b/i,
  },
  {
    name: 'agent-memory-write',
    severity: 'high',
    category: 'Persistence',
    description:
      "Writes into the agent's memory or instruction files. A skill that edits these can change the agent's behaviour for good (ClawHavoc went after SOUL.md and MEMORY.md).",
    pattern:
      /(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?[^\s"'|]*(?:MEMORY\.md|SOUL\.md|CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|copilot-instructions\.md)\b/i,
  },
  {
    name: 'autostart',
    severity: 'medium',
    category: 'Autostart',
    description:
      'Sets something to start automatically (cron, launch agent, shell profile, Windows Run key). It keeps running after the skill is done.',
    pattern:
      /\(\s*crontab\s+-l[^\n]*\|\s*crontab\s+-|\becho\b[^\n]*\|\s*crontab\s+-|(?:>>|\btee\s+-a)\s*["']?(?:~|\$HOME)\/\.(?:bashrc|zshrc|bash_profile|zprofile|profile)\b|\b(?:cp|mv|ln|tee|cat\s*>)\b[^\n]*Library\/Launch(?:Agents|Daemons)\/|\bschtasks\s+\/create\b|CurrentVersion\\Run\b/i,
  },
  {
    name: 'destructive-command',
    severity: 'critical',
    category: 'Destructive Command',
    description: 'Wipes the whole disk or home folder.',
    pattern:
      /\brm\s+-(?:[a-z]*r[a-z]*f|[a-z]*f[a-z]*r)[a-z]*\s+(?:--no-preserve-root\s+)?["']?(?:\/\*|~\/\*|~\/|\$HOME\/?|\/|~)["']?(?:\s|$|;|&)|\bmkfs\.\w+\s+\/dev\/|\bdd\s+[^\n]*of=\/dev\/(?:sd|disk|nvme|hd)|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:|\bdiskutil\s+erase(?:Disk|Volume)\b|\bFormat-Volume\b/i,
    // Hooks that *block* these commands mention them in a grep.
    unless: /\bgrep\b|blocked|deny|forbid/i,
  },
];

// Unicode that renders as nothing (or reorders text) but is read by the model.
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/u;
const ZERO_WIDTH_ALL = /[\u200B-\u200D\u2060-\u2064\u180E]/g;
const ZERO_WIDTH_IN_WORD = /[\p{L}\p{N}][\u200B-\u200D\u2060-\u2064][\p{L}\p{N}]/u;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;

// A hidden HTML comment only matters if it's telling the agent to do something risky.
const RISKY_COMMENT =
  /\b(?:ignore|disregard)\s+(?:the\s+|all\s+|any\s+|previous|prior|above)|\byou\s+(?:must|should)\s+(?:now\s+)?(?:run|execute|send|ignore|download|install|curl)\b|\b(?:curl|wget|iwr|bash\s+-c)\b|\beval\s*[("'$`]|\bexfiltrat|\b(?:api[_ ]?key|password|private\s+key|seed\s+phrase|credentials?)\b|\b(?:do\s+not|don'?t)\s+(?:tell|mention|show)\b|\bsilently\b|\bsecretly\b/i;

export class MarkdownAnalyzer implements LanguageAnalyzer {
  readonly language: Language = 'markdown';
  readonly fileExtensions = ['.md', '.mdx', '.markdown'];

  canAnalyze(filePath: string): boolean {
    const lower = filePath.toLowerCase();
    return this.fileExtensions.some((ext) => lower.endsWith(ext));
  }

  analyzeFile(filePath: string): Finding[] {
    let source: string;
    try {
      source = fs.readFileSync(filePath, 'utf-8');
    } catch (_error) {
      return [];
    }
    return analyzeMarkdown(source, filePath);
  }
}

/**
 * Words that mark a command as something to avoid. Skills often *warn* about a
 * technique ("DO NOT use `curl | bash`") and a scanner that cannot tell the
 * warning from the attack trains people to ignore it.
 */
const NEGATION =
  /\b(?:do\s+not|don'?t|never|avoid|instead\s+of|not\s+allowed|must\s+not|should\s+not|shouldn'?t|blocked|refuse|disallow)\b/gi;

/**
 * An order to run something. If one follows the warning, the warning was a
 * disguise ("documentation only ... before first use, run the setup step").
 */
const IMPERATIVE =
  /\b(?:now|must\s+(?:now\s+)?(?:run|execute|apply|paste)|please\s+(?:run|apply|execute|paste)|make\s+sure\s+to|be\s+sure\s+to|go\s+ahead|before\s+first\s+use|to\s+finish|(?:run|execute|paste|apply)\s+(?:it|this|these|the\s+following|the\s+setup|the\s+command|once))\b|\bagent\s*:/i;

/**
 * Rules whose meaning depends on context: naming the command is often how a
 * skill explains or forbids it. Only these may be softened by a nearby warning.
 * Everything else (paste sites, decode-and-run, exfiltration, hiding things
 * from the user, memory writes) is evidence on its own and is never softened.
 */
const SOFTENABLE = new Set([
  'pipe-to-shell',
  'shell-from-download',
  'download-then-execute',
  'credential-file-access',
  'keychain-dump',
  'remove-quarantine',
  'skip-agent-permissions',
]);

/**
 * True when a warning governs the match. Prose wraps, so the lookback reaches
 * about two lines; the forward check stays short ("`curl | sh` is blocked").
 * A warning followed by an order to run something does not count.
 */
function isNegated(line: string, index: number, length: number, proseBefore: string): boolean {
  const context = `${proseBefore} ${line.slice(0, index)}`.slice(-240);
  const after = line.slice(index + length, index + length + 60);

  let lastNegation = -1;
  for (const m of context.matchAll(NEGATION)) lastNegation = m.index ?? lastNegation;
  if (lastNegation >= 0) {
    // Skip the warning's own verb ("never run a command ...").
    const afterWarning = context.slice(lastNegation).replace(/^\S+(?:\s+not)?\s+\S+/, '');
    if (!IMPERATIVE.test(afterWarning)) return true;
  }
  NEGATION.lastIndex = 0;
  const forward = new RegExp(NEGATION.source, 'i').test(after);
  return forward && !IMPERATIVE.test(after);
}

/** Analyze markdown text directly (exported for tests). */
export function analyzeMarkdown(source: string, filePath: string): Finding[] {
  const findings: Finding[] = [];
  const config = getConfigLoader();
  const lines = source.split('\n');
  const frontmatterEnd = findFrontmatterEnd(lines);

  const add = (
    rule: Pick<MarkdownRule, 'name' | 'severity' | 'category' | 'description'>,
    lineIndex: number,
    column: number,
    snippet: string,
  ): void => {
    if (!config.isPatternEnabled(rule.name, 'markdown')) return;
    let severity = config.getPatternSeverity(rule.name, rule.severity, 'markdown');
    let description = rule.description;

    // The frontmatter description is loaded into the agent's context in every
    // session, before the skill is even used. Injection there is worse.
    if (lineIndex < frontmatterEnd && /Prompt Injection|Hidden Content/.test(rule.category)) {
      severity = 'critical';
      description += ' Found in the frontmatter, which the agent loads in every session.';
    }

    findings.push({
      file: filePath,
      line: lineIndex + 1,
      column,
      severity,
      category: rule.category,
      description,
      codeSnippet: clip(snippet),
      language: 'markdown',
    });
  };

  // Track fenced code blocks the CommonMark way: a fence closes only with the
  // same character, at least as long, and no info string. Naive toggling on
  // every ``` line desyncs on nested/annotated fences in long docs.
  let fence: string | null = null;
  // Recent prose, so a warning two lines above a command ("Never run ...
  // `security dump-keychain`") still counts as a warning about it.
  let prose = '';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const proseBefore = prose;
    prose = `${prose} ${line}`.slice(-240);
    const fm = /^\s*(`{3,}|~{3,})(.*)$/.exec(line);
    if (fm) {
      const marker = fm[1];
      const rest = fm[2].trim();
      if (fence === null) {
        if (!(marker[0] === '`' && rest.includes('`'))) {
          fence = marker;
          continue;
        }
      } else if (marker[0] === fence[0] && marker.length >= fence.length && rest === '') {
        fence = null;
        continue;
      }
    }
    const inFence = fence !== null;

    // 1) Line rules
    for (const rule of MARKDOWN_RULES) {
      const m = rule.pattern.exec(line);
      if (!m) continue;
      if (rule.unless && rule.unless.test(line)) continue;
      const inCode = inFence || insideInlineCode(line, m.index);
      if (rule.proseOnly && inCode) continue;

      if (rule.phrase && isQuoted(line, m.index, m[0].length)) {
        // Being talked about, not used. Still shown, weighted low.
        add(
          {
            name: rule.name,
            severity: 'low',
            category: 'Quoted Attack Phrase',
            description: `Quotes a known prompt-injection phrase (${rule.name}). Usually documentation about attacks; check it isn't aimed at the agent.`,
          },
          i,
          m.index,
          line,
        );
        continue;
      }
      const snippet = rule.redact ? line.replace(m[0], redact(m[0])) : line;
      // A doc that says "do not run curl | bash" is teaching, not attacking.
      // Only context-dependent rules soften, and only to MEDIUM: still a
      // review item, never a pass.
      if (
        SOFTENABLE.has(rule.name) &&
        (rule.severity === 'high' || rule.severity === 'critical') &&
        isNegated(line, m.index, m[0].length, proseBefore)
      ) {
        add(
          {
            name: rule.name,
            severity: 'medium',
            category: rule.category,
            description: `${rule.description} Appears next to a warning against it, so it is shown for review rather than as a verdict.`,
          },
          i,
          m.index,
          snippet,
        );
        continue;
      }
      add(rule, i, m.index, snippet);
    }

    // 2) Invisible / reordering Unicode
    const tag = TAG_CHARS.exec(line);
    if (tag) {
      add(
        {
          name: 'unicode-tag-smuggling',
          severity: 'critical',
          category: 'Prompt Injection',
          description: `Invisible Unicode "tag" characters hide text that the model reads but you can't see. Hidden text: "${decodeTags(line)}"`,
        },
        i,
        tag.index,
        visible(line),
      );
    }
    // One stray zero-width space is normal in copy-pasted docs. Several, or one
    // splitting a word (to dodge filters), is not.
    const zwCount = (line.match(ZERO_WIDTH_ALL) || []).length;
    const zwInWord = ZERO_WIDTH_IN_WORD.exec(line);
    if (zwCount >= 3 || zwInWord) {
      add(
        {
          name: 'zero-width-characters',
          severity: 'high',
          category: 'Hidden Content',
          description: `Zero-width characters (${zwCount} on this line) can hide or split words so filters and humans miss them.`,
        },
        i,
        zwInWord ? zwInWord.index + 1 : line.search(ZERO_WIDTH_ALL),
        visible(line),
      );
    }
    const bidi = BIDI.exec(line);
    if (bidi) {
      add(
        {
          name: 'bidi-override',
          severity: 'high',
          category: 'Hidden Content',
          description:
            'Right-to-left override characters make text display differently from how it is read ("Trojan Source").',
        },
        i,
        bidi.index,
        visible(line),
      );
    }
  }

  // 3) HTML comments: invisible on GitHub, fully visible to the agent.
  const commentRe = /<!--([\s\S]*?)-->/g;
  let c: RegExpExecArray | null;
  while ((c = commentRe.exec(source)) !== null) {
    const body = c[1].trim();
    if (!RISKY_COMMENT.test(body)) continue;
    const lineIndex = source.slice(0, c.index).split('\n').length - 1;
    add(
      {
        name: 'hidden-html-comment',
        severity: 'high',
        category: 'Hidden Content',
        description:
          'Hidden HTML comment with risky instructions. You never see it on the rendered page, but the agent reads it.',
      },
      lineIndex,
      0,
      `<!-- ${body.replace(/\s+/g, ' ')} -->`,
    );
  }

  return findings;
}

/** Index of the first line after YAML frontmatter, or 0 if there is none. */
function findFrontmatterEnd(lines: string[]): number {
  if (lines[0]?.replace(/^\uFEFF/, '').trim() !== '---') return 0;
  for (let i = 1; i < Math.min(lines.length, 200); i++) {
    if (lines[i].trim() === '---') return i + 1;
  }
  return 0;
}

/** True if position `idx` sits inside `inline code` on this line. */
function insideInlineCode(line: string, idx: number): boolean {
  let ticks = 0;
  for (let k = 0; k < idx; k++) if (line[k] === '`') ticks++;
  return ticks % 2 === 1;
}

/** True if the match is wrapped in quotes or backticks ("...", '...', “...”, `...`). */
function isQuoted(line: string, idx: number, len: number): boolean {
  const before = line.slice(Math.max(0, idx - 3), idx);
  const after = line.slice(idx + len, idx + len + 40);
  const open = /["'`\u201C\u2018]\s*(?:\w+\s+)?$/.test(before) || /["\u201C]/.test(before);
  const close = /["'`\u201D\u2019]/.test(after);
  return open && close;
}

function redact(secret: string): string {
  if (secret.startsWith('-----BEGIN')) return '-----BEGIN [REDACTED] PRIVATE KEY-----';
  return `${secret.slice(0, 4)}…[REDACTED]`;
}

/** Make invisible characters visible in the report. */
function visible(line: string): string {
  return line
    .replace(/[\u{E0000}-\u{E007F}]/gu, '')
    .replace(/[\u200B-\u200D\u2060-\u2064\u180E\uFEFF\u202A-\u202E\u2066-\u2069]/g, (ch) => {
      return `<U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}>`;
    });
}

/** Tag characters map 1:1 onto ASCII (U+E0041 = 'A'). Show the hidden text. */
function decodeTags(line: string): string {
  let out = '';
  for (const ch of line) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xe0020 && cp <= 0xe007e) out += String.fromCharCode(cp - 0xe0000);
  }
  return clip(out, 120);
}

function clip(text: string, max = 200): string {
  const t = text.trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}
