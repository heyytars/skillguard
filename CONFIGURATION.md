# SkillGuard Configuration Guide

SkillGuard supports extensive configuration to customize risk evaluation based on your specific security requirements. This allows you to adjust severity levels, thresholds, and enable/disable specific security checks.

## Table of Contents

- [Quick Start](#quick-start)
- [Configuration Files](#configuration-files)
- [Configuration Options](#configuration-options)
- [Example Configurations](#example-configurations)
- [Pattern Overrides](#pattern-overrides)
- [Language-Specific Settings](#language-specific-settings)

## Quick Start

Create a `.skillguardrc.json` file in your project root:

```json
{
  "severityWeights": {
    "critical": 50,
    "high": 30,
    "medium": 20,
    "low": 10
  },
  "globalPatternOverrides": [
    {
      "pattern": "fetch",
      "severity": "low",
      "description": "HTTP requests are expected in this project"
    }
  ]
}
```

Run SkillGuard:

```bash
# Auto-detects .skillguardrc.json
skillguard scan ./my-project

# Or specify a config file
skillguard scan ./my-project --config ./custom-config.json
```

## Configuration Files

SkillGuard searches for configuration files in this order:

1. File specified via `--config` flag
2. `.skillguardrc.json` in current directory
3. `.skillguardrc` in current directory
4. `skillguard.config.json` in current directory
5. Searches parent directories up to root

## Configuration Options

### Risk Thresholds

Control when a score becomes low/medium/high/critical:

```json
{
  "riskThresholds": {
    "safe": 0,
    "low": 1,
    "medium": 21,
    "high": 51,
    "critical": 76
  }
}
```

### Severity Weights

Adjust how much each severity level contributes to the risk score:

```json
{
  "severityWeights": {
    "critical": 50,  // Each critical finding adds 50 points
    "high": 30,      // Each high finding adds 30 points
    "medium": 20,    // Each medium finding adds 20 points
    "low": 10        // Each low finding adds 10 points
  }
}
```

### Global Pattern Overrides

Override severity or disable patterns across all languages:

```json
{
  "globalPatternOverrides": [
    {
      "pattern": "fetch",
      "severity": "low",
      "description": "Explanation for this override"
    },
    {
      "pattern": "process.env",
      "enabled": false,
      "description": "Disable environment variable checks"
    }
  ]
}
```

### Exclude/Include Patterns

Control which directories are scanned:

```json
{
  "excludePatterns": [
    "node_modules",
    "dist",
    "test",
    "__tests__"
  ],
  "includePatterns": [
    "src/**/*.js"
  ]
}
```

### Dependency Scanning

Configure vulnerability scanning:

```json
{
  "dependencyScanning": {
    "enabled": true,
    "npmAudit": true,
    "osvScanning": true
  }
}
```

## Example Configurations

### Permissive Configuration

Suitable for development environments where you accept more risk:

```json
{
  "description": "Permissive configuration for development",
  "riskThresholds": {
    "low": 1,
    "medium": 40,
    "high": 70,
    "critical": 90
  },
  "severityWeights": {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5
  },
  "globalPatternOverrides": [
    {
      "pattern": "fetch",
      "severity": "low"
    },
    {
      "pattern": "process.env",
      "enabled": false
    }
  ]
}
```

### Strict Configuration

Maximum security for production environments:

```json
{
  "description": "Strict configuration for production",
  "riskThresholds": {
    "low": 1,
    "medium": 10,
    "high": 30,
    "critical": 50
  },
  "severityWeights": {
    "critical": 60,
    "high": 40,
    "medium": 25,
    "low": 15
  },
  "globalPatternOverrides": [
    {
      "pattern": "eval",
      "severity": "critical"
    },
    {
      "pattern": "fetch",
      "severity": "high"
    }
  ]
}
```

### Network-Focused Configuration

Prioritize detecting data exfiltration:

```json
{
  "description": "Network security focused",
  "globalPatternOverrides": [
    {
      "pattern": "fetch",
      "severity": "critical"
    },
    {
      "pattern": "axios",
      "severity": "critical"
    },
    {
      "pattern": "http.request",
      "severity": "critical"
    },
    {
      "pattern": "socket",
      "severity": "critical"
    }
  ]
}
```

## Pattern Overrides

### Threat Categories (v2.0)

SkillGuard has 305 built-in rules. These five categories are the ones skills most often abuse:

| Category | Examples | Default severity (rule count) |
|----------|----------|------------------|
| **Credential Theft** | Hardcoded secrets, SSH keys, keychains, AWS creds | Mostly High (10 critical, 16 high, 8 medium) |
| **Code Injection** | eval, SSTI, YAML load, reflection | Mostly Critical (30 critical, 13 high) |
| **Prompt Injection** | LLM API misuse, system prompts | High (30 high, 8 medium) |
| **Data Exfiltration** | DNS tunneling, clipboard, keyloggers | Mostly High (6 critical, 25 high, 8 medium) |
| **Evasion Techniques** | Anti-debug, sandbox detection, obfuscation | Mostly High (7 critical, 33 high, 5 medium) |

### Common Patterns by Language

#### JavaScript/TypeScript (40 rules)
- `exec`, `spawn` - Shell execution
- `eval`, `Function`, `vm.runInNewContext` - Code injection
- `fetch`, `axios` - Network access
- `fs.writeFile` - File system write
- **NEW**: `openai`, `anthropic` - Prompt injection
- **NEW**: `dns.lookup`, `clipboard`, `nativeImage.captureScreen` - Data exfiltration
- **NEW**: `atob(...eval)`, `debugger`, `prototype.constructor` - Evasion

#### Python (45 rules)
- `os.system`, `subprocess.call` - Shell execution
- `eval`, `exec`, `yaml.load()`, `Template()` - Code injection
- `requests`, `urllib` - Network access
- `pickle.loads` - Deserialization
- **NEW**: `keyring`, `aws_access_key` - Credential theft
- **NEW**: `openai`, `langchain`, `f"...{user_input}..."` - Prompt injection
- **NEW**: `pyperclip`, `ImageGrab`, `pynput.keyboard` - Data exfiltration
- **NEW**: `base64.b64decode(...exec)`, `getattr` chains - Evasion

#### Java (37 rules)
- `Runtime.exec`, `ProcessBuilder` - Shell execution
- `Class.forName`, `SpEL`, `OGNL` - Reflection/Injection
- `InitialContext.lookup` - JNDI (Log4Shell)
- `ObjectInputStream` - Deserialization
- **NEW**: `KeyStore`, `BasicAWSCredentials` - Credential theft
- **NEW**: `Robot.createScreenCapture`, `KeyListener` - Data exfiltration

#### Go (33 rules)
- `exec.Command` - Shell execution
- `unsafe`, `plugin.Open()` - Unsafe operations
- `os.WriteFile` - File operations
- `http.Get` - Network access
- **NEW**: `clipboard`, `screenshot`, `keyboard.GetKeys` - Data exfiltration
- **NEW**: `antidebug`, `sandbox detection` - Evasion

#### Ruby/PHP/C++/Rust
See the [SECURITY_COVERAGE_REPORT.md](SECURITY_COVERAGE_REPORT.md) for complete pattern lists with 30+ patterns each.

## Language-Specific Settings

Override patterns for specific languages:

```json
{
  "languages": {
    "python": {
      "enabled": true,
      "patternOverrides": [
        {
          "pattern": "subprocess.call",
          "severity": "high",
          "description": "Subprocess is required for this Python service"
        },
        {
          "pattern": "requests.post",
          "severity": "low"
        }
      ]
    },
    "javascript": {
      "enabled": true,
      "patternOverrides": [
        {
          "pattern": "eval",
          "severity": "critical",
          "enabled": true
        },
        {
          "pattern": "fetch",
          "severity": "medium"
        }
      ]
    },
    "cpp": {
      "enabled": false,
      "description": "Disable C++ scanning for this project"
    }
  }
}
```

## Advanced Usage

### Conditional Configuration

You can maintain multiple configuration files for different environments:

```bash
# Development
skillguard scan . --config .skillguardrc.dev.json

# Staging
skillguard scan . --config .skillguardrc.staging.json

# Production
skillguard scan . --config .skillguardrc.prod.json
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Security Scan (Strict)
  run: |
    npx -y https://github.com/heyytars/skillguard/releases/latest/download/skillguard.tgz scan . --config .skillguardrc.strict.json --json > results.json
```

### Pattern Priority

When a pattern is defined in multiple places, SkillGuard uses this priority:

1. Language-specific override (highest priority)
2. Global pattern override
3. Default severity (lowest priority)

## Complete Example

See [`.skillguardrc.example.json`](.skillguardrc.example.json) for a fully documented configuration file with all available options.

## Additional Resources

- [README.md](README.md) - Main documentation
- [examples/configs/](examples/configs/) - Example configuration files
  - `permissive.json` - Development-friendly config
  - `strict.json` - High-security config
  - `network-focused.json` - Data exfiltration detection

## Support

For questions or issues with configuration, please open an issue on GitHub:
https://github.com/heyytars/skillguard/issues
