# PromptShield Jailbreak Patterns & Fixes

## Issue Template Injection (2026-03-16)
- **Jailbreak Technique**: Malicious content injection into GitHub issue templates to bypass input sanitization.
- **Defense Mechanism**: Strict YAML/Markdown template validation + context-aware sanitizer for embedded code.
- **Gist**: `gists/ready/ISSUE-TEMPLATE-INJECTION.md`
- **Status**: Ready for upload

## GitHub Actions Workflow Injection (2026-03-16)
- **Jailbreak Technique**: Malicious PRs modify `.github/workflows/` to inject arbitrary commands, leak secrets, or upload payloads.
- **Defense Mechanism**: Input validation for workflow files, action pinning, secret sanitization, and runner isolation.
- **Gist**: `gists/ready/CI-CD-INJECTION.md`
- **Status**: Ready for upload

## Initial Commit Tokenizer Bypass (2026-03-16)
- **Jailbreak Technique**: Unicode homoglyphs and zero-width spaces bypass strict ASCII-only tokenizer guards.
- **Defense Mechanism**: Unicode NFC normalization + zero-width character stripping pre-processing.
- **Gist**: `gists/ready/INITIAL-COMMIT-BYPASS.md`
- **Status**: Ready for upload

---

> ✅ Local analysis cycle #3 completed. Third pattern captured and stored.
> ✅ Next sync window: 16:00 CST today (in ~34 minutes).