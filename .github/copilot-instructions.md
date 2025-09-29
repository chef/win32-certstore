<!-- AUTOMATION / AI ASSISTANT OPERATIONAL GUIDE -->

# AI / Copilot Operational Instructions for `chef/win32-certstore`

> This document defines the authoritative, non-destructive, prompt-driven workflow for AI-assisted contributors (human or automated) working in this repository. All actions MUST follow the policies, safeguards, and step gates described here. Deviations require explicit maintainer approval.

---

## 1. Purpose
Provide a clear, enforceable process for implementing changes (feature, bug, maintenance, docs) with: Jira-driven planning, deterministic branching & PR standards, mandatory test & coverage expectations (>80%), Expeditor + CI awareness, label governance, and DCO-compliant commits. Every major step is iterative: output a summary, remaining checklist, then explicitly ask: `Continue to next step? (yes/no)` before advancing.

---

## 2. Repository Structure (Condensed)
Only key source, config, and automation paths are listed (policy/licensing files are protected — do not modify without approval).

```
.
├── Gemfile                  # Ruby gem dependencies (delegates to gemspec)
├── win32-certstore.gemspec  # Gem specification (name, version file, runtime deps)
├── VERSION                  # Canonical version file (Expeditor bumps)
├── Rakefile                 # RSpec + style tasks (default: spec + style)
├── lib/
│   ├── win32-certstore.rb   # Primary file requiring internal components
│   └── win32/
│       ├── certstore.rb     # Public API façade
│       └── certstore/
│           ├── store_base.rb # Base logic for certificate store interactions
│           ├── version.rb    # VERSION constant synced from root VERSION
│           └── mixin/
│               ├── assertions.rb # Validation helpers
│               ├── crypto.rb     # Cryptographic helper logic
│               ├── helper.rb     # General utilities
│               ├── string.rb     # String manipulation helpers
│               └── unicode.rb    # Windows Unicode conversions
├── spec/
│   ├── spec_helper.rb       # RSpec configuration (platform gating)
│   ├── win32/functional/... # Functional specs (Windows dependent)
│   ├── win32/unit/...       # Unit specs by component
│   └── win32/assets/        # Test fixture certificates (.pfx, .pem)
├── .github/
│   ├── workflows/
│   │   ├── unit.yml         # Windows matrix unit tests (Ruby 3.1, 3.2, 3.4)
│   │   └── lint.yml         # Lint/style via cookstyle on Ubuntu
│   ├── PULL_REQUEST_TEMPLATE.md # Legacy PR template (superseded by HTML sectioning here)
│   ├── ISSUE_TEMPLATE.md    # Issue intake template
│   ├── dependabot.yml       # Automated dependency update config
│   ├── CODEOWNERS           # Review responsibility mapping
│   └── copilot-instructions.md # (THIS FILE) Operational AI guidance
└── .expeditor/
	├── config.yml           # Expeditor automation: version bump, changelog, publish
	├── update_version.sh    # Syncs lib version constant post bump
	├── verify.pipeline.yml  # Buildkite / verification pipeline configuration
	└── verify_win32certstore.ps1 # Windows test harness & environment prep
```

Protected / Policy Files (DO NOT MODIFY unless explicitly told): `LICENSE`, `CODE_OF_CONDUCT.md`, `README.md` (structural edits require approval), `.expeditor/*`, `.github/workflows/*`, `CODEOWNERS`.

---

## 3. Tooling & Ecosystem
Language: Ruby (library gem focused on Windows certificate store handling).

Primary Toolchain:
- Ruby Versions (CI): 3.1, 3.2, 3.4 (Windows); lint uses 3.0 (ubuntu) for cookstyle.
- Test Framework: RSpec (invoked via `rake spec`).
- Style / Lint: Cookstyle (Chef-flavored RuboCop) via `rake style` or `cookstyle --chefstyle -c .rubocop.yml`.
- Packaging / Release: Expeditor automates version bumps & rubygems publish.
- CI Systems:
  - GitHub Actions (`unit.yml`, `lint.yml`).
  - Buildkite via Expeditor pipeline (`.expeditor/verify.pipeline.yml`) for extended validation.

Coverage: Not currently instrumented. To enforce >=80% requirement, add SimpleCov in `spec/spec_helper.rb` (see Section 9) when implementing test-impacting changes. AI MUST propose and apply instrumentation if missing when coverage evaluation is requested.

---

## 4. MCP (Jira) Integration
All Jira interactions MUST use the `atlassian-mcp-server` (Model Context Protocol). No direct REST manual crafting unless server unavailable.

Standard Pattern:
1. Input: Jira ID (e.g., `ABC-123`).
2. Invoke (conceptual): `atlassian-mcp-server getIssue <JIRA_ID>`.
3. Parse Fields: summary, description, acceptance criteria (bulletize), linked issues, story points, component, labels.
4. Construct Plan Object:
   - Design / Approach
   - Impacted Files (create vs modify vs delete)
   - Test Strategy (unit, functional, fixtures needed)
   - Edge Cases
   - Risk & Mitigations
5. Present plan, request confirmation: `Continue to next step? (yes/no)`.
6. Only after YES: begin implementation workflow.

If no Jira ID is provided: treat request as freeform; still create a structured plan and ask for confirmation.

---

## 5. Workflow Overview (High-Level Gates)
Each numbered phase MUST end with: (a) Step Summary, (b) Remaining Checklist (markdown checkboxes), (c) Prompt: `Continue to next step? (yes/no)`.

1. Intake & Clarify
2. Jira Fetch (if ID supplied)
3. Repository Analysis (structure, tests, CI, gaps)
4. Implementation Plan Draft
5. Plan Confirmation
6. Branch Creation
7. Incremental Code Changes + Tests
8. Style / Lint
9. Test & Coverage Verification
10. Commit (DCO Signed) & Push
11. PR Creation & Enrichment (HTML template)
12. Label Application
13. Post-Implementation Summary (diff stats, coverage delta)
14. Await Further Actions / Close Loop

At ANY refusal (no), pause and await new instructions — never proceed automatically.

---

## 6. Detailed Step Instructions

### 6.1 Intake & Clarify
Gather: goal statement, Jira ID (optional), expected acceptance criteria. If ambiguous, request minimal clarifications (avoid over-questioning). Output initial interpretation.

### 6.2 Jira Retrieval (Conditional)
Invoke MCP server (pseudo):
```
atlassian-mcp-server getIssue ABC-123
```
Parse into a structured markdown block:
```
Jira: ABC-123
Summary: ...
Acceptance Criteria:
 - ...
Linked Issues: ...
Story Points: N (if present)
Labels: [...]
```

### 6.3 Repository Analysis
Confirm presence/absence of coverage, affected modules, existing tests for target areas; note if SimpleCov needs enabling.

### 6.4 Plan Draft
Provide sections: Design, Data / API Impact, File Operations, Test Strategy (unit/functional), Edge Cases (≥3), Risk, Rollback.

### 6.5 Plan Confirmation
Ask for explicit approval before code changes.

### 6.6 Branch Creation
Branch Name:
- If Jira: exact `ABC-123`.
- Else: kebab slug (e.g., `feature-add-x`) — avoid slashes.

Commands:
```
git fetch origin
git checkout -b ABC-123 origin/master
```
If branch exists: checkout and continue (idempotent behavior).

### 6.7 Implement Incrementally
For each cohesive change:
1. Modify/add source.
2. Add/update tests.
3. Run specs locally:
```
bundle exec rake spec
```
4. If Windows-specific logic: note that local macOS run skips Windows-only specs (guarded by platform conditions). Ensure logic separation remains testable.

### 6.8 Style / Lint
```
bundle exec rake style
```
Or direct:
```
cookstyle --chefstyle -c .rubocop.yml
```
Resolve all offenses unless explicitly waived with justification.

### 6.9 Coverage ≥ 80%
If SimpleCov not yet installed, add (AI may apply patch when implementing feature):
```ruby
# At top of spec/spec_helper.rb
require 'simplecov'
SimpleCov.start do
  enable_coverage :branch
  minimum_coverage 80
  add_filter '/spec/'
end
```
Then rerun:
```
bundle exec rake spec
```
If below threshold: identify uncovered files (use `coverage/index.html` if generated) and add tests until compliance.

### 6.10 Commit (DCO)
Commit message format:
```
<Jira-ID|Scope>: Short imperative summary

Longer explanation (wrap ~72 cols). Include rationale & notable test changes.

Signed-off-by: Full Name <email@example.com>
```
Example:
```
ABC-123: Add certificate chain parsing helper

Implements chain traversal to support future trust validation. Adds unit tests for edge cases (empty, malformed). Increases coverage of mixin/crypto.

Signed-off-by: Jane Doe <jane.doe@example.com>
```
Refuse to proceed if sign-off line missing.

Commands:
```
git add .
git commit -m "ABC-123: Add certificate chain parsing helper" -m "Signed-off-by: Jane Doe <jane.doe@example.com>"
```

### 6.11 Push & PR Creation
```
git push -u origin ABC-123
gh pr create --base master --head ABC-123 --title "ABC-123: Add certificate chain parsing helper" --draft --fill
```
Then patch description to HTML template (Section 7). Remove `--draft` when ready.

### 6.12 Labels
Apply type + triage + platform (if relevant). Expeditor bump labels only if version bump intentionally needed (minor/major). Avoid misuse of skip labels.

### 6.13 Post-Implementation Summary
Report: files changed, additions/deletions, test run result (pass/fail), coverage delta, risk, follow-ups.

### 6.14 Finalize / Await Merge
Do NOT merge; maintainers handle merge (Expeditor handles release). Ensure branch up to date: `git fetch origin && git rebase origin/master` (or merge if policy prefers) before marking ready.

---

## 7. Branching & PR Standards
Branch Naming:
- Jira-backed: exact Jira key (uppercase) e.g., `ABC-123`.
- Non-Jira: `chore-*`, `feature-*`, `bugfix-*` descriptive slug.

PR Description (HTML Template):
```html
<h2>Summary</h2>
<p>Short high-level explanation.</p>
<h2>Jira</h2>
<p><a href="https://your-jira/browse/ABC-123">ABC-123</a></p>
<h2>Changes</h2>
<ul>
  <li>...</li>
</ul>
<h2>Tests & Coverage</h2>
<p>RSpec pass summary, coverage % before → after.</p>
<h2>Risk & Mitigations</h2>
<p>Potential regressions + safeguards.</p>
<h2>Labels Applied</h2>
<p>Type: Enhancement; Platform: Windows; etc.</p>
<h2>DCO</h2>
<p>All commits signed off.</p>
```

Draft vs Final:
- Keep Draft until: tests green, lint clean, coverage verified, description finalized.
- Mark Ready: remove draft state via GitHub UI or `gh pr ready`.

Required / Expected Checks:
- GitHub Actions: `unit`, `lint` must succeed.
- (If invoked) Buildkite verification via Expeditor.

Re-run Workflows:
```
gh run list --limit 5
gh run rerun <run-id>
```
Or via GitHub UI (Re-run jobs).

Merge Strategy:
- Maintainers typically perform squash or merge; do not force push after review unless rebasing to resolve conflicts (retain sign-offs).
- Never self-merge.

Idempotency:
- If PR already exists, update branch & push.
- If branch exists locally, reuse; do not recreate.

---

## 8. Commit & DCO Policy
All commits MUST end with a single valid sign-off line:
`Signed-off-by: Full Name <email@domain>`

Validation Steps:
1. Reject unsigned commits (amend with `git commit --amend -s`).
2. Multi-author contributions: each author authors their own signed commit (avoid co-authored lines unless necessary).
3. Never fabricate another person's sign-off.

---

## 9. Testing & Coverage Guidance
Run All Tests:
```
bundle exec rake spec
```

Platform Notes:
- macOS/Linux will skip Windows-only tests (guarded). Do not remove guards.
- For Windows-specific changes, rely on CI matrix to validate or use a Windows environment (e.g., GitHub Codespaces with Windows or local VM).

Adding Coverage (if missing):
1. Add SimpleCov snippet (Section 6.9).
2. Add `simplecov` to development/test group (Gemfile) if needed.
3. Commit instrumentation separately (with DCO).

Coverage Enforcement Flow:
1. Run tests → collect coverage.
2. If <80%, list top 3 files by uncovered lines.
3. Add targeted specs.
4. Re-run until threshold met.

Edge Case Expectations (example categories):
- Empty / nil certificate input
- Corrupt / malformed PFX
- Unicode alias handling
- Permission / store access denial
- Large chain enumeration

---

## 10. Labels Reference
Strategic label mapping (Type + Aspect + Platform + Priority + Status + Triage). Apply the minimal meaningful set.

Repository Labels (name – description):
- Aspect: Documentation – How do we use this project?
- Aspect: Integration – Works correctly with other projects or systems.
- Aspect: Packaging – Distribution of compiled or releasable artifacts.
- Aspect: Performance – Efficiency without negative system impact.
- Aspect: Portability – Cross-platform behavior.
- Aspect: Security – Stability against malicious access.
- Aspect: Stability – Consistent results.
- Aspect: Testing – Test coverage & CI health.
- Aspect: UI – Interface interaction & design.
- Aspect: UX – User experience & accessibility.
- Chef 17.11 – (Version-specific context).
- dependencies – Dependency file updates (Dependabot, etc.).
- DO NOT MERGE – Block merging (investigation / WIP risk).
- Expeditor: Bump Version Major – Trigger major version bump.
- Expeditor: Bump Version Minor – Trigger minor version bump.
- Expeditor: Skip All – Skip all Expeditor actions.
- Expeditor: Skip Changelog – Omit changelog update.
- Expeditor: Skip Habitat – Skip habitat package build.
- Expeditor: Skip Omnibus – Skip omnibus release build.
- Expeditor: Skip Version Bump – Prevent version increment.
- hacktoberfest-accepted – Qualifies for Hacktoberfest credit.
- oss-standards – OSS standardization tasks.
- Platform: AWS / Azure / Debian-like / Docker / GCP / Linux / macOS / RHEL-like / SLES-like / Unix-like / VMware / Windows – Platform targeting.
- Priority: Critical / Medium / Low – Urgency.
- ruby – Ruby code change.
- Status: Adopted – Being actively worked.
- Status: Good First Issue – Starter friendly.
- Status: Help Wanted – Needs contributor assistance.
- Status: Incomplete – PR not ready.
- Status: Sustaining Backlog – Long-term queue candidate.
- Status: Untriaged – Awaiting triage.
- Status: Waiting on Contributor – Pending author updates.
- Triage: Confirmed / Declined / Duplicate / Feature Request / Needs Information / Not Reproducible / Support – Triage outcome classification.
- Type: Breaking Change – Backwards-incompatible change.
- Type: Bug – Incorrect behavior.
- Type: Chore – Non-critical maintenance.
- Type: Deprecation – Feature removal path.
- Type: Design Proposal – Survey / proposal discussion.
- Type: Enhancement – New functionality.
- Type: Regression – Previously working behavior broken.
- Type: Tech Debt – Refactor / cleanup.

Minimum Label Set Recommendation:
- Always include one Type + (optional) Platform + (optional) Aspect + (optional) Priority + lifecycle (Status / Triage as applicable).

---

## 11. CI / Expeditor Integration

GitHub Actions Workflows:
1. `unit.yml` – Triggers on `push` to `master` & PRs; runs Windows matrix (Ruby 3.1, 3.2, 3.4) executing `bundle exec rake spec`.
2. `lint.yml` – Triggers on PR + push to `main`; runs cookstyle lint (Ruby 3.0). Note: Default branch naming discrepancy (`master` vs `main`); confirm canonical default (`master` appears in unit workflow & branching examples). Do NOT alter without maintainer direction.

Expeditor (`.expeditor/config.yml`):
- Auto version bump on PR merge (unless skip labels present).
- Adds changelog rollup section.
- Builds gem and publishes to rubygems after bump.
- Deletes merged PR branches automatically.
- Controlled by labels: major/minor bump, skip actions.

Buildkite Pipeline (`.expeditor/verify.pipeline.yml`):
- Validates on Windows images with Ruby versions (3.1, 3.4) via PowerShell script.

PowerShell Harness (`verify_win32certstore.ps1`):
- Prepares Windows environment (Chef client, node, cspell), prunes conflicting DLLs, runs specs.

Guardrails:
- Do not modify Expeditor/Buildkite config unless explicitly tasked.
- Avoid adding secrets into workflows or scripts.

---

## 12. Security & Protected Files
NEVER:
- Commit secrets, tokens, credentials.
- Modify `LICENSE`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, or `.expeditor/*`, `.github/workflows/*` without approval.
- Force-push to `master` (or default branch) or rewrite shared history.
- Merge PRs.

ALWAYS:
- Review diff for binary artifacts (reject large or unnecessary binaries).
- Reference only documented public APIs — avoid monkey patches unless justified.

---

## 13. Prompts Pattern (Interaction Model)
Each major automation message MUST follow this skeleton:
```
Step: <Phase Name>
Summary: <1–3 sentences>
Checklist:
- [x] Completed prior steps
- [ ] Next actionable item
Recommendation: <suggested next prompt user can copy>
Continue to next step? (yes/no)
```

Example After Plan Draft:
```
Step: Plan Draft
Summary: Proposed design for ABC-123 covering parsing + test expansion.
Checklist:
- [x] Fetched Jira
- [x] Analyzed repository
- [x] Drafted plan
- [ ] Awaiting approval to create branch
Recommendation: Reply "yes" or ask: Refine risk analysis.
Continue to next step? (yes/no)
```

If user replies `no`: respond with clarifying questions or revised plan, then re-ask.

---

## 14. Environment Preparation
macOS / Linux (development):
```
ruby -v                # Ensure compatible (>=3.1 recommended)
gem install bundler
bundle install
bundle exec rake spec  # Run tests (Windows-only ones skipped automatically)
bundle exec rake style # Lint
```

Windows (optional for deeper validation):
1. Install Ruby (matching CI matrix) & Git.
2. `gem install bundler` then `bundle install`.
3. Run `bundle exec rake spec` (ensures Windows-only logic exercised).

Add Coverage (if enforcing):
```
bundle add simplecov --group "test"
```
Insert SimpleCov start block at top of `spec/spec_helper.rb` (see Section 6.9) and re-run specs.

GitHub CLI Setup (No ~/.profile Edits):
```
gh auth login  # Follow interactive prompts; avoid referencing shell profile files.
```

---

## 15. Validation & Exit Criteria
An implementation task is COMPLETE when:
1. Acceptance criteria (Jira or agreed freeform) fully met.
2. All new/changed logic covered by tests; overall coverage ≥ 80% (or improved if instrumentation newly added).
3. Lint/style clean (no unresolved offenses).
4. All commits DCO-signed.
5. PR description populated with HTML sections & accurate label set.
6. CI (unit + lint + any Buildkite jobs) green.
7. Risks documented + mitigations listed.
8. No protected files modified without authorization.
9. Awaiting maintainer merge (do not self-merge unless directed).

Final Output Before Idle:
```
Summary: Implementation complete; awaiting review.
Checklist:
- [x] Tests pass
- [x] Coverage ≥ 80%
- [x] Lint clean
- [x] PR ready
Continue to next step? (yes/no)
```

If further enhancements requested, restart phase cycle at Planning (Section 6.4) using existing branch (or new branch if scope diverges significantly).

---

## 16. Quick Reference Commands
```
# Install deps
bundle install

# Run tests + style
bundle exec rake spec
bundle exec rake style

# Add SimpleCov (if absent)
bundle add simplecov --group "test"

# New branch (Jira)
git checkout -b ABC-123 origin/master

# Commit with DCO
git commit -m "ABC-123: Short summary" -m "Signed-off-by: Full Name <email@example.com>"

# Push + PR
git push -u origin ABC-123
gh pr create --base master --head ABC-123 --title "ABC-123: Short summary" --draft --fill
```

---

## 17. Idempotency & Recovery
- Re-running a step MUST detect existing artifacts (branch, PR, coverage instrumentation) and skip recreation.
- If merge conflicts: rebase or merge master, re-run tests, update PR.
- If CI flake: re-run selective job (do not spam reruns).
- If coverage instrumentation newly added: expect initial lower baseline; future deltas compared post-instrumentation.

---

## 18. Safeguard Summary (Do / Do Not)
Do:
- Ask before each major transition.
- Maintain minimal, cohesive commits.
- Explicitly document deviations.

Do Not:
- Modify secrets, tokens, credential stores.
- Commit generated large binaries or archives.
- Rewrite history on shared branches.
- Change release automation or workflows casually.

---

## 19. Template Prompt Starters
- "Fetch Jira ABC-123 and draft a plan"
- "Analyze current test coverage hotspots for mixin/crypto.rb"
- "Propose additional unit tests to raise coverage above 85%"
- "Generate DCO-compliant commit message for ABC-123 implementing chain parsing"
- "Summarize PR changes and produce HTML description block"

---

## 20. Final Note
This document MUST be appended (not overwritten) if extended. Any structural change requires maintainer agreement. Always preserve guardrails and DCO language. When in doubt: pause and ask.
