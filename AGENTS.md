# Commit and pull request rules

- Use Conventional Commits: a concise English `type: description` describing the actual behavior.
- Write all commit messages and pull request titles and descriptions in English.
- Never include emojis or co-author attribution, including Co-authored-by trailers, in human/agent-authored commits and pull requests. Dependabot-authored changes are the sole exception.
- Keep the content focused on the essential change. Describe behavior explicitly; do not use development phase names or task identifiers.
- Apply these rules to squash commit titles and bodies as well.
- Merge pull requests only with squash merge. After merging, delete the work branch locally and remotely, then update local main to match remote main.

# Current verification scope

- Implement and run both scenario-based unit tests and runtime tests for changed behavior. Use safe local CLI, IPC, real cryptographic exchanges, and bounded test processes. Exclude attack-capable vulnerability reproduction and host-bypass code; this is not a blanket exclusion of runtime testing.
- Existing attack-capable reproduction programs remain outside execution scope. Ordinary core and Inspector tests, including go test -race, and safe runtime validation are in scope. Preserve historical raw findings instead of promoting them to PASS from unrelated test results.
- Keep unit-test results separate from actual core execution and full protocol conformance. Missing real bindings remain UNSUPPORTED or NOT_RUN as appropriate.
