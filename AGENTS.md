# Commit and pull request rules

- Use Conventional Commits: a concise English `type: description` describing the actual behavior.
- Write all commit messages and pull request titles and descriptions in English.
- Never include emojis or co-author attribution, including Co-authored-by trailers.
- Keep the content focused on the essential change. Describe behavior explicitly; do not use development phase names or task identifiers.
- Apply these rules to squash commit titles and bodies as well.
- Merge pull requests only with squash merge. After merging, delete the work branch locally and remotely, then update local main to match remote main.

# Current verification scope

- Use scenario-based unit tests for new defensive verification work. Use explicit test inputs and scripted observations or small test doubles; do not create a simulator in the current scope.
- Do not run vulnerability reproduction probes, live core race diagnostics, or real host bypass tests. Existing raw findings remain historical evidence and must not be erased or promoted to PASS by unit-test results.
- Ordinary Inspector unit tests, including `go test -race`, and read-only validation of archived evidence remain in scope. They must not launch the live reproduction programs.
- Keep unit-test results separate from actual core execution and full protocol conformance. Missing real bindings remain UNSUPPORTED or NOT_RUN as appropriate.
