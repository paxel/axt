# Security policy

## Supported versions

AXT is a draft; no version has been released yet. Once versions are released, only the latest one gets security fixes.

## Reporting a vulnerability

Report it privately through GitHub's [private vulnerability reporting](https://github.com/paxel/axt/security/advisories/new) (the repository's **Security** tab, **Report a vulnerability**). Do not open a public issue, pull request or discussion for it.

Describe what an attacker gains. For the specification: a message that a conforming receiver accepts although its signature, its sender or its addressee is wrong; a way for a relay or a third party to read or change a record; a way to bring back, replace or delete another sender's record. For the reference relay and the conformance suite: a request that reads another mailbox, input that runs as code, a secret that leaks into a log.

The report and its fix are discussed in that advisory, which stays private until the fix is published.

## What is already checked

The repository is held to the standard of [paxel/gates](https://github.com/paxel/gates): CodeQL, OpenSSF Scorecard, SonarQube Cloud, the OSV gate on the locked dependencies, the alert gate, strict lint and type checks, a coverage ratchet and weekly fuzzing. Every change runs the conformance suite against the reference adapter and the reference relay and compares the committed test vectors with the generator's output.

Every key, secret and certificate in the specification's examples and in the test vectors is a test value ([spec/keys.md](spec/keys.md), section 7.1) and is not a leak.
