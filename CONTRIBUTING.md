# Contributing to sakimori

Thanks for your interest in contributing! A few things to know before
you open a pull request.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin][dco] (DCO)
instead of a Contributor License Agreement. The DCO is a lightweight
way for contributors to certify that they wrote — or otherwise have
the right to submit — the code they are contributing.

By signing off on your commits, you are agreeing to the terms of the
DCO (reproduced in full at the bottom of this file).

### How to sign off

Add a `Signed-off-by` trailer to every commit. The easiest way is to
pass `-s` (or `--signoff`) to `git commit`:

```bash
git commit -s -m "fix(proxy): handle empty packument response"
```

This appends a line like:

```
Signed-off-by: Your Name <your.email@example.com>
```

The name and email **must match** your `git config user.name` and
`git config user.email`. Anonymous or pseudonymous sign-offs are not
accepted.

### Fixing a missing sign-off

If you forgot to sign off and the PR has only one commit:

```bash
git commit --amend --signoff
git push --force-with-lease
```

For multi-commit PRs:

```bash
git rebase --signoff main
git push --force-with-lease
```

A bot (or a maintainer) will flag PRs whose commits are not signed off.

## Why DCO and not a CLA?

A CLA would require contributors to grant the project owner additional
rights (typically a copyright assignment or a broad license back). The
DCO instead asks contributors to attest to the origin of their work
and contribute it under the project's existing license
(MIT OR Apache-2.0). This is the same model used by the Linux kernel,
Docker, GitLab, and many others.

If the project's license ever changes in the future, that change will
require either (a) only affecting code written after the change, or
(b) explicit agreement from contributors whose code is affected.

## Style and tests

- Run `cargo fmt` and `cargo clippy --all-targets --all-features` before
  pushing.
- Add tests for new behaviour. The handler traits in `sakimori-core`
  are designed to be mockable — prefer testing logic against a fake
  rather than spinning up real I/O.
- Don't assert on exact error message strings; use substring matches so
  CI stays green across kernel and libc versions.

## Reporting security issues

Please do **not** open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) (if present) or email the maintainer
directly.

---

## Developer Certificate of Origin 1.1

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.


Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

[dco]: https://developercertificate.org/
