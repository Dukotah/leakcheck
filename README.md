# LeakCheck

**Find exposed API keys & secrets — in your browser.**

LeakCheck is a client-side secret scanner. Paste your code, `.env`, or config
and instantly see exposed API keys, tokens, and private keys, flagged by
severity. It uses a library of named provider patterns (Stripe, AWS, GitHub,
OpenAI, Google, Slack, and more) plus high-entropy heuristics to surface things
that look like secrets.

A **Copper Bay Labs** product.

- **Live:** https://dukotah.github.io/leakcheck/
- **100% client-side.** Detection runs entirely in your browser. Your code and
  secrets are never uploaded, transmitted, logged, or stored. There is no
  backend — open the Network tab and watch: nothing leaves the page.

## Run it locally

No build step, no dependencies. Just open `index.html` in any modern browser:

```
git clone https://github.com/dukotah/leakcheck.git
cd leakcheck
# open index.html (double-click, or `start index.html` on Windows)
```

Because everything runs locally, you can even disconnect from the network and
it still works.

## What it is (and isn't)

LeakCheck is **heuristic detection**, not a security guarantee or audit. It can
miss real secrets and flag harmless strings. Treat its output as a fast first
pass, not proof your repo is clean. See [How it works](about.html) for the full
methodology, the detection table, and what to do if you find a leaked key.

## Roadmap

- A downloadable **pre-commit / CI ruleset pack** so the same patterns can block
  secrets before they ever land in a commit or pipeline.

---

A [Copper Bay Labs](https://copperbaytech.com) product.
