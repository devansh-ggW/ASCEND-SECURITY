# ASCEND Security

**Browser-first scam, link and file analysis.**

ASCEND is a lightweight security project focused on making suspicious digital content easier to inspect and understand.

## What is live

- URL analysis for HTTPS, raw IPs, Punycode, unusual ports, redirects, shorteners, obfuscation and suspicious language.
- Message analysis for urgency, credential requests, payment pressure, fake rewards, account threats and remote-access bait.
- Local file inspection for metadata, executable/script indicators, suspicious double extensions, PE/MZ signatures and SHA-256 fingerprints.
- Explainable findings instead of a black-box score.
- No file upload or file execution in the browser analyzer.
- Responsive terminal-inspired interface designed to stay lightweight.

## Important limitation

This is **not a full antivirus** and it does not claim to detect every malware sample. The current website uses local heuristic checks. A deeper protection layer will require a secure backend, reputation intelligence and isolated analysis infrastructure.

Never execute an unknown file just because ASCEND reports a low signal.

## GitHub Pages

The site is static HTML/CSS/JavaScript and can be published with GitHub Pages. GitHub Pages supports static files, but GitHub states that Pages is not intended to operate a commercial SaaS or online business, so production ASCEND services should move to appropriate application hosting as the project grows.

## Roadmap

1. Browser-first analysis — current
2. Secure reputation API / backend
3. URL and domain reputation intelligence
4. Isolated file-analysis pipeline
5. Desktop protection app
6. Continuous monitoring and user-controlled alerts

## Project structure

```text
index.html   # landing page + scanner UI
styles.css   # visual system and responsive layout
app.js       # local analysis engine
.nojekyll    # static publishing helper
```

Built for the DEWIFY product ecosystem.
