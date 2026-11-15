# How Strong Is "Strong"? Password guessability visualizer

COMP 435 final project (Track 3), checkpoint prototype. Team: Alex Miller, Ryan Pham, Ted Thavisin, Andre Rastrelly.

Type a password and see how long three attacker models take to reach it: brute force, a leaked-password
dictionary, and a rule-based attack (dictionary words + capitalization, leetspeak, reversal, digits, years,
dates, sequences, keyboard walks). The overall verdict is the weakest of the three. Toggles change the
threat model: offline vs. online, hash algorithm, salted vs. unsalted, size of the stolen dump, and attacker
hardware. A conventional composition-rule meter is shown alongside for contrast.

## Run it

```bash
cd prototype
python3 -m http.server 8000   # then open http://localhost:8000
```

Opening `prototype/index.html` directly also works. The opt-in breach check needs `localhost` or https
in some browsers, because it uses the Web Crypto API.

## Rebuild the wordlists

```bash
bash scripts/fetch_data.sh             # downloads into data/raw/
python3 -I scripts/build_wordlists.py  # writes prototype/wordlists.js
```

## Score sample passwords from the command line

```bash
node scripts/score_samples.js                  # built-in sample set, Markdown table
node scripts/score_samples.js 'Hunter2!' 'abc' # your own
```

## Files

| Path | What it is |
| --- | --- |
| `prototype/index.html` | The visualizer UI |
| `prototype/estimator.js` | The three attack models, scenario rates, time formatting (browser + Node) |
| `prototype/wordlists.js` | Generated: top-100k leaked passwords + 20k English words |
| `scripts/` | Data download, wordlist build, sample scoring |

## Assumptions to know

- Offline speeds: one RTX 4090, hashcat v6.2.6 benchmark
  (<https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd>). PBKDF2 and bcrypt are scaled
  linearly from the benchmarked iteration count to 600,000 iterations and cost 10/12.
- Online speeds: 100 guesses/hour (rate-limited) and 10 guesses/second (no limit), as in zxcvbn.
- Salted + mass attack: each guess costs one hash per account in the dump. Unsalted: one hash tests all
  accounts, and anything already in the public list is treated as an instant lookup-table hit.
- The rule-based model is a minimum-cost segmentation (PCFG / zxcvbn style), with a k! factor for the order
  of pieces. It estimates an upper bound on guesses for these specific attacks, not a guarantee of safety.
