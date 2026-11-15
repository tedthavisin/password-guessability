/*
 * estimator.js: password guessability under three attacker models.
 *
 *   1. Brute force   : try every string over the password's character classes, shortest first.
 *   2. Dictionary    : try a frequency-ordered leaked-password list in order (guesses = rank).
 *   3. Rule-based    : dictionary words + mangling rules (capitalization, leetspeak, reversal)
 *                      combined with digits, years, dates, sequences, keyboard walks, repeats.
 *                      Scored with a minimum-cost segmentation, in the spirit of PCFG (Weir et al.,
 *                      IEEE S&P 2009) and zxcvbn (Wheeler, USENIX Security 2016).
 *
 * "Realistic guesses" = the minimum over the three models: the attacker uses whichever finds it first.
 * The scenario (online/offline, hash, salt, hardware) turns guesses into time.
 *
 * Works in the browser (window.Estimator) and in Node (require('./estimator.js')).
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.Estimator = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Attacker speeds
  // ---------------------------------------------------------------------------

  // Offline speed of ONE NVIDIA RTX 4090, hashcat v6.2.6 benchmark:
  // https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd
  // Iterated hashes are scaled linearly from the benchmarked iteration count to a deployed setting.
  const HASHES = {
    ntlm:     { label: 'NTLM', rate: 288.5e9, salt: 'never', note: 'Windows password hash; never salted' },
    md5:      { label: 'MD5', rate: 164.1e9, salt: 'choice' },
    sha1:     { label: 'SHA-1', rate: 50638.7e6, salt: 'choice' },
    sha256:   { label: 'SHA-256', rate: 21975.5e6, salt: 'choice' },
    pbkdf2:   { label: 'PBKDF2-SHA256 (600k iter.)', rate: 8865.7e3 * 999 / 600000, salt: 'always',
                note: 'benchmarked at 999 iterations; scaled to the OWASP-recommended 600,000' },
    bcrypt10: { label: 'bcrypt (cost 10)', rate: 184.0e3 * 32 / 1024, salt: 'always',
                note: 'benchmarked at cost 5 (32 rounds); scaled to cost 10 (1,024 rounds)' },
    bcrypt12: { label: 'bcrypt (cost 12)', rate: 184.0e3 * 32 / 4096, salt: 'always',
                note: 'benchmarked at cost 5 (32 rounds); scaled to cost 12 (4,096 rounds)' },
    scrypt:   { label: 'scrypt (N=16384)', rate: 7126, salt: 'always' },
  };

  // Online guessing against a live login form (rates as in zxcvbn's attack scenarios).
  const ONLINE = {
    throttled:   { label: 'Online, rate-limited', rate: 100 / 3600, note: '100 guesses per hour' },
    unthrottled: { label: 'Online, no rate limit', rate: 10, note: '10 guesses per second' },
  };

  const DEFAULT_SCENARIO = { mode: 'offline', hash: 'md5', salted: false, accounts: 1e6, gpus: 1 };

  // ---------------------------------------------------------------------------
  // Wordlists
  // ---------------------------------------------------------------------------

  let PASSWORD_RANK = new Map(); // exact password -> rank in the leaked list (1-based)
  let WORD_RANK = new Map();     // lowercase base word -> best rank across all lists
  let LIST_SIZE = 0;

  function init(wordlists) {
    PASSWORD_RANK = new Map();
    WORD_RANK = new Map();
    const pw = (wordlists.passwords || '').split('\n');
    LIST_SIZE = pw.length;
    pw.forEach((p, i) => {
      if (!PASSWORD_RANK.has(p)) PASSWORD_RANK.set(p, i + 1);
      const l = p.toLowerCase();
      if (!WORD_RANK.has(l)) WORD_RANK.set(l, i + 1);
    });
    (wordlists.english || '').split('\n').forEach((w, i) => {
      const l = w.toLowerCase();
      const r = i + 1;
      if (!WORD_RANK.has(l) || WORD_RANK.get(l) > r) WORD_RANK.set(l, r);
    });
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  const log10 = Math.log10;
  const SYMBOLS = 33; // printable ASCII that is not a letter or digit, incl. space

  function charClass(c) {
    if (c >= 'a' && c <= 'z') return 'lower';
    if (c >= 'A' && c <= 'Z') return 'upper';
    if (c >= '0' && c <= '9') return 'digit';
    const code = c.charCodeAt(0);
    if (code >= 32 && code < 127) return 'symbol';
    return 'other';
  }
  const CLASS_SIZE = { lower: 26, upper: 26, digit: 10, symbol: SYMBOLS, other: 100 };

  function cardinality(s) {
    const seen = new Set();
    for (const c of s) seen.add(charClass(c));
    let n = 0;
    seen.forEach((k) => { n += CLASS_SIZE[k]; });
    return n;
  }

  function nCk(n, k) {
    if (k > n) return 0;
    let r = 1;
    for (let i = 1; i <= k; i++) r = (r * (n - k + i)) / i;
    return r;
  }

  let FACT_LOG = [0];
  function log10Factorial(k) {
    while (FACT_LOG.length <= k) FACT_LOG.push(FACT_LOG[FACT_LOG.length - 1] + log10(FACT_LOG.length));
    return FACT_LOG[k];
  }

  // Number of capitalization variants an attacker must try to reach this one.
  function capVariations(s) {
    let U = 0, L = 0;
    for (const c of s) {
      if (c >= 'A' && c <= 'Z') U++;
      else if (c >= 'a' && c <= 'z') L++;
    }
    if (U === 0) return 1;
    const first = s[0], last = s[s.length - 1];
    if (L === 0) return 2;
    if (U === 1 && ((first >= 'A' && first <= 'Z') || (last >= 'A' && last <= 'Z'))) return 2;
    let v = 0;
    for (let i = 1; i <= Math.min(U, L); i++) v += nCk(U + L, i);
    return Math.max(v, 2);
  }

  const LEET = {
    '4': ['a'], '@': ['a'], '8': ['b'], '(': ['c'], '{': ['c'], '[': ['c'], '<': ['c'],
    '3': ['e'], '6': ['g'], '9': ['g'], '1': ['i', 'l'], '!': ['i'], '|': ['i', 'l'],
    '0': ['o'], '$': ['s'], '5': ['s'], '7': ['t'], '+': ['t'], '%': ['x'], '2': ['z'],
  };

  // All de-leeted lowercase readings of s (s = letters + leet chars, at least one of each).
  function unleetVariants(s) {
    let variants = [''];
    let subs = 0;
    for (const c of s) {
      const opts = LEET[c];
      if (opts) {
        subs++;
        const next = [];
        for (const v of variants) for (const o of opts) next.push(v + o);
        variants = next.slice(0, 32);
      } else {
        variants = variants.map((v) => v + c.toLowerCase());
      }
    }
    return { variants, subs };
  }

  const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
  function isKeyboardWalk(l) {
    if (l.length < 4) return false;
    return KEYBOARD_ROWS.some((row) => row.includes(l) || row.split('').reverse().join('').includes(l));
  }

  function sequenceInfo(s) {
    if (s.length < 3) return null;
    const cls = charClass(s[0]);
    if (cls !== 'lower' && cls !== 'upper' && cls !== 'digit') return null;
    const d = s.charCodeAt(1) - s.charCodeAt(0);
    if (d !== 1 && d !== -1) return null;
    for (let i = 1; i < s.length; i++) {
      if (charClass(s[i]) !== cls || s.charCodeAt(i) - s.charCodeAt(i - 1) !== d) return null;
    }
    const obvious = 'aAzZ019'.includes(s[0]);
    const base = obvious ? 4 : cls === 'digit' ? 10 : 26;
    return { guesses: base * s.length * (d < 0 ? 2 : 1), desc: d < 0 ? 'descending' : 'ascending' };
  }

  const REFERENCE_YEAR = 2026;
  function yearSpace(y) { return Math.max(Math.abs(y - REFERENCE_YEAR), 20); }

  function digitInfo(s) {
    const n = s.length;
    if (n === 4) {
      const y = +s;
      if (y >= 1900 && y <= 2039) return { kind: 'year', guesses: yearSpace(y), label: `year ${s}` };
    }
    if (n === 8) {
      const y = +s.slice(4), a = +s.slice(0, 2), b = +s.slice(2, 4);
      const okMD = (m, d) => m >= 1 && m <= 12 && d >= 1 && d <= 31;
      if (y >= 1900 && y <= 2039 && (okMD(a, b) || okMD(b, a))) {
        return { kind: 'date', guesses: 365 * yearSpace(y), label: `date ${s}` };
      }
    }
    if (n === 6) {
      const a = +s.slice(0, 2), b = +s.slice(2, 4);
      const okMD = (m, d) => m >= 1 && m <= 12 && d >= 1 && d <= 31;
      if (okMD(a, b) || okMD(b, a)) return { kind: 'date', guesses: 365 * 100, label: `date ${s}` };
    }
    return { kind: 'digits', guesses: Math.pow(10, n), label: `${n} digit${n > 1 ? 's' : ''}` };
  }

  // ---------------------------------------------------------------------------
  // Model 3: rule-based / pattern attack (minimum-cost segmentation)
  // ---------------------------------------------------------------------------

  const MAX_WORD = 30;

  function patternMatches(pw) {
    const n = pw.length;
    const byEnd = Array.from({ length: n + 1 }, () => []);
    const add = (i, j, guesses, kind, label) => {
      const floor = j - i === 1 ? 10 : 50; // no multi-char chunk is cheaper than 50 guesses
      byEnd[j].push({ i, j, token: pw.slice(i, j), kind, label, floored: guesses < floor, log10: log10(Math.max(guesses, floor)) });
    };

    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j <= n; j++) {
        const s = pw.slice(i, j);
        const l = s.toLowerCase();
        const len = j - i;

        // Brute-force chunk over this substring's own character classes.
        add(i, j, Math.pow(cardinality(s), len), 'brute', `${len} random char${len > 1 ? 's' : ''}`);

        if (len > MAX_WORD) continue;

        // Dictionary word (exact, capitalized, reversed, leetspeak).
        if (WORD_RANK.has(l)) {
          const r = WORD_RANK.get(l), cap = capVariations(s);
          add(i, j, r * cap, 'word', `word "${l}" (rank ${r.toLocaleString('en-US')})` + (cap > 1 ? ` × ${cap} capitalizations` : ''));
        }
        const rev = l.split('').reverse().join('');
        if (len >= 3 && rev !== l && WORD_RANK.has(rev)) {
          const r = WORD_RANK.get(rev), cap = capVariations(s);
          add(i, j, r * cap * 2, 'word', `reversed word "${rev}" (rank ${r.toLocaleString('en-US')})` + (cap > 1 ? ` × ${cap} caps` : ''));
        }
        if (len >= 3 && /[a-zA-Z]/.test(s) && /^[a-zA-Z0-9@!$+%|(<{\[]+$/.test(s) && [...s].some((c) => LEET[c])) {
          const { variants, subs } = unleetVariants(s);
          let best = null;
          for (const v of variants) {
            const r = WORD_RANK.get(v);
            if (r && (!best || r < best.r)) best = { v, r };
          }
          if (best) {
            const cap = capVariations(s), leet = Math.pow(2, subs);
            add(i, j, best.r * cap * leet, 'word',
              `word "${best.v}" (rank ${best.r.toLocaleString('en-US')}) × ${leet} leetspeak` + (cap > 1 ? ` × ${cap} caps` : ''));
          }
        }

        // Digits, years, dates.
        if (/^[0-9]+$/.test(s)) {
          const d = digitInfo(s);
          add(i, j, d.guesses, d.kind, d.label);
        }

        // Sequences (abc, 4321), repeats (aaaa), keyboard walks (qwerty, asdf).
        const seq = sequenceInfo(s);
        if (seq) add(i, j, seq.guesses, 'sequence', `${seq.desc} sequence "${s}"`);
        if (len >= 3 && s.split('').every((c) => c === s[0])) {
          add(i, j, CLASS_SIZE[charClass(s[0])] * len, 'repeat', `"${s[0]}" repeated ${len}×`);
        }
        if (isKeyboardWalk(l)) {
          add(i, j, 60 * len * capVariations(s), 'keyboard', `keyboard walk "${s}"`);
        }
      }
    }
    return byEnd;
  }

  function patternAttack(pw) {
    const n = pw.length;
    if (n === 0) return { log10: 0, segments: [] };
    const byEnd = patternMatches(pw);
    const K = Math.min(n, 12);
    const best = Array.from({ length: n + 1 }, () => new Array(K + 1).fill(Infinity));
    const back = Array.from({ length: n + 1 }, () => new Array(K + 1).fill(null));
    best[0][0] = 0;
    for (let j = 1; j <= n; j++) {
      for (const m of byEnd[j]) {
        for (let k = 1; k <= K; k++) {
          const prev = best[m.i][k - 1];
          if (prev === Infinity) continue;
          const v = prev + m.log10;
          if (v < best[j][k]) { best[j][k] = v; back[j][k] = m; }
        }
      }
    }
    // The attacker must also guess how the pieces are ordered: multiply by k!.
    let bestK = 1, bestTotal = Infinity;
    for (let k = 1; k <= K; k++) {
      const t = best[n][k] + log10Factorial(k);
      if (t < bestTotal) { bestTotal = t; bestK = k; }
    }
    const segments = [];
    let j = n, k = bestK;
    while (j > 0 && k > 0) {
      const m = back[j][k];
      segments.unshift({ token: m.token, kind: m.kind, label: m.label, log10: m.log10, floored: m.floored });
      j = m.i; k--;
    }
    return { log10: bestTotal, segments, orderFactor: bestK };
  }

  // ---------------------------------------------------------------------------
  // Models 1 and 2
  // ---------------------------------------------------------------------------

  function bruteForce(pw) {
    const L = pw.length;
    const C = cardinality(pw);
    if (L === 0) return { log10: 0, charset: 0, length: 0 };
    // Keyspace of all strings of length 1..L over C symbols: (C^(L+1) - C) / (C - 1).
    const lg = L * log10(C) + log10(C / (C - 1)) + log10(1 - Math.pow(C, -L));
    return { log10: lg, charset: C, length: L };
  }

  function dictionary(pw) {
    const rank = PASSWORD_RANK.get(pw);
    return rank ? { rank, log10: log10(rank), listSize: LIST_SIZE } : { rank: null, log10: Infinity, listSize: LIST_SIZE };
  }

  // A typical composition-rule ("LUDS") strength meter, as found on many sign-up forms.
  function conventionalMeter(pw) {
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    if (pw.length < 8) score = Math.min(score, 1);
    const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong', 'Strong'];
    return { score, max: 5, label: pw.length ? labels[score] : '' };
  }

  // ---------------------------------------------------------------------------
  // Put it together
  // ---------------------------------------------------------------------------

  function estimate(pw) {
    const bf = bruteForce(pw);
    const dict = dictionary(pw);
    let pat = patternAttack(pw);
    // A "pattern" made only of random chunks is just brute force; don't credit the rule model with it.
    const structured = pat.segments.some((s) => s.kind !== 'brute');
    if (!structured) pat = { log10: bf.log10, segments: pat.segments, orderFactor: 1, none: true };

    const models = { bruteforce: bf.log10, dictionary: dict.log10, rules: pat.log10 };
    let weakest = 'bruteforce';
    for (const k of ['dictionary', 'rules', 'bruteforce']) if (models[k] < models[weakest]) weakest = k;
    if (models.dictionary <= models[weakest]) weakest = 'dictionary';

    return {
      password: pw,
      bruteforce: bf,
      dictionary: dict,
      rules: pat,
      overall: { log10: Math.min(bf.log10, dict.log10, pat.log10), weakest },
      conventional: conventionalMeter(pw),
    };
  }

  // Guesses per second the attacker spends on THIS account, plus scenario flags.
  function resolveScenario(sc) {
    sc = Object.assign({}, DEFAULT_SCENARIO, sc);
    if (sc.mode !== 'offline') {
      const o = ONLINE[sc.mode];
      return { rate: o.rate, salted: null, precomputed: false, label: `${o.label} (${o.note})` };
    }
    const h = HASHES[sc.hash];
    const salted = h.salt === 'always' ? true : h.salt === 'never' ? false : !!sc.salted;
    const raw = h.rate * sc.gpus;
    // Salted: each guess must be hashed separately for every account in the dump.
    // Unsalted: one hash tests a guess against every account, and lookup tables are possible.
    const rate = salted ? raw / sc.accounts : raw;
    return {
      rate, rawRate: raw, salted, precomputed: !salted, hash: h,
      label: `Offline, ${h.label}, ${salted ? 'salted' : 'unsalted'}, ${sc.gpus} GPU${sc.gpus > 1 ? 's' : ''}`,
    };
  }

  // Seconds to reach the password under each model for a given scenario.
  function times(est, sc) {
    const r = resolveScenario(sc);
    const t = (lg) => (lg === Infinity ? Infinity : Math.pow(10, lg) / r.rate);
    const out = {
      scenario: r,
      bruteforce: { seconds: t(est.bruteforce.log10) },
      dictionary: { seconds: t(est.dictionary.log10) },
      rules: { seconds: t(est.rules.log10) },
    };
    // Unsalted + already in a public list = a precomputed lookup table cracks it with no guessing.
    if (r.precomputed && est.dictionary.rank) out.dictionary = { seconds: 0, lookup: true };
    const all = ['bruteforce', 'dictionary', 'rules'];
    let weakest = all[0];
    for (const k of all) if (out[k].seconds < out[weakest].seconds) weakest = k;
    if (out.dictionary.seconds <= out[weakest].seconds) weakest = 'dictionary';
    out.overall = { seconds: out[weakest].seconds, weakest, lookup: !!out[weakest].lookup };
    return out;
  }

  function formatSeconds(s) {
    if (s === Infinity) return 'not applicable';
    if (s < 1) return 'instantly';
    const units = [
      ['second', 1], ['minute', 60], ['hour', 3600], ['day', 86400],
      ['month', 2629800], ['year', 31557600], ['century', 3155760000],
    ];
    if (s >= 31557600 * 1e6) {
      const y = log10(s / 31557600);
      return `~10^${Math.floor(y)} years`;
    }
    let u = units[0];
    for (const x of units) if (s >= x[1]) u = x;
    const v = s / u[1];
    const n = v >= 100 ? Math.round(v).toLocaleString('en-US') : v >= 10 ? Math.round(v) : Math.round(v * 10) / 10;
    const plural = u[0] === 'century' ? 'centuries' : `${u[0]}s`;
    return `${n} ${n === 1 ? u[0] : plural}`;
  }

  function formatGuesses(lg) {
    if (lg === Infinity) return 'n/a';
    if (lg < 6) return Math.round(Math.pow(10, lg)).toLocaleString('en-US');
    return `10^${lg.toFixed(1)}`;
  }

  // 0 (crackable instantly) .. 1 (beyond a century): drives the red-to-green colour.
  function safety(seconds) {
    if (seconds <= 0) return 0;
    if (seconds === Infinity) return 1;
    const lo = 0, hi = log10(3155760000); // 1 second .. 100 years
    return Math.min(1, Math.max(0, (log10(seconds) - lo) / (hi - lo)));
  }

  function verdict(seconds) {
    if (seconds < 1) return 'Cracked instantly';
    if (seconds < 3600) return 'Cracked in under an hour';
    if (seconds < 86400 * 30) return 'Cracked within a month';
    if (seconds < 31557600 * 100) return 'Resists for years';
    return 'Out of practical reach';
  }

  return {
    init, estimate, times, resolveScenario, formatSeconds, formatGuesses, safety, verdict,
    HASHES, ONLINE, DEFAULT_SCENARIO,
    get listSize() { return LIST_SIZE; },
  };
});
