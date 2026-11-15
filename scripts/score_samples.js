// Score a handful of passwords with the prototype estimator and print a Markdown table.
// Usage: node scripts/score_samples.js [password ...]
const path = require('path');
const E = require(path.join(__dirname, '..', 'prototype', 'estimator.js'));
E.init(require(path.join(__dirname, '..', 'prototype', 'wordlists.js')));

const SAMPLES = process.argv.slice(2).length ? process.argv.slice(2) : [
  'password', 'P@ssw0rd!', 'Summer2024!', 'Dragon$2025', 'Jessica1990', 'iloveyou123',
  'qwerty12345', 'Tr0ub4dor&3', 'correcthorsebatterystaple', 'blue-Otter-candle-91', 'Xk9#mQ2$vL', 'kT7#q',
];

const FAST = { mode: 'offline', hash: 'md5', salted: false, gpus: 1 };
const SLOW = { mode: 'offline', hash: 'bcrypt10', salted: true, accounts: 1e6, gpus: 1 };
const NAME = { bruteforce: 'brute force', dictionary: 'dictionary', rules: 'rule-based' };

const time = (t) => (t.overall.lookup ? 'instantly (lookup table)' : E.formatSeconds(t.overall.seconds));

console.log('| Password | Conventional meter | Realistic guesses | Weakest attack | MD5, unsalted | bcrypt-10, salted, 1M-account dump |');
console.log('| --- | --- | --- | --- | --- | --- |');
for (const pw of SAMPLES) {
  const est = E.estimate(pw);
  const row = [
    '`' + pw + '`',
    est.conventional.label,
    E.formatGuesses(est.overall.log10),
    NAME[est.overall.weakest],
    time(E.times(est, FAST)),
    time(E.times(est, SLOW)),
  ];
  console.log('| ' + row.join(' | ') + ' |');
}
