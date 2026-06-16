/**
 * analyzer.js — Server-side password strength analysis.
 * Uses zxcvbn for pattern detection + custom entropy calculation.
 * NOTE: The blueprint recommends client-side analysis for privacy.
 * This module powers the optional POST /analyze endpoint for non-browser clients (CLI, etc.).
 */

const zxcvbn = require('zxcvbn');

const LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];

/**
 * Compute Shannon entropy in bits based on charset size and length.
 * Formula: entropy = log2(charset_size ^ length)
 */
function computeEntropy(password) {
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 33;
  if (charsetSize === 0) return 0;
  return Math.round(Math.log2(Math.pow(charsetSize, password.length)) * 100) / 100;
}

/**
 * Detect structural weaknesses and produce plain-language penalties.
 */
function detectPenalties(password, zxcvbnResult) {
  const penalties = [];

  if (password.length < 8) {
    penalties.push({ type: 'too_short', detail: 'Password is too short — use at least 12 characters.' });
  }
  if (/(.)\1{2,}/.test(password)) {
    penalties.push({ type: 'repeated_chars', detail: 'Repeated characters detected (e.g., "aaa") — avoid repetition.' });
  }
  if (/qwerty|asdfgh|zxcvbn|12345|abcde/i.test(password)) {
    const match = password.match(/qwerty|asdfgh|zxcvbn|12345|abcde/i);
    penalties.push({ type: 'keyboard_walk', detail: `Keyboard walk pattern detected: "${match[0]}" — avoid sequential key patterns.` });
  }
  if (/p[@4a]ss(w[o0]rd)?/i.test(password)) {
    penalties.push({ type: 'leetspeak', detail: 'Leetspeak substitution detected (e.g., p@ssw0rd) — attackers know these patterns.' });
  }
  if (/(19|20)\d{2}/.test(password)) {
    penalties.push({ type: 'date_pattern', detail: 'Year pattern detected — dates like 1990 or 2023 are among the first guesses.' });
  }
  if (/^[a-z]+$/i.test(password)) {
    penalties.push({ type: 'letters_only', detail: 'Only letters detected — add numbers and symbols to increase strength.' });
  }
  if (/^[0-9]+$/.test(password)) {
    penalties.push({ type: 'digits_only', detail: 'Only digits — mix in letters and symbols.' });
  }
  if (zxcvbnResult.feedback.warning) {
    penalties.push({ type: 'zxcvbn_warning', detail: zxcvbnResult.feedback.warning });
  }

  return penalties;
}

/**
 * Build actionable suggestions from analysis results.
 */
function buildSuggestions(password, zxcvbnResult, penalties) {
  const suggestions = [...zxcvbnResult.feedback.suggestions];
  const penaltyTypes = penalties.map(p => p.type);

  if (password.length < 12) {
    suggestions.unshift('Use at least 12 characters — longer passwords are exponentially harder to crack.');
  }
  if (!/[^a-zA-Z0-9]/.test(password)) {
    suggestions.push('Adding symbols (!, @, #, $) would add ~18 bits of entropy.');
  }
  if (!/[0-9]/.test(password)) {
    suggestions.push('Including digits increases your character pool by 10.');
  }
  if (!/[A-Z]/.test(password) && /[a-z]/.test(password)) {
    suggestions.push('Mix uppercase and lowercase letters to strengthen the password.');
  }
  if (penaltyTypes.includes('repeated_chars')) {
    suggestions.push('Replace repeated characters with varied symbols or words.');
  }
  if (!penaltyTypes.length && password.length >= 16) {
    suggestions.push('Great password! Consider using a password manager to store it securely.');
  }

  return [...new Set(suggestions)]; // deduplicate
}

/**
 * Main analysis function. Returns the full structured result object.
 */
function analyze(password) {
  // Input validation (SEC-05)
  if (typeof password !== 'string') throw new Error('Password must be a string');
  if (password.length === 0) throw new Error('Password cannot be empty');
  if (password.length > 512) throw new Error('Password exceeds 512 character limit');

  // Normalize to UTF-8 (handled by JS natively; this strips surrogates)
  const normalized = password.normalize('NFC');

  const r = zxcvbn(normalized);
  const entropy = computeEntropy(normalized);
  const penalties = detectPenalties(normalized, r);
  const suggestions = buildSuggestions(normalized, r, penalties);

  const crackTimes = {
    online_throttled: r.crack_times_display.online_throttling_100_per_hour,
    offline_slow_hash: r.crack_times_display.offline_slow_hashing_1e4_per_second,
    offline_fast_hash: r.crack_times_display.offline_fast_hashing_1e10_per_second,
  };

  return {
    score: r.score,
    strength_label: LABELS[r.score],
    entropy_bits: entropy,
    crack_times: crackTimes,
    penalties,
    suggestions,
    breach_check: null, // populated by breach endpoint
  };
}

module.exports = { analyze };
