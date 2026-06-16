import { useMemo } from 'react';
import zxcvbn from 'zxcvbn';

const LABELS = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
const COLORS = ['#f87171', '#fb923c', '#fbbf24', '#a78bfa', '#4ade80'];

export function computeEntropy(password) {
  let cs = 0;
  if (/[a-z]/.test(password)) cs += 26;
  if (/[A-Z]/.test(password)) cs += 26;
  if (/[0-9]/.test(password)) cs += 10;
  if (/[^a-zA-Z0-9]/.test(password)) cs += 33;
  if (cs === 0 || password.length === 0) return 0;
  return Math.round(Math.log2(Math.pow(cs, password.length)) * 10) / 10;
}

export function detectPenalties(password, r) {
  const penalties = [];
  if (password.length < 8) penalties.push({ type: 'too_short', detail: 'Too short — aim for at least 12 characters.' });
  if (/(.)\1{2,}/.test(password)) penalties.push({ type: 'repeated_chars', detail: 'Repeated characters detected (e.g., "aaa").' });
  const walk = password.match(/qwerty|asdfgh|zxcvbn|12345|abcde/i);
  if (walk) penalties.push({ type: 'keyboard_walk', detail: `Keyboard walk detected: "${walk[0]}".` });
  if (/p[@4a]ss(w[o0]rd)?/i.test(password)) penalties.push({ type: 'leetspeak', detail: 'Leetspeak substitution detected (e.g. p@ssw0rd).' });
  if (/(19|20)\d{2}/.test(password)) penalties.push({ type: 'date_pattern', detail: 'Year/date pattern detected.' });
  if (/^[a-z]+$/i.test(password)) penalties.push({ type: 'letters_only', detail: 'Only letters — add numbers and symbols.' });
  if (/^[0-9]+$/.test(password)) penalties.push({ type: 'digits_only', detail: 'Only digits — mix in letters and symbols.' });
  if (r.feedback.warning) penalties.push({ type: 'zxcvbn', detail: r.feedback.warning });
  return penalties;
}

export function usePasswordAnalysis(password) {
  return useMemo(() => {
    if (!password) return null;
    const r = zxcvbn(password);
    const entropy = computeEntropy(password);
    const penalties = detectPenalties(password, r);
    const suggestions = [...r.feedback.suggestions];
    if (password.length < 12) suggestions.unshift('Use at least 12 characters.');
    if (!/[^a-zA-Z0-9]/.test(password)) suggestions.push('Adding symbols adds ~18 bits of entropy.');
    if (!/[0-9]/.test(password)) suggestions.push('Include digits to strengthen the password.');
    if (!/[A-Z]/.test(password) && /[a-z]/.test(password)) suggestions.push('Mix uppercase and lowercase letters.');

    return {
      score: r.score,
      label: LABELS[r.score],
      color: COLORS[r.score],
      entropy,
      crack_times: {
        online_throttled: r.crack_times_display.online_throttling_100_per_hour,
        offline_slow: r.crack_times_display.offline_slow_hashing_1e4_per_second,
        offline_fast: r.crack_times_display.offline_fast_hashing_1e10_per_second,
      },
      penalties,
      suggestions: [...new Set(suggestions)],
    };
  }, [password]);
}
