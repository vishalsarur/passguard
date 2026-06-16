import React, { useState, useRef } from 'react';
import { usePasswordAnalysis } from './usePasswordAnalysis';
import StrengthMeter from './StrengthMeter';
import CrackTimes from './CrackTimes';
import { PenaltiesPanel, SuggestionsPanel } from './Panels';
import BreachChecker from './BreachChecker';

const s = {
  page: {
    minHeight: '100vh',
    background: '#07070e',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    padding: '0 1rem 4rem',
  },
  topBar: {
    width: '100%',
    maxWidth: '720px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '1.5rem 0 0',
    marginBottom: '2.5rem',
  },
  logo: {
    fontFamily: "'Space Mono', monospace",
    fontSize: '1rem',
    fontWeight: 700,
    letterSpacing: '0.1em',
    color: '#7c5cfc',
    textTransform: 'uppercase',
  },
  tagline: { fontSize: '0.72rem', color: '#64647a' },
  shield: { fontSize: '1.5rem', color: '#7c5cfc' },
  main: { width: '100%', maxWidth: '720px' },
  inputWrap: { position: 'relative', marginBottom: '1rem' },
  pwInput: {
    width: '100%',
    background: '#0f0f1a',
    border: '1px solid #252535',
    borderRadius: '12px',
    padding: '1rem 3.5rem 1rem 1.2rem',
    fontFamily: "'Space Mono', monospace",
    fontSize: '1.05rem',
    color: '#e2e2f0',
    letterSpacing: '0.04em',
    outline: 'none',
    transition: 'border-color 0.2s',
    boxSizing: 'border-box',
  },
  eyeBtn: {
    position: 'absolute',
    right: '1rem',
    top: '50%',
    transform: 'translateY(-50%)',
    background: 'none',
    border: 'none',
    color: '#64647a',
    cursor: 'pointer',
    padding: '0.25rem',
    display: 'flex',
    alignItems: 'center',
    fontSize: '1.1rem',
    transition: 'color 0.2s',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '0.85rem',
    marginBottom: '0.85rem',
  },
  stack: { display: 'flex', flexDirection: 'column', gap: '0.85rem' },
  privacyNote: {
    marginTop: '1.5rem',
    paddingTop: '1rem',
    borderTop: '1px solid #1e1e2e',
    fontSize: '0.68rem',
    color: '#3d3d52',
    lineHeight: 1.7,
    textAlign: 'center',
  },
  accent: { color: '#4ade80', fontWeight: 600 },
  charCount: {
    textAlign: 'right',
    fontSize: '0.65rem',
    color: '#3d3d52',
    marginBottom: '0.5rem',
    fontFamily: "'Space Mono', monospace",
  },
};

export default function App() {
  const [password, setPassword] = useState('');
  const [showPw, setShowPw] = useState(false);
  const inputRef = useRef(null);
  const analysis = usePasswordAnalysis(password);

  function handleChange(e) {
    const val = e.target.value;
    if (val.length > 512) return;
    setPassword(val);
  }

  return (
    <div style={s.page}>
      <div style={s.topBar}>
        <div>
          <div style={s.logo}>
            <i className="ti ti-shield-lock" aria-hidden="true" /> PassGuard
          </div>
          <div style={s.tagline}>Privacy-first password strength analyzer &amp; breach checker</div>
        </div>
        <a
          href="https://haveibeenpwned.com"
          target="_blank"
          rel="noopener noreferrer"
          style={{ fontSize: '0.68rem', color: '#3d3d52' }}
        >
          Powered by HIBP
        </a>
      </div>

      <main style={s.main} role="main">
        <div style={s.inputWrap}>
          <input
            ref={inputRef}
            type={showPw ? 'text' : 'password'}
            style={s.pwInput}
            placeholder="Enter a password to analyze..."
            value={password}
            onChange={handleChange}
            autoComplete="off"
            spellCheck={false}
            aria-label="Password input"
            maxLength={512}
          />
          <button
            style={s.eyeBtn}
            onClick={() => setShowPw(v => !v)}
            aria-label={showPw ? 'Hide password' : 'Show password'}
          >
            <i className={`ti ${showPw ? 'ti-eye-off' : 'ti-eye'}`} aria-hidden="true" />
          </button>
        </div>

        {password.length > 0 && (
          <div style={s.charCount}>{password.length} / 512 chars</div>
        )}

        <StrengthMeter analysis={analysis} />

        {analysis && (
          <div style={{ ...s.stack, marginTop: '1rem' }}>
            <div style={s.grid}>
              <CrackTimes crack_times={analysis.crack_times} />
              <PenaltiesPanel penalties={analysis.penalties} />
            </div>
            <SuggestionsPanel suggestions={analysis.suggestions} />
          </div>
        )}

        <div style={{ marginTop: analysis ? '0.85rem' : '1.5rem' }}>
          <BreachChecker password={password} />
        </div>

        <div style={s.privacyNote}>
          <span style={s.accent}>Zero raw-password transmission.</span> All strength analysis runs entirely in your browser using zxcvbn.
          For breach checks, only the <span style={s.accent}>first 5 characters of the SHA-1 hash</span> are sent to HaveIBeenPwned —
          your password never leaves your device. The backend API holds your HIBP key server-side and never logs passwords or hash prefixes.
        </div>
      </main>
    </div>
  );
}
