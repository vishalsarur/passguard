import React from 'react';

const s = {
  card: {
    background: '#0f0f1a',
    border: '1px solid #252535',
    borderRadius: '10px',
    padding: '1rem',
  },
  title: {
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.62rem',
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    color: '#64647a',
    marginBottom: '0.8rem',
  },
  empty: { fontSize: '0.78rem', color: '#4ade80' },
  pItem: {
    display: 'flex',
    gap: '0.5rem',
    alignItems: 'flex-start',
    marginBottom: '0.5rem',
    fontSize: '0.78rem',
    lineHeight: 1.5,
    color: '#e2e2f0',
  },
  pIcon: { color: '#fbbf24', flexShrink: 0, marginTop: '1px', fontSize: '0.9rem' },
  sItem: {
    display: 'flex',
    gap: '0.5rem',
    alignItems: 'flex-start',
    marginBottom: '0.45rem',
    fontSize: '0.78rem',
    lineHeight: 1.5,
    color: '#8888a0',
  },
  dot: {
    width: '5px',
    height: '5px',
    borderRadius: '50%',
    background: '#7c5cfc',
    flexShrink: 0,
    marginTop: '6px',
  },
};

export function PenaltiesPanel({ penalties }) {
  return (
    <div style={s.card}>
      <div style={s.title}>Detected weaknesses</div>
      {!penalties || penalties.length === 0 ? (
        <div style={s.empty}><i className="ti ti-shield-check" aria-hidden="true" /> No major issues detected</div>
      ) : (
        penalties.map((p, i) => (
          <div key={i} style={{ ...s.pItem, marginBottom: i === penalties.length - 1 ? 0 : s.pItem.marginBottom }}>
            <i className="ti ti-alert-triangle" style={s.pIcon} aria-hidden="true" />
            <span>{p.detail}</span>
          </div>
        ))
      )}
    </div>
  );
}

export function SuggestionsPanel({ suggestions }) {
  if (!suggestions || suggestions.length === 0) return null;
  return (
    <div style={s.card}>
      <div style={s.title}>Suggestions</div>
      {suggestions.map((sg, i) => (
        <div key={i} style={{ ...s.sItem, marginBottom: i === suggestions.length - 1 ? 0 : s.sItem.marginBottom }}>
          <div style={s.dot} />
          <span>{sg}</span>
        </div>
      ))}
    </div>
  );
}
