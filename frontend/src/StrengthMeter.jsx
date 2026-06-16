import React from 'react';

const styles = {
  wrap: { marginBottom: '0.5rem' },
  row: { display: 'flex', gap: '5px', height: '5px', marginBottom: '0.5rem' },
  seg: (active, color) => ({
    flex: 1,
    borderRadius: '3px',
    background: active ? color : '#252535',
    transition: 'background 0.3s ease',
  }),
  footer: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    minHeight: '1.3rem',
  },
  label: (color) => ({
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.72rem',
    fontWeight: 700,
    letterSpacing: '0.1em',
    textTransform: 'uppercase',
    color: color || '#64647a',
  }),
  entropy: {
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.7rem',
    color: '#64647a',
  },
};

export default function StrengthMeter({ analysis }) {
  const score = analysis?.score ?? -1;
  const color = analysis?.color ?? '#64647a';

  return (
    <div style={styles.wrap}>
      <div style={styles.row} role="progressbar" aria-valuenow={score + 1} aria-valuemin={0} aria-valuemax={5} aria-label="Password strength">
        {[0, 1, 2, 3, 4].map(i => (
          <div key={i} style={styles.seg(i <= score, color)} />
        ))}
      </div>
      <div style={styles.footer}>
        <span style={styles.label(analysis ? color : undefined)}>
          {analysis ? analysis.label : '—'}
        </span>
        {analysis && (
          <span style={styles.entropy}>
            {analysis.entropy} bits entropy
          </span>
        )}
      </div>
    </div>
  );
}
