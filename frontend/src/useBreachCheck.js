import { useState, useCallback } from 'react';

/**
 * SHA-1 hash using the Web Crypto API (client-side).
 * The raw password NEVER leaves the browser.
 */
async function sha1(str) {
  const buf = new TextEncoder().encode(str);
  const hash = await crypto.subtle.digest('SHA-1', buf);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

export function useBreachCheck() {
  const [pwResult, setPwResult] = useState(null);
  const [pwLoading, setPwLoading] = useState(false);

  const [emailResult, setEmailResult] = useState(null);
  const [emailLoading, setEmailLoading] = useState(false);

  const checkPassword = useCallback(async (password) => {
    if (!password) return;
    setPwLoading(true);
    setPwResult(null);
    try {
      const hash = await sha1(password);
      const prefix = hash.slice(0, 5);

      const res = await fetch(`https://passguard-backend-5d25.onrender.com/api/breach/password?prefix=${prefix}&hash=${hash}`, {
        headers: { Accept: 'application/json' },
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        if (res.status === 503) {
          setPwResult({ status: 'unavailable', message: err.message || 'Breach check temporarily unavailable.' });
        } else {
          setPwResult({ status: 'error', message: err.error || 'Unknown error' });
        }
        return;
      }

      const data = await res.json();
      setPwResult({
        status: data.pwned ? 'pwned' : 'safe',
        pwned: data.pwned,
        count: data.count,
        message: data.message,
        fromCache: data.fromCache,
      });
    } catch (err) {
      setPwResult({ status: 'unavailable', message: 'Could not reach breach check service. Strength analysis above is still accurate.' });
    } finally {
      setPwLoading(false);
    }
  }, []);

  const checkEmail = useCallback(async (email) => {
    if (!email || !email.includes('@')) return;
    setEmailLoading(true);
    setEmailResult(null);
    try {
      const res = await fetch(`/api/breach/email?email=${encodeURIComponent(email)}`, {
        headers: { Accept: 'application/json' },
      });

      if (res.status === 501) {
        setEmailResult({ status: 'no_key', message: 'Email breach check requires an HIBP API key. Set HIBP_API_KEY in backend/.env.' });
        return;
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        setEmailResult({ status: 'error', message: err.message || 'Unknown error' });
        return;
      }

      const data = await res.json();
      setEmailResult({
        status: data.breached ? 'breached' : 'safe',
        ...data,
      });
    } catch (err) {
      setEmailResult({ status: 'unavailable', message: 'Email breach check temporarily unavailable.' });
    } finally {
      setEmailLoading(false);
    }
  }, []);

  return { checkPassword, pwResult, pwLoading, checkEmail, emailResult, emailLoading };
}
