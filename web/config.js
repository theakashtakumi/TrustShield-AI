/**
 * TrustShield AI — Centralized Client API Configuration
 * Supports same-origin hosting, cross-port local dev, and separate production backend deployments.
 */
(function (global) {
  'use strict';

  function resolveApiBase() {
    // 1. Explicit window override
    if (global.__TRUSTSHIELD_API_BASE__ && typeof global.__TRUSTSHIELD_API_BASE__ === 'string') {
      return global.__TRUSTSHIELD_API_BASE__.replace(/\/+$/, '');
    }

    // 2. Browser localStorage override (user/admin configurable)
    try {
      const stored = global.localStorage && global.localStorage.getItem('trustshield_api_base');
      if (stored && typeof stored === 'string' && stored.trim()) {
        return stored.trim().replace(/\/+$/, '');
      }
    } catch {}

    // 3. Local development cross-port detection
    // If frontend is served on port 3000, 5000, 5500, etc., route to local Python server on port 8000
    const loc = global.location;
    if (loc && (loc.hostname === 'localhost' || loc.hostname === '127.0.0.1')) {
      if (loc.port && loc.port !== '8000') {
        return `${loc.protocol}//${loc.hostname}:8000`;
      }
    }

    // 4. Default: same-origin (relative requests)
    return '';
  }

  let currentBase = resolveApiBase();

  const TrustShieldConfig = {
    getApiBase() {
      return currentBase;
    },
    getApiUrl(path) {
      const cleanPath = String(path || '').startsWith('/') ? path : `/${path}`;
      return `${currentBase}${cleanPath}`;
    },
    setApiBase(newBase) {
      const sanitized = String(newBase || '').trim().replace(/\/+$/, '');
      try {
        if (sanitized) {
          global.localStorage && global.localStorage.setItem('trustshield_api_base', sanitized);
        } else {
          global.localStorage && global.localStorage.removeItem('trustshield_api_base');
        }
      } catch {}
      currentBase = sanitized || resolveApiBase();
      return currentBase;
    },
    async checkHealth() {
      const url = this.getApiUrl('/api/health');
      try {
        const res = await fetch(url, { credentials: 'include', headers: { Accept: 'application/json' } });
        const data = await res.json().catch(() => ({}));
        return { ok: res.ok && data.ok === true, status: res.status, data };
      } catch (err) {
        return { ok: false, status: 0, error: err.message };
      }
    }
  };

  global.TrustShieldConfig = TrustShieldConfig;
})(typeof window !== 'undefined' ? window : this);
