'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { createClient } from '@/lib/supabase/client';

declare global {
  interface Window {
    turnstile?: {
      render: (container: HTMLElement, options: Record<string, unknown>) => string;
      reset: (widgetId: string) => void;
      remove: (widgetId: string) => void;
    };
    onTurnstileLoad?: () => void;
  }
}

const TURNSTILE_SITE_KEY = process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY || '';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState<string | null>(null);
  const turnstileRef = useRef<HTMLDivElement>(null);
  const widgetIdRef = useRef<string | null>(null);
  const router = useRouter();
  const supabase = createClient();

  const renderWidget = useCallback(() => {
    if (!turnstileRef.current || !window.turnstile) return;
    if (widgetIdRef.current) {
      window.turnstile.remove(widgetIdRef.current);
    }
    widgetIdRef.current = window.turnstile.render(turnstileRef.current, {
      sitekey: TURNSTILE_SITE_KEY,
      theme: 'dark',
      callback: (token: string) => setTurnstileToken(token),
      'expired-callback': () => setTurnstileToken(null),
      'error-callback': () => setTurnstileToken(null),
      action: 'login',
    });
  }, []);

  useEffect(() => {
    if (!TURNSTILE_SITE_KEY) return;
    if (window.turnstile) {
      renderWidget();
      return;
    }
    const existing = document.querySelector('script[src*="turnstile"]');
    if (!existing) {
      window.onTurnstileLoad = renderWidget;
      const script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onTurnstileLoad&render=explicit';
      script.async = true;
      document.head.appendChild(script);
    }
    return () => {
      if (widgetIdRef.current && window.turnstile) {
        window.turnstile.remove(widgetIdRef.current);
        widgetIdRef.current = null;
      }
    };
  }, [renderWidget]);

  async function handleGitHubLogin() {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`,
      },
    });
    if (error) setError(error.message);
  }

  async function handleEmailLogin(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    // Verify Turnstile token server-side
    if (TURNSTILE_SITE_KEY && !turnstileToken) {
      setError('Please complete the verification.');
      setLoading(false);
      return;
    }

    if (TURNSTILE_SITE_KEY && turnstileToken) {
      const verifyRes = await fetch('/api/verify-turnstile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: turnstileToken }),
      });
      const verifyData = await verifyRes.json();
      if (!verifyData.success) {
        setError('Verification failed. Please try again.');
        setLoading(false);
        if (widgetIdRef.current && window.turnstile) {
          window.turnstile.reset(widgetIdRef.current);
        }
        setTurnstileToken(null);
        return;
      }
    }

    const { error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      setError(error.message);
      setLoading(false);
    } else {
      router.push('/dashboard');
      router.refresh();
    }
  }

  return (
    <div className="min-h-screen bg-bg bg-grid flex items-center justify-center p-6">
      <div className="w-full max-w-md">
        {/* Branding */}
        <div className="text-center mb-8">
          <Link href="/" className="inline-flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-amber/20 border border-amber/40 flex items-center justify-center">
              <span className="text-amber font-bold">SD</span>
            </div>
            <span className="font-[family-name:var(--font-display)] text-2xl tracking-wider text-text-bright">
              SECURITY DETECTIONS
            </span>
          </Link>
        </div>

        {/* Card */}
        <div className="bg-card border border-border rounded-[var(--radius-card)] p-8">
          <h1 className="font-[family-name:var(--font-display)] text-3xl text-text-bright tracking-wider mb-2">
            SIGN IN
          </h1>
          <p className="text-text-dim text-sm mb-6">
            Access AI-powered detection coverage intelligence.
          </p>

          {/* GitHub SSO */}
          <button
            onClick={handleGitHubLogin}
            className="w-full flex items-center justify-center gap-3 bg-card2 hover:bg-border border border-border-bright text-text-bright font-semibold py-3 rounded-[var(--radius-button)] transition-colors mb-6"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            Continue with GitHub
          </button>

          {/* Divider */}
          <div className="flex items-center gap-4 mb-6">
            <div className="flex-1 border-t border-border" />
            <span className="text-text-dim text-xs uppercase font-[family-name:var(--font-mono)]">or</span>
            <div className="flex-1 border-t border-border" />
          </div>

          {/* Email form */}
          <form onSubmit={handleEmailLogin} className="space-y-4">
            <div>
              <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
                placeholder="analyst@example.com"
                required
              />
            </div>
            <div>
              <label className="block text-text-dim text-xs uppercase font-[family-name:var(--font-mono)] tracking-wider mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-bg2 border border-border focus:border-amber/50 rounded-[var(--radius-button)] px-4 py-2.5 text-text placeholder:text-text-dim/50 outline-none transition-colors font-[family-name:var(--font-mono)] text-sm"
                placeholder="••••••••"
                required
              />
            </div>

            <div className="text-right">
              <Link href="/forgot-password" className="text-text-dim hover:text-amber text-xs transition-colors">
                Forgot password?
              </Link>
            </div>

            {/* Cloudflare Turnstile */}
            {TURNSTILE_SITE_KEY && (
              <div className="flex justify-center">
                <div ref={turnstileRef} />
              </div>
            )}

            {error && (
              <div className="bg-red/10 border border-red/30 rounded-[var(--radius-card)] px-4 py-2 text-red text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading || (!!TURNSTILE_SITE_KEY && !turnstileToken)}
              className="w-full bg-amber hover:bg-amber-dim disabled:opacity-50 text-bg font-bold py-3 rounded-[var(--radius-button)] transition-colors"
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <p className="text-text-dim text-sm text-center mt-6">
            Don&apos;t have an account?{' '}
            <Link href="/signup" className="text-amber hover:text-amber-dim transition-colors">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
