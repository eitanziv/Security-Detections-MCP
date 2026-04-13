import { NextRequest } from 'next/server';

const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

export async function POST(request: NextRequest) {
  const { token } = await request.json();

  if (!token) {
    return Response.json({ success: false, error: 'Missing token' }, { status: 400 });
  }

  const secretKey = process.env.TURNSTILE_SECRET_KEY;
  if (!secretKey) {
    console.error('TURNSTILE_SECRET_KEY not configured');
    return Response.json({ success: false, error: 'Server config error' }, { status: 500 });
  }

  const form = new URLSearchParams();
  form.append('secret', secretKey);
  form.append('response', token);

  const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  if (ip) form.append('remoteip', ip);

  const res = await fetch(VERIFY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });

  const result = await res.json();

  if (!result.success) {
    return Response.json({ success: false, errors: result['error-codes'] }, { status: 403 });
  }

  return Response.json({ success: true });
}
