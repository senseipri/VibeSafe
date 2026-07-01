'use client';
import { useState } from 'react';
import { Check, Loader2, AlertTriangle, Mail } from 'lucide-react';

export default function WaitlistForm({ source = 'footer' }) {
  const [email, setEmail] = useState('');
  const [state, setState] = useState('idle'); // idle | loading | ok | err
  const [msg, setMsg] = useState('');
  const [website, setWebsite] = useState('');

  const submit = async (e) => {
    e.preventDefault();
    setState('loading');
    setMsg('');
    try {
      const res = await fetch('/api/waitlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, website, source }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setState('err');
        setMsg(data?.error || 'Could not subscribe.');
        return;
      }
      setState('ok');
      setMsg('You\u2019re in. Watch your inbox.');
      setEmail('');
    } catch {
      setState('err');
      setMsg('Network error');
    }
  };

  return (
    <form onSubmit={submit} className="w-full">
      <label className="font-mono text-[11px] tracking-[0.15em] text-[#A0A0A0] block mb-2">
        WEEKLY SECURITY DIGEST
      </label>
      <div className="flex gap-2">
        <div className="relative flex-1">
          <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#A0A0A0]" />
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="founder@startup.dev"
            className="w-full pl-9 pr-3 py-2.5 rounded-md bg-[#05050D] border border-[#1F1F3D] focus:border-[#8A2BE2] text-[13px] text-[#FFFFFF] outline-none transition-colors"
          />
        </div>
        <input
          type="text"
          tabIndex={-1}
          aria-hidden="true"
          autoComplete="off"
          value={website}
          onChange={(e) => setWebsite(e.target.value)}
          name="website"
          className="absolute opacity-0 -z-10 w-0 h-0"
        />
        <button
          type="submit"
          disabled={state === 'loading'}
          className="px-4 py-2.5 rounded-md bg-[#8A2BE2] hover:bg-[#B967FF] disabled:opacity-60 text-white text-[13px] font-medium inline-flex items-center gap-1.5"
        >
          {state === 'loading' ? (
            <Loader2 className="w-3.5 h-3.5 animate-spin" />
          ) : state === 'ok' ? (
            <Check className="w-3.5 h-3.5" />
          ) : (
            'Join'
          )}
        </button>
      </div>
      {msg && (
        <div
          className={`mt-2 flex items-center gap-1.5 text-[12px] font-mono ${
            state === 'ok' ? 'text-[#22C55E]' : 'text-[#8A2BE2]'
          }`}
        >
          {state === 'ok' ? (
            <Check className="w-3 h-3" />
          ) : (
            <AlertTriangle className="w-3 h-3" />
          )}
          {msg}
        </div>
      )}
    </form>
  );
}
