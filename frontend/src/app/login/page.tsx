"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { auth, setToken } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await auth.login(email, password);
      setToken(res.access_token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-background flex items-center justify-center px-4">
      {/* Background archival texture suggestion */}
      <div className="absolute inset-0 pointer-events-none opacity-[0.015]"
        style={{ backgroundImage: "repeating-linear-gradient(0deg, #2c2c2c, #2c2c2c 1px, transparent 1px, transparent 32px)" }} />

      <div className="relative w-full max-w-[420px]">
        {/* Card */}
        <div className="bg-paper rounded-3xl border border-mist shadow-editorial p-12">
          {/* Brand */}
          <div className="mb-8 text-center">
            <div className="inline-flex items-center justify-center w-12 h-12 rounded-xl border border-graphite bg-paper mb-4">
              <span className="font-code-default text-lg font-bold text-primary">Ψ</span>
            </div>
            <h1 className="font-headline-xl text-headline-xl text-graphite tracking-tight">NETRA</h1>
            <p className="font-body-caption text-body-caption text-ash mt-1.5 max-w-[280px] mx-auto">
              Networked Evidence &amp; Threat-actor Relationship Analyzer
            </p>
          </div>

          {/* Divider */}
          <div className="h-[1px] bg-mist mb-8" />

          {/* Classification badge */}
          <div className="flex items-center justify-center mb-6">
            <span className="px-2.5 py-1 rounded border border-mist bg-surface-container-low text-ash text-[10px] font-label-uppercase tracking-widest">
              CLASSIFIED // REL TO INTEL — ENCLAVE ACCESS
            </span>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-1">
              <label className="block text-[11px] font-label-uppercase text-ash tracking-widest">
                ANALYST IDENTIFIER
              </label>
              <input
                type="text"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="ledger-input w-full py-2 text-body-default font-body-default text-graphite"
                placeholder="admin or analyst@netra.local"
                required
                autoFocus
              />
            </div>
            <div className="space-y-1">
              <label className="block text-[11px] font-label-uppercase text-ash tracking-widest">
                ENCLAVE PASSPHRASE
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="ledger-input w-full py-2 text-body-default font-body-default text-graphite"
                placeholder="••••••••••••••"
                required
              />
            </div>

            {error && (
              <p className="text-severity-critical text-[13px] font-body-caption flex items-center gap-1.5">
                <span className="material-symbols-outlined text-[16px]">error</span>
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-primary-container hover:bg-twilight text-paper font-label-ui text-label-ui rounded-lg transition-colors duration-100 flex items-center justify-center gap-2 disabled:opacity-60"
            >
              {loading ? (
                <>
                  <span className="material-symbols-outlined text-[16px] animate-spin">refresh</span>
                  Authenticating…
                </>
              ) : (
                <>
                  Authenticate
                  <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
                </>
              )}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-mist">
            <div className="flex items-center justify-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-status-live" />
              <span className="text-[11px] font-code-compact text-ash">TLS 1.3 · E2E Encrypted · Ephemeral Session</span>
            </div>
          </div>
        </div>

        {/* Below card */}
        <p className="text-center text-[11px] font-body-caption text-ash mt-6">
          NETRA v2.0 · Threat Dossier Archive System
        </p>
      </div>
    </div>
  );
}
