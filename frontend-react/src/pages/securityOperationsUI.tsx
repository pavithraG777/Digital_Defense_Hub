import type { ReactNode } from "react";
import { AlertTriangle, LoaderCircle, X } from "lucide-react";

export type UnknownMap = Record<string, unknown>;

const sensitiveFieldPattern = /(password|secret|credential|token_value|private_key|storage_path|process_path|source_ip|ip_address|raw_payload|authorization)/i;

export function isMap(value: unknown): value is UnknownMap {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function text(value: unknown, fallback = "Not reported") {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

export function humanize(value: string) {
  return value
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function formatDate(value?: string | null) {
  if (!value) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function formatScore(value?: number | null, suffix = "/100") {
  return typeof value === "number" && Number.isFinite(value) ? `${value.toFixed(value % 1 ? 1 : 0)}${suffix}` : "Not reported";
}

export function tone(value?: string | null) {
  const normalized = (value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-");
  return `soc-tone-${normalized}`;
}

export type SafeFact = { label: string; value: string };

function factValue(value: unknown) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (typeof value === "string" && value.trim()) return value.trim();
  return null;
}

/**
 * Converts backend explainability objects into short human-readable facts.
 * Sensitive keys and opaque internal identifiers are intentionally omitted.
 */
export function safeFacts(value: unknown, prefix = "", depth = 0): SafeFact[] {
  if (depth > 3 || value === null || value === undefined) return [];
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return [];
    if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && trimmed.length < 200_000) {
      try {
        return safeFacts(JSON.parse(trimmed) as unknown, prefix, depth + 1);
      } catch {
        return prefix ? [{ label: humanize(prefix), value: trimmed }] : [];
      }
    }
    return prefix ? [{ label: humanize(prefix), value: trimmed }] : [];
  }
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => safeFacts(item, prefix ? `${prefix} ${index + 1}` : `Item ${index + 1}`, depth + 1));
  }
  if (!isMap(value)) return [];

  return Object.entries(value).flatMap(([key, child]) => {
    if (sensitiveFieldPattern.test(key) || /(^|_)id$/i.test(key)) return [];
    const label = prefix ? `${prefix} ${humanize(key)}` : humanize(key);
    const scalar = factValue(child);
    return scalar === null ? safeFacts(child, label, depth + 1) : [{ label, value: scalar }];
  });
}

export function MetricCard({ label, value, hint, accent = "blue" }: { label: string; value: ReactNode; hint?: ReactNode; accent?: "blue" | "red" | "amber" | "green" | "violet" }) {
  return <article className={`soc-metric soc-metric-${accent}`}><span>{label}</span><strong>{value}</strong>{hint ? <small>{hint}</small> : null}</article>;
}

export function StatusBadge({ value }: { value?: string | null }) {
  const label = value ? humanize(value) : "Not reported";
  return <span className={`soc-status ${tone(value)}`}>{label}</span>;
}

export function LoadingState({ label = "Loading live security records…" }: { label?: string }) {
  return <div className="soc-state"><LoaderCircle className="spin" size={22} /><p>{label}</p></div>;
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return <div className="soc-state soc-empty"><AlertTriangle size={24} /><h2>{title}</h2><p>{message}</p></div>;
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="alert alert-error soc-error" role="alert"><AlertTriangle size={17} /> {message}</div>;
}

export function DetailDrawer({ title, eyebrow, onClose, children }: { title: string; eyebrow: string; onClose: () => void; children: ReactNode }) {
  return (
    <div className="soc-drawer-backdrop" role="presentation" onMouseDown={onClose}>
      <aside className="soc-drawer" role="dialog" aria-modal="true" aria-label={title} onMouseDown={(event) => event.stopPropagation()}>
        <header><div><p>{eyebrow}</p><h2>{title}</h2></div><button type="button" className="icon-button" aria-label="Close details" onClick={onClose}><X size={19} /></button></header>
        <div className="soc-drawer-body">{children}</div>
      </aside>
    </div>
  );
}

export function FactGrid({ facts, empty = "No additional non-sensitive details were returned." }: { facts: SafeFact[]; empty?: string }) {
  if (!facts.length) return <p className="soc-muted">{empty}</p>;
  return <dl className="soc-fact-grid">{facts.map((fact, index) => <div key={`${fact.label}-${index}`}><dt>{fact.label}</dt><dd>{fact.value}</dd></div>)}</dl>;
}
