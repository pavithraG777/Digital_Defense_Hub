export type UnknownRecord = Record<string, unknown>;

const collectionKeys = [
  "items",
  "results",
  "data",
  "users",
  "organizations",
  "roles",
  "permissions",
  "threats",
  "incidents",
  "honeytokens",
  "canaries",
  "events",
  "detections",
  "scores",
  "notifications",
  "assets",
  "jobs",
  "models",
  "datasets",
  "cases",
  "audit_logs",
  "records",
];

export function isRecord(value: unknown): value is UnknownRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function toCollection(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  if (!isRecord(value)) return [];

  for (const key of collectionKeys) {
    if (Array.isArray(value[key])) return value[key] as unknown[];
  }

  return [];
}

export function getRecordId(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  const candidate = value.id ?? value.uuid ?? value.ID;
  return candidate === undefined || candidate === null ? undefined : String(candidate);
}

export function getRecordLabel(value: unknown): string {
  if (!isRecord(value)) return displayValue(value);
  const candidate = value.display_name
    ?? value.name
    ?? value.title
    ?? value.username
    ?? value.organization_name
    ?? value.role_name
    ?? value.permission_name
    ?? value.case_title
    ?? value.report_number
    ?? value.asset_code
    ?? value.job_number
    ?? value.file_name
    ?? value.id;
  return displayValue(candidate);
}

export function getRecordStatus(value: unknown): string {
  if (!isRecord(value)) return "—";
  return displayValue(
    value.status
      ?? value.account_status
      ?? value.severity
      ?? value.risk_level
      ?? value.analysis_status
      ?? value.health_status,
  );
}

export function displayValue(value: unknown): string {
  if (value === undefined || value === null || value === "") return "—";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.length ? value.map(displayValue).join(", ") : "—";
  return JSON.stringify(value);
}

export function formatDate(value: unknown): string {
  if (typeof value !== "string" || !value) return displayValue(value);
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function recordTimestamp(value: unknown): string {
  if (!isRecord(value)) return "—";
  return formatDate(value.updated_at ?? value.generated_at ?? value.created_at ?? value.detected_at ?? value.occurred_at ?? value.timestamp);
}

export function getNumeric(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim() !== "" && Number.isFinite(Number(value))) return Number(value);
  return undefined;
}

export function normalizeSeverity(value: unknown): string {
  return getRecordStatus(value).toLowerCase();
}
