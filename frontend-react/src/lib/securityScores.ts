import { api } from "./api";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NOT_AVAILABLE";
export type DistributionItem = { value: string; count: number };
export type RiskFactor = {
  code: string;
  label: string;
  score: number | null;
  weight: number;
  effective_weight: number;
  normalized_contribution: number;
  record_count: number;
  available: boolean;
  explanation: string;
};
export type OrganizationRisk = {
  organization: { id: string; code: string; name: string; status: string };
  data_available: boolean;
  risk_score: number | null;
  risk_level: RiskLevel;
  factors: RiskFactor[];
  source_counts: {
    total_threats: number;
    open_threats: number;
    total_incidents: number;
    open_incidents: number;
    recent_behavior_detections: number;
  };
  last_signal_at?: string;
};
export type SecurityScoreMethodology = {
  version: string;
  behavior_window_days: number;
  weights: Record<string, number>;
  thresholds: Record<string, number>;
  missing_data_policy: string;
  formula: string;
};
export type OrganizationScoreComparison = {
  calculated_at: string;
  methodology: SecurityScoreMethodology;
  organizations: OrganizationRisk[];
};
export type ThreatRecord = {
  id: string;
  code: string;
  title: string;
  type: string;
  category: string;
  detection_method: string;
  severity: RiskLevel;
  score: number;
  confidence: number;
  classification: string;
  status: string;
  occurrence_count: number;
  affected_file_count: number;
  first_detected_at: string;
  last_detected_at: string;
};
export type ThreatScoreData = {
  calculated_at: string;
  risk: OrganizationRisk;
  inventory: {
    total: number;
    open: number;
    resolved: number;
    false_positive: number;
    severity: DistributionItem[];
    status: DistributionItem[];
    category: DistributionItem[];
    detection_method: DistributionItem[];
    total_occurrences: number;
    affected_file_count: number;
    affected_device_count: number;
  };
  trend: { date: string; detected: number; average_score: number; maximum_score: number }[];
  top_threats: ThreatRecord[];
  methodology: SecurityScoreMethodology;
};

export const securityScores = {
  organization: () => api.get<OrganizationRisk>("/security-scores/organization"),
  organizations: () => api.get<OrganizationScoreComparison>("/security-scores/organizations"),
  threats: () => api.get<ThreatScoreData>("/security-scores/threats"),
};
