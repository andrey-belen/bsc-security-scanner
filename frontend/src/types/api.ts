// API Types for BSC Security Scanner

export interface ScanFinding {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  details: string;
}

export interface ScanResult {
  address: string;
  scan_time: string;
  chain: string;
  quick_scan: boolean;
  findings: ScanFinding[];
  risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'VERY LOW';
  errors: Array<{
    type: string;
    context: string;
  }>;
  warnings: Array<{
    analysis: string;
    error: string;
    timestamp: string;
  }>;
  name?: string;
  symbol?: string;
  decimals?: number;
  total_supply?: string;
  is_verified?: boolean;
  error?: string;
  error_type?: string;
}

export interface AnalysisRequest {
  address: string;
  quickScan?: boolean;
}

export interface AnalysisResponse {
  message: string;
  analysisId: string;
  status: 'running' | 'completed' | 'failed';
  estimatedTime?: string;
  statusUrl: string;
}

export interface AnalysisStatus {
  analysisId: string;
  status: 'running' | 'completed' | 'failed';
  result?: ScanResult;
  error?: string;
  startTime: string;
  completedTime?: string;
  progress?: string;
}

export interface SynchronousAnalysisResponse {
  status: 'completed';
  result: ScanResult;
  address: string;
  quickScan: boolean;
}

export interface ApiError {
  error: string;
  message?: string;
  details?: Array<{
    type: string;
    msg: string;
    path: string[];
    location: string;
  }>;
}

export interface HealthCheck {
  status: string;
  timestamp: string;
  activeAnalyses: number;
}

export interface ApiInfo {
  name: string;
  version: string;
  description: string;
  endpoints: {
    analyze: string;
    status: string;
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
  };
}