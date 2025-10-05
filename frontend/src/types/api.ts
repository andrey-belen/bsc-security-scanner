// API Types for BSC Security Scanner

export interface ScanFinding {
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  message: string;
  details: string;
}

export interface HolderMetrics {
  top_10_concentration: number;
  whale_count: number;
  total_holders: number;
  circulating_supply: number;
}

export interface HolderData {
  findings: ScanFinding[];
  metrics: HolderMetrics;
  top_holders?: Array<{
    address: string;
    balance: number;
    percentage: number;
    label: string;
  }>;
}

export interface LiquidityMetrics {
  total_liquidity_usd: number;
  lp_burned_percent: number;
  lp_locked_percent: number;
  lp_unlocked_percent: number;
  pools_found: number;
  lock_details?: Array<{
    platform: string;
    amount: number;
    percent: number;
  }>;
}

export interface LiquidityData {
  findings: ScanFinding[];
  metrics: LiquidityMetrics;
  pools?: string[];
}

export interface HoneypotData {
  findings: ScanFinding[];
  is_honeypot: boolean;
  simulation_confidence?: number;
  simulation_results?: {
    buy: {
      success: boolean;
      tokens_received: number;
      error?: string;
    };
    sell: {
      success: boolean;
      bnb_received: number;
      error?: string;
    };
  };
}

export interface ScanResult {
  address: string;
  scan_time: string;
  chain: string;
  quick_scan: boolean;
  findings: ScanFinding[];
  risk_score: number;
  risk_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'VERY LOW';
  errors?: Array<{
    type: string;
    context: string;
  }>;
  warnings?: Array<{
    analysis: string;
    error: string;
    timestamp: string;
  }>;
  token_name?: string;
  token_symbol?: string;
  decimals?: number;
  total_supply?: string;
  is_verified?: boolean;
  is_renounced?: boolean;
  owner?: string;
  analysis_confidence?: number;
  has_source_code?: boolean;

  // Advanced analysis data
  holder_distribution?: HolderData;
  liquidity?: LiquidityData;
  honeypot_check?: HoneypotData;

  // Legacy fields
  error?: string;
  error_type?: string;
  name?: string;
  symbol?: string;
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