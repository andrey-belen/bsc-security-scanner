import axios, { AxiosResponse } from 'axios';
import {
  AnalysisRequest,
  AnalysisResponse,
  AnalysisStatus,
  SynchronousAnalysisResponse,
  HealthCheck,
  ApiInfo,
} from '../types/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: '/api',
  timeout: 300000, // 5 minutes for long-running analyses
  headers: {
    'Content-Type': 'application/json',
  },
});

// Response interceptor for error handling
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  (error) => {
    console.error('API Error:', error);
    
    if (error.response?.data) {
      // Server responded with error status
      throw new Error(error.response.data.error || error.response.data.message || 'API Error');
    } else if (error.request) {
      // Request was made but no response received
      throw new Error('No response from server. Please check your connection.');
    } else {
      // Something else happened
      throw new Error(error.message || 'An unexpected error occurred');
    }
  }
);

export class ApiService {
  /**
   * Check API health status
   */
  static async getHealthStatus(): Promise<HealthCheck> {
    const response = await api.get('/health');
    return response.data;
  }

  /**
   * Get API information
   */
  static async getApiInfo(): Promise<ApiInfo> {
    const response = await api.get('/info');
    return response.data;
  }

  /**
   * Start asynchronous contract analysis
   */
  static async startAnalysis(request: AnalysisRequest): Promise<AnalysisResponse> {
    const response = await api.post('/analyze', request);
    return response.data;
  }

  /**
   * Get analysis status by ID
   */
  static async getAnalysisStatus(analysisId: string): Promise<AnalysisStatus> {
    const response = await api.get(`/analyze/${analysisId}/status`);
    return response.data;
  }

  /**
   * Perform synchronous contract analysis (for quick scans)
   */
  static async analyzeSynchronously(request: AnalysisRequest): Promise<SynchronousAnalysisResponse> {
    const response = await api.post('/analyze-sync', request);
    return response.data;
  }

  /**
   * Poll for analysis completion
   * @param analysisId The analysis ID to poll
   * @param intervalMs Polling interval in milliseconds (default: 3000)
   * @param maxAttempts Maximum polling attempts (default: 120)
   * @returns Promise that resolves with the final analysis result
   */
  static async pollAnalysisStatus(
    analysisId: string,
    intervalMs: number = 3000,
    maxAttempts: number = 120
  ): Promise<AnalysisStatus> {
    let attempts = 0;

    return new Promise((resolve, reject) => {
      const poll = async () => {
        try {
          attempts++;
          const status = await this.getAnalysisStatus(analysisId);

          if (status.status === 'completed' || status.status === 'failed') {
            resolve(status);
          } else if (attempts >= maxAttempts) {
            reject(new Error('Analysis polling timeout - maximum attempts reached'));
          } else {
            // Continue polling
            setTimeout(poll, intervalMs);
          }
        } catch (error) {
          reject(error);
        }
      };

      poll();
    });
  }

  /**
   * Validate BSC address format
   */
  static isValidBSCAddress(address: string): boolean {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
  }

  /**
   * Format address for display (short version)
   */
  static formatAddress(address: string): string {
    if (!address || address.length < 10) return address;
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  }

  /**
   * Get risk level color for UI styling
   */
  static getRiskLevelColor(riskLevel: string): string {
    switch (riskLevel) {
      case 'CRITICAL':
        return '#dc2626'; // red-600
      case 'HIGH':
        return '#ea580c'; // orange-600
      case 'MEDIUM':
        return '#ca8a04'; // yellow-600
      case 'LOW':
        return '#16a34a'; // green-600
      case 'VERY LOW':
        return '#059669'; // emerald-600
      default:
        return '#6b7280'; // gray-500
    }
  }

  /**
   * Get severity color for findings
   */
  static getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical':
        return '#dc2626'; // red-600
      case 'high':
        return '#ea580c'; // orange-600
      case 'medium':
        return '#ca8a04'; // yellow-600
      case 'low':
        return '#16a34a'; // green-600
      case 'info':
        return '#2563eb'; // blue-600
      default:
        return '#6b7280'; // gray-500
    }
  }

  /**
   * Calculate risk percentage for progress bars
   */
  static getRiskPercentage(riskScore: number): number {
    return Math.min(Math.max((riskScore / 100) * 100, 0), 100);
  }

  /**
   * Format timestamp for display
   */
  static formatTimestamp(isoString: string): string {
    try {
      const date = new Date(isoString);
      return date.toLocaleString();
    } catch {
      return isoString;
    }
  }

  /**
   * Download scan results as JSON
   */
  static downloadAsJSON(data: any, filename: string): void {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }

  /**
   * Clear all caches (Python, database, and memory)
   */
  static async clearCache(): Promise<{ success: boolean; message: string }> {
    const response = await api.post('/cache/clear');
    return response.data;
  }
}

export default ApiService;