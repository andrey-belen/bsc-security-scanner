import React from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Info, 
  Download,
  ExternalLink,
  Clock,
  Zap
} from 'lucide-react';
import { ScanResult, ScanFinding } from '../types/api';
import { ApiService } from '../services/api';

interface ScanResultsProps {
  result: ScanResult;
  onNewScan: () => void;
}

const ScanResults: React.FC<ScanResultsProps> = ({ result, onNewScan }) => {
  const getRiskLevelIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return <XCircle className="h-6 w-6 text-red-600" />;
      case 'HIGH':
        return <AlertTriangle className="h-6 w-6 text-orange-600" />;
      case 'MEDIUM':
        return <AlertTriangle className="h-6 w-6 text-yellow-600" />;
      case 'LOW':
        return <CheckCircle className="h-6 w-6 text-green-600" />;
      case 'VERY LOW':
        return <CheckCircle className="h-6 w-6 text-emerald-600" />;
      default:
        return <Info className="h-6 w-6 text-gray-600" />;
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return <XCircle className="h-5 w-5 text-red-500" />;
      case 'high':
        return <AlertTriangle className="h-5 w-5 text-orange-500" />;
      case 'medium':
        return <AlertTriangle className="h-5 w-5 text-yellow-500" />;
      case 'low':
        return <CheckCircle className="h-5 w-5 text-green-500" />;
      case 'info':
        return <Info className="h-5 w-5 text-blue-500" />;
      default:
        return <Info className="h-5 w-5 text-gray-500" />;
    }
  };

  const getRiskLevelBadgeClass = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'MEDIUM':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'LOW':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'VERY LOW':
        return 'bg-emerald-100 text-emerald-800 border-emerald-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getSeverityBadgeClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-700 border-red-200';
      case 'high':
        return 'bg-orange-100 text-orange-700 border-orange-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-700 border-yellow-200';
      case 'low':
        return 'bg-green-100 text-green-700 border-green-200';
      case 'info':
        return 'bg-blue-100 text-blue-700 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-700 border-gray-200';
    }
  };

  const downloadReport = () => {
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `bsc-security-scan-${ApiService.formatAddress(result.address)}-${timestamp}.json`;
    ApiService.downloadAsJSON(result, filename);
  };

  const riskPercentage = ApiService.getRiskPercentage(result.risk_score);

  // Group findings by severity
  const findingsBySeverity = result.findings.reduce((acc, finding) => {
    if (!acc[finding.severity]) {
      acc[finding.severity] = [];
    }
    acc[finding.severity].push(finding);
    return acc;
  }, {} as Record<string, ScanFinding[]>);

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-2xl font-bold text-gray-900 flex items-center">
              <Shield className="h-6 w-6 mr-2 text-blue-600" />
              Security Analysis Complete
            </h2>
            <p className="text-gray-600 mt-1">
              Contract: <code className="bg-gray-100 px-2 py-1 rounded text-sm">{result.address}</code>
            </p>
          </div>
          <div className="flex space-x-3">
            <button
              onClick={downloadReport}
              className="flex items-center px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors"
            >
              <Download className="h-4 w-4 mr-2" />
              Download Report
            </button>
            <button
              onClick={onNewScan}
              className="flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              <Zap className="h-4 w-4 mr-2" />
              New Scan
            </button>
          </div>
        </div>

        {/* Contract Info */}
        {(result.name || result.symbol) && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            {result.name && (
              <div>
                <span className="text-sm text-gray-500">Token Name</span>
                <p className="font-medium">{result.name}</p>
              </div>
            )}
            {result.symbol && (
              <div>
                <span className="text-sm text-gray-500">Symbol</span>
                <p className="font-medium">{result.symbol}</p>
              </div>
            )}
            <div>
              <span className="text-sm text-gray-500">Scan Type</span>
              <div className="flex items-center">
                {result.quick_scan ? (
                  <>
                    <Zap className="h-4 w-4 mr-1 text-yellow-500" />
                    <span className="font-medium">Quick Scan</span>
                  </>
                ) : (
                  <>
                    <Clock className="h-4 w-4 mr-1 text-blue-500" />
                    <span className="font-medium">Full Analysis</span>
                  </>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Risk Score */}
        <div className="bg-gray-50 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center">
              {getRiskLevelIcon(result.risk_level)}
              <div className="ml-3">
                <h3 className="text-lg font-semibold text-gray-900">Risk Assessment</h3>
                <p className="text-gray-600">Overall security evaluation</p>
              </div>
            </div>
            <div className="text-right">
              <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getRiskLevelBadgeClass(result.risk_level)}`}>
                {result.risk_level}
              </div>
              <p className="text-2xl font-bold text-gray-900 mt-1">
                {result.risk_score}/100
              </p>
            </div>
          </div>

          {/* Risk Progress Bar */}
          <div className="w-full bg-gray-200 rounded-full h-3 mb-2">
            <div
              className={`h-3 rounded-full transition-all duration-500 ${
                result.risk_level === 'CRITICAL' ? 'bg-red-500' :
                result.risk_level === 'HIGH' ? 'bg-orange-500' :
                result.risk_level === 'MEDIUM' ? 'bg-yellow-500' :
                result.risk_level === 'LOW' ? 'bg-green-500' :
                'bg-emerald-500'
              }`}
              style={{ width: `${riskPercentage}%` }}
            ></div>
          </div>
          <p className="text-sm text-gray-600">
            {result.findings.length} security finding{result.findings.length !== 1 ? 's' : ''} detected
          </p>
        </div>
      </div>

      {/* Error Display */}
      {result.error && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-4">
          <div className="flex items-start">
            <XCircle className="h-5 w-5 text-red-500 mt-0.5 mr-3" />
            <div>
              <h4 className="font-medium text-red-800">Analysis Error</h4>
              <p className="text-red-700 mt-1">{result.error}</p>
              {result.error_type && (
                <p className="text-sm text-red-600 mt-1">Error Type: {result.error_type}</p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Security Findings */}
      {result.findings.length > 0 && (
        <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6">
          <h3 className="text-xl font-bold text-gray-900 mb-4 flex items-center">
            <AlertTriangle className="h-5 w-5 mr-2 text-orange-500" />
            Security Findings ({result.findings.length})
          </h3>

          <div className="space-y-4">
            {severityOrder.map(severity => {
              const findings = findingsBySeverity[severity];
              if (!findings || findings.length === 0) return null;

              return (
                <div key={severity} className="border border-gray-200 rounded-lg overflow-hidden">
                  <div className={`px-4 py-3 ${getSeverityBadgeClass(severity)} border-b border-gray-200`}>
                    <div className="flex items-center">
                      {getSeverityIcon(severity)}
                      <span className="ml-2 font-medium capitalize">
                        {severity} ({findings.length})
                      </span>
                    </div>
                  </div>
                  <div className="divide-y divide-gray-200">
                    {findings.map((finding, index) => (
                      <div key={`${severity}-${index}`} className="p-4">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <h4 className="font-medium text-gray-900 mb-2">
                              {finding.message.replace(/[\u{1f600}-\u{1f64f}\u{1f300}-\u{1f5ff}\u{1f680}-\u{1f6ff}\u{1f1e0}-\u{1f1ff}\u{2600}-\u{26ff}\u{2700}-\u{27bf}]/gu, '')}
                            </h4>
                            <p className="text-gray-600 text-sm mb-2">{finding.details}</p>
                            <div className="flex items-center text-xs text-gray-500">
                              <span className="bg-gray-100 px-2 py-1 rounded">
                                {finding.type.replace('_', ' ')}
                              </span>
                            </div>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Warnings */}
      {result.warnings && result.warnings.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h4 className="font-medium text-yellow-800 mb-3 flex items-center">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Analysis Warnings ({result.warnings.length})
          </h4>
          <div className="space-y-2">
            {result.warnings.map((warning, index) => (
              <div key={index} className="text-sm text-yellow-700">
                <strong>{warning.analysis}:</strong> {warning.error}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analysis Metadata */}
      <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Analysis Details</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <span className="text-sm text-gray-500">Scan Time</span>
            <p className="font-medium">{ApiService.formatTimestamp(result.scan_time)}</p>
          </div>
          <div>
            <span className="text-sm text-gray-500">Blockchain</span>
            <p className="font-medium">{result.chain}</p>
          </div>
          {result.is_verified !== undefined && (
            <div>
              <span className="text-sm text-gray-500">Contract Verification</span>
              <div className="flex items-center">
                {result.is_verified ? (
                  <>
                    <CheckCircle className="h-4 w-4 text-green-500 mr-1" />
                    <span className="font-medium text-green-700">Verified</span>
                  </>
                ) : (
                  <>
                    <XCircle className="h-4 w-4 text-red-500 mr-1" />
                    <span className="font-medium text-red-700">Not Verified</span>
                  </>
                )}
              </div>
            </div>
          )}
          <div>
            <span className="text-sm text-gray-500">BSCScan</span>
            <a
              href={`https://bscscan.com/address/${result.address}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center text-blue-600 hover:text-blue-800 font-medium"
            >
              View on BSCScan
              <ExternalLink className="h-3 w-3 ml-1" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanResults;