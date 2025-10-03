import React, { useState } from 'react';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Download,
  ExternalLink,
  Clock,
  Zap,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Tag
} from 'lucide-react';
import { ScanResult, ScanFinding } from '../types/api';
import { ApiService } from '../services/api';

interface ScanResultsProps {
  result: ScanResult;
  onNewScan: () => void;
}

const ScanResults: React.FC<ScanResultsProps> = ({ result, onNewScan }) => {
  const [copiedAddress, setCopiedAddress] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());

  const copyAddress = async () => {
    try {
      await navigator.clipboard.writeText(result.address);
      setCopiedAddress(true);
      setTimeout(() => setCopiedAddress(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const toggleFinding = (index: number) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedFindings(newExpanded);
  };

  const getRiskLevelIcon = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return <XCircle className="h-12 sm:h-16 w-12 sm:w-16" />;
      case 'HIGH':
        return <AlertTriangle className="h-12 sm:h-16 w-12 sm:w-16" />;
      case 'MEDIUM':
        return <AlertTriangle className="h-12 sm:h-16 w-12 sm:w-16" />;
      case 'LOW':
        return <CheckCircle className="h-12 sm:h-16 w-12 sm:w-16" />;
      case 'VERY LOW':
        return <CheckCircle className="h-12 sm:h-16 w-12 sm:w-16" />;
      default:
        return <Shield className="h-12 sm:h-16 w-12 sm:w-16" />;
    }
  };

  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return 'text-red-500';
      case 'HIGH':
        return 'text-red-500';
      case 'MEDIUM':
        return 'text-[#ffd700]';
      case 'LOW':
        return 'text-[#00ff88]';
      case 'VERY LOW':
        return 'text-[#00ff88]';
      default:
        return 'text-[#8b949e]';
    }
  };

  const getRiskBadgeBg = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return 'bg-red-500/20 border-red-500/50 text-red-400';
      case 'HIGH':
        return 'bg-red-500/20 border-red-500/50 text-red-400';
      case 'MEDIUM':
        return 'bg-[#ffd700]/20 border-[#ffd700]/50 text-[#ffd700]';
      case 'LOW':
        return 'bg-[#00ff88]/20 border-[#00ff88]/50 text-[#00ff88]';
      case 'VERY LOW':
        return 'bg-[#00ff88]/20 border-[#00ff88]/50 text-[#00ff88]';
      default:
        return 'bg-[#8b949e]/20 border-[#8b949e]/50 text-[#8b949e]';
    }
  };

  const getRiskInterpretation = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
        return 'This contract has critical security vulnerabilities. Avoid interaction.';
      case 'HIGH':
        return 'This contract has significant security concerns. Proceed with extreme caution.';
      case 'MEDIUM':
        return 'This contract has moderate security concerns. Conduct additional research.';
      case 'LOW':
        return 'This contract appears relatively safe, but always verify independently.';
      case 'VERY LOW':
        return 'This contract appears safe with no significant security concerns detected.';
      default:
        return 'Analysis completed with unknown risk level.';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '🔴';
      case 'high':
        return '⚠️';
      case 'medium':
        return '⚡';
      case 'low':
        return '✓';
      case 'info':
        return 'ℹ️';
      default:
        return '•';
    }
  };

  const downloadReport = () => {
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `bsc-security-scan-${result.address.slice(0, 10)}-${timestamp}.json`;
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
    <div className="w-full max-w-4xl mx-auto space-y-6">
      {/* Massive Risk Badge - Above the Fold */}
      <div className="bg-[#161b22] rounded-lg border border-[#21262d] p-8 sm:p-12 text-center">
        <div className={`flex justify-center mb-6 ${getRiskLevelColor(result.risk_level)}`}>
          {getRiskLevelIcon(result.risk_level)}
        </div>

        <div className={`inline-flex items-center px-6 py-3 rounded-lg border-2 text-2xl sm:text-4xl font-bold mb-4 ${getRiskBadgeBg(result.risk_level)}`}>
          {result.risk_level}
        </div>

        <div className="text-4xl sm:text-6xl font-mono font-bold text-[#e6edf3] mb-4">
          {result.risk_score}<span className="text-[#6e7681]">/100</span>
        </div>

        <p className="text-[#8b949e] text-sm sm:text-base max-w-2xl mx-auto mb-6">
          {getRiskInterpretation(result.risk_level)}
        </p>

        {/* Progress bar */}
        <div className="w-full max-w-md mx-auto bg-[#0d1117] rounded-full h-3 border border-[#21262d] mb-6">
          <div
            className={`h-full rounded-full transition-all duration-500 ${
              result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH' ? 'bg-gradient-to-r from-red-500 to-red-600' :
              result.risk_level === 'MEDIUM' ? 'bg-gradient-to-r from-[#ffd700] to-yellow-500' :
              'bg-gradient-to-r from-[#00ff88] to-[#00cc6a]'
            }`}
            style={{ width: `${riskPercentage}%` }}
          ></div>
        </div>

        {/* Action buttons */}
        <div className="flex flex-col sm:flex-row gap-3 justify-center">
          <button
            onClick={onNewScan}
            className="px-6 py-3 bg-[#00ff88] text-[#0d1117] rounded-lg font-semibold hover:bg-[#00ff88]/90 transition-colors flex items-center justify-center gap-2"
          >
            <Zap className="h-5 w-5" />
            Analyze Another Contract
          </button>
          <button
            onClick={downloadReport}
            className="px-6 py-3 bg-[#21262d] text-[#e6edf3] rounded-lg font-semibold hover:bg-[#30363d] transition-colors flex items-center justify-center gap-2"
          >
            <Download className="h-5 w-5" />
            Download Report
          </button>
        </div>
      </div>

      {/* Contract Info */}
      <div className="bg-[#161b22] rounded-lg border border-[#21262d] p-6">
        <h3 className="text-lg font-semibold text-[#e6edf3] mb-4 flex items-center gap-2">
          <Info className="h-5 w-5 text-[#00ff88]" />
          Contract Information
        </h3>

        <div className="space-y-4">
          {/* Address with copy */}
          <div>
            <div className="text-xs text-[#6e7681] mb-1 uppercase tracking-wide">Address</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-[#0d1117] px-3 py-2 rounded border border-[#21262d] text-[#00ff88] font-mono text-sm break-all">
                {result.address}
              </code>
              <button
                onClick={copyAddress}
                className="p-2 bg-[#21262d] hover:bg-[#30363d] rounded border border-[#30363d] transition-colors"
                title="Copy address"
              >
                {copiedAddress ? (
                  <Check className="h-4 w-4 text-[#00ff88]" />
                ) : (
                  <Copy className="h-4 w-4 text-[#8b949e]" />
                )}
              </button>
            </div>
          </div>

          {/* Token archetype */}
          {result.archetype && result.archetype.type !== 'unknown' && (
            <div>
              <div className="text-xs text-[#6e7681] mb-1 uppercase tracking-wide">Token Type</div>
              <div className="flex items-center gap-2">
                <Tag className="h-4 w-4 text-[#00ff88]" />
                <span className="text-[#e6edf3] font-medium capitalize">
                  {result.archetype.type.replace('_', ' ')}
                </span>
                {result.archetype.confidence && (
                  <span className="text-xs text-[#8b949e]">
                    ({Math.round(result.archetype.confidence * 100)}% confidence)
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Metadata grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 pt-4 border-t border-[#21262d]">
            {result.quick_scan !== undefined && (
              <div>
                <div className="text-xs text-[#6e7681] mb-1">Scan Type</div>
                <div className="flex items-center gap-1 text-[#e6edf3]">
                  {result.quick_scan ? (
                    <>
                      <Zap className="h-4 w-4 text-[#ffd700]" />
                      <span className="text-sm">Quick</span>
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4 text-[#00ff88]" />
                      <span className="text-sm">Full</span>
                    </>
                  )}
                </div>
              </div>
            )}

            {result.scan_time && (
              <div>
                <div className="text-xs text-[#6e7681] mb-1">Scanned</div>
                <div className="flex items-center gap-1 text-[#e6edf3]">
                  <Clock className="h-4 w-4 text-[#8b949e]" />
                  <span className="text-sm">{new Date(result.scan_time).toLocaleDateString()}</span>
                </div>
              </div>
            )}

            <div className="col-span-2 sm:col-span-1">
              <div className="text-xs text-[#6e7681] mb-1">Blockchain</div>
              <div className="text-sm text-[#e6edf3]">
                <a
                  href={`https://bscscan.com/address/${result.address}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-[#00ff88] hover:text-[#00cc6a] transition-colors"
                >
                  View on BSCScan
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Security Findings */}
      {result.findings.length > 0 ? (
        <div className="bg-[#161b22] rounded-lg border border-[#21262d] p-6">
          <h3 className="text-lg font-semibold text-[#e6edf3] mb-4 flex items-center gap-2">
            <AlertTriangle className="h-5 w-5 text-[#ffd700]" />
            Security Findings ({result.findings.length})
          </h3>

          <div className="space-y-3">
            {result.findings.map((finding, index) => {
              const isExpanded = expandedFindings.has(index);
              const hasDetails = finding.details && finding.details.length > 0;

              return (
                <div
                  key={index}
                  className="bg-[#0d1117] border border-[#21262d] rounded-lg overflow-hidden"
                >
                  <button
                    onClick={() => hasDetails && toggleFinding(index)}
                    className={`w-full p-4 text-left transition-colors ${
                      hasDetails ? 'hover:bg-[#161b22] cursor-pointer' : 'cursor-default'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <span className="text-lg flex-shrink-0 mt-0.5">
                        {getSeverityIcon(finding.severity)}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <h4 className="text-[#e6edf3] font-medium text-sm sm:text-base">
                            {finding.message}
                          </h4>
                          {hasDetails && (
                            <div className="flex-shrink-0">
                              {isExpanded ? (
                                <ChevronDown className="h-5 w-5 text-[#8b949e]" />
                              ) : (
                                <ChevronRight className="h-5 w-5 text-[#8b949e]" />
                              )}
                            </div>
                          )}
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <span className="text-xs text-[#6e7681] uppercase tracking-wide">
                            {finding.severity}
                          </span>
                          {finding.type && (
                            <>
                              <span className="text-[#6e7681]">•</span>
                              <span className="text-xs text-[#8b949e]">
                                {finding.type.replace('_', ' ')}
                              </span>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  </button>

                  {isExpanded && hasDetails && (
                    <div className="px-4 pb-4 border-t border-[#21262d] pt-4 mt-2">
                      <p className="text-sm text-[#8b949e] whitespace-pre-wrap">
                        {finding.details}
                      </p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="bg-[#161b22] rounded-lg border border-[#00ff88]/30 p-8 text-center">
          <CheckCircle className="h-12 w-12 text-[#00ff88] mx-auto mb-4" />
          <h3 className="text-xl font-semibold text-[#e6edf3] mb-2">
            No Security Issues Found
          </h3>
          <p className="text-[#8b949e]">
            This contract passed all security checks. However, always conduct your own research.
          </p>
        </div>
      )}

      {/* Bottom action button */}
      <div className="flex justify-center">
        <button
          onClick={onNewScan}
          className="px-6 py-3 bg-[#21262d] text-[#e6edf3] rounded-lg font-medium hover:bg-[#30363d] transition-colors flex items-center gap-2"
        >
          <Zap className="h-5 w-5" />
          Analyze Another Contract
        </button>
      </div>
    </div>
  );
};

export default ScanResults;
