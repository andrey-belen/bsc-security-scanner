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
  Activity,
  Users,
  Droplets,
  FlaskConical,
  BarChart3,
  Lock,
  Unlock,
  Coins
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

  const getRiskLevelColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
      case 'HIGH':
        return 'from-red-500 to-red-600';
      case 'MEDIUM':
        return 'from-yellow-500 to-amber-500';
      case 'LOW':
      case 'VERY LOW':
        return 'from-green-500 to-emerald-500';
      default:
        return 'from-gray-500 to-gray-600';
    }
  };

  const getRiskTextColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'CRITICAL':
      case 'HIGH':
        return 'text-red-400';
      case 'MEDIUM':
        return 'text-yellow-400';
      case 'LOW':
      case 'VERY LOW':
        return 'text-green-400';
      default:
        return 'text-gray-400';
    }
  };

  const getSeverityStyles = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-500/10 border-red-500/30 text-red-400';
      case 'high':
        return 'bg-orange-500/10 border-orange-500/30 text-orange-400';
      case 'medium':
        return 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400';
      case 'low':
        return 'bg-blue-500/10 border-blue-500/30 text-blue-400';
      case 'info':
        return 'bg-green-500/10 border-green-500/30 text-green-400';
      default:
        return 'bg-gray-500/10 border-gray-500/30 text-gray-400';
    }
  };

  const downloadReport = () => {
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `bsc-security-scan-${result.address.slice(0, 10)}-${timestamp}.json`;
    ApiService.downloadAsJSON(result, filename);
  };

  const riskPercentage = ApiService.getRiskPercentage(result.risk_score);

  // Group findings by category
  const findingsByCategory = result.findings.reduce((acc, finding) => {
    const category = finding.type || 'general';
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(finding);
    return acc;
  }, {} as Record<string, ScanFinding[]>);

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'verification':
        return <Shield className="h-4 w-4" />;
      case 'ownership':
        return <Lock className="h-4 w-4" />;
      case 'functions':
        return <Activity className="h-4 w-4" />;
      case 'holders':
        return <Users className="h-4 w-4" />;
      case 'liquidity':
        return <Droplets className="h-4 w-4" />;
      case 'honeypot':
        return <FlaskConical className="h-4 w-4" />;
      case 'token_type':
        return <Coins className="h-4 w-4" />;
      default:
        return <AlertTriangle className="h-4 w-4" />;
    }
  };

  const getCategoryName = (category: string) => {
    switch (category) {
      case 'verification':
        return 'Contract Verification';
      case 'ownership':
        return 'Ownership Analysis';
      case 'functions':
        return 'Function Analysis';
      case 'holders':
        return 'Holder Distribution';
      case 'liquidity':
        return 'Liquidity Analysis';
      case 'honeypot':
        return 'Honeypot Detection';
      case 'token_type':
        return 'Token Classification';
      case 'source_code':
        return 'Source Code Analysis';
      default:
        return 'General Findings';
    }
  };

  // Get advanced analysis data
  const holderData = (result as any).holder_distribution;
  const liquidityData = (result as any).liquidity;
  const honeypotData = (result as any).honeypot_check;

  return (
    <div className="w-full max-w-7xl mx-auto">
      {/* Desktop Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* LEFT COLUMN - Key Metrics & Score */}
        <div className="lg:col-span-1 space-y-6">

          {/* Risk Score Card */}
          <div className="bg-gradient-to-br from-[#161b22] to-[#0d1117] rounded-2xl border border-[#21262d] p-6 relative overflow-hidden">
            {/* Animated background */}
            <div className={`absolute inset-0 bg-gradient-to-br ${getRiskLevelColor(result.risk_level)} opacity-5`}></div>

            <div className="relative z-10">
              <div className="text-center mb-4">
                <div className="text-sm text-[#6e7681] uppercase tracking-wider mb-2">Risk Assessment</div>
                <div className={`text-7xl font-bold font-mono mb-2 ${getRiskTextColor(result.risk_level)}`}>
                  {result.risk_score}
                </div>
                <div className="text-xl text-[#8b949e] mb-4">/ 100</div>

                {/* Risk Level Badge */}
                <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg border ${
                  result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH'
                    ? 'bg-red-500/20 border-red-500/50 text-red-400'
                    : result.risk_level === 'MEDIUM'
                    ? 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400'
                    : 'bg-green-500/20 border-green-500/50 text-green-400'
                }`}>
                  {result.risk_level === 'CRITICAL' || result.risk_level === 'HIGH' ? (
                    <XCircle className="h-5 w-5" />
                  ) : result.risk_level === 'MEDIUM' ? (
                    <AlertTriangle className="h-5 w-5" />
                  ) : (
                    <CheckCircle className="h-5 w-5" />
                  )}
                  <span className="font-bold">{result.risk_level}</span>
                </div>
              </div>

              {/* Progress Bar */}
              <div className="w-full bg-[#0d1117] rounded-full h-2 mb-4 overflow-hidden border border-[#21262d]">
                <div
                  className={`h-full bg-gradient-to-r ${getRiskLevelColor(result.risk_level)} transition-all duration-1000 ease-out`}
                  style={{ width: `${riskPercentage}%` }}
                ></div>
              </div>

              {/* Analysis Confidence */}
              {result.analysis_confidence !== undefined && (
                <div className="text-center text-sm text-[#8b949e]">
                  Analysis Confidence: {Math.round((result.analysis_confidence || 0) * 100)}%
                </div>
              )}
            </div>
          </div>

          {/* Contract Info Card */}
          <div className="bg-[#161b22] rounded-xl border border-[#21262d] p-6">
            <h3 className="text-sm font-semibold text-[#e6edf3] mb-4 uppercase tracking-wider flex items-center gap-2">
              <Info className="h-4 w-4 text-[#00ff88]" />
              Contract Info
            </h3>

            <div className="space-y-4">
              {/* Token Name/Symbol */}
              {(result.token_name || result.token_symbol) && (
                <div>
                  <div className="text-xs text-[#6e7681] mb-1">Token</div>
                  <div className="text-[#e6edf3] font-mono">
                    {result.token_name || 'Unknown'}
                    {result.token_symbol && <span className="text-[#00ff88]"> ({result.token_symbol})</span>}
                  </div>
                </div>
              )}

              {/* Address */}
              <div>
                <div className="text-xs text-[#6e7681] mb-1">Address</div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-[#0d1117] px-2 py-1.5 rounded border border-[#21262d] text-[#00ff88] font-mono text-xs truncate">
                    {result.address}
                  </code>
                  <button
                    onClick={copyAddress}
                    className="p-1.5 bg-[#21262d] hover:bg-[#30363d] rounded border border-[#30363d] transition-colors"
                    title="Copy address"
                  >
                    {copiedAddress ? (
                      <Check className="h-3 w-3 text-[#00ff88]" />
                    ) : (
                      <Copy className="h-3 w-3 text-[#8b949e]" />
                    )}
                  </button>
                </div>
              </div>

              {/* Verification Status */}
              {result.is_verified !== undefined && (
                <div>
                  <div className="text-xs text-[#6e7681] mb-1">Verification</div>
                  <div className={`flex items-center gap-2 ${result.is_verified ? 'text-green-400' : 'text-orange-400'}`}>
                    {result.is_verified ? (
                      <>
                        <CheckCircle className="h-4 w-4" />
                        <span className="text-sm">Verified</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-4 w-4" />
                        <span className="text-sm">Unverified</span>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* Ownership Status */}
              {result.is_renounced !== undefined && (
                <div>
                  <div className="text-xs text-[#6e7681] mb-1">Ownership</div>
                  <div className={`flex items-center gap-2 ${result.is_renounced ? 'text-green-400' : 'text-yellow-400'}`}>
                    {result.is_renounced ? (
                      <>
                        <Unlock className="h-4 w-4" />
                        <span className="text-sm">Renounced</span>
                      </>
                    ) : (
                      <>
                        <Lock className="h-4 w-4" />
                        <span className="text-sm">Active Owner</span>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* Scan Type */}
              <div>
                <div className="text-xs text-[#6e7681] mb-1">Scan Type</div>
                <div className="flex items-center gap-2 text-[#e6edf3]">
                  {result.quick_scan ? (
                    <>
                      <Zap className="h-4 w-4 text-[#ffd700]" />
                      <span className="text-sm">Quick Scan</span>
                    </>
                  ) : (
                    <>
                      <Shield className="h-4 w-4 text-[#00ff88]" />
                      <span className="text-sm">Full Scan</span>
                    </>
                  )}
                </div>
              </div>

              {/* Scan Time */}
              {result.scan_time && (
                <div>
                  <div className="text-xs text-[#6e7681] mb-1">Analyzed</div>
                  <div className="flex items-center gap-2 text-[#e6edf3]">
                    <Clock className="h-4 w-4 text-[#8b949e]" />
                    <span className="text-sm">{new Date(result.scan_time).toLocaleString()}</span>
                  </div>
                </div>
              )}
            </div>

            {/* BSCScan Link */}
            <a
              href={`https://bscscan.com/address/${result.address}`}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 flex items-center justify-center gap-2 w-full px-4 py-2 bg-[#0d1117] border border-[#21262d] rounded-lg text-[#00ff88] hover:bg-[#21262d] transition-colors text-sm"
            >
              View on BSCScan
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>

          {/* Advanced Metrics */}
          {!result.quick_scan && (holderData || liquidityData || honeypotData) && (
            <div className="bg-[#161b22] rounded-xl border border-[#21262d] p-6">
              <h3 className="text-sm font-semibold text-[#e6edf3] mb-4 uppercase tracking-wider flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-[#00ff88]" />
                Advanced Metrics
              </h3>

              <div className="space-y-3">
                {/* Holder Metrics */}
                {holderData?.metrics && (
                  <div className="bg-[#0d1117] rounded-lg p-3 border border-[#21262d]">
                    <div className="flex items-center gap-2 mb-2">
                      <Users className="h-4 w-4 text-[#00ff88]" />
                      <span className="text-xs font-semibold text-[#e6edf3] uppercase">Holders</span>
                    </div>
                    <div className="space-y-1 text-xs text-[#8b949e]">
                      <div className="flex justify-between">
                        <span>Total:</span>
                        <span className="text-[#e6edf3]">{holderData.metrics.total_holders?.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Top 10:</span>
                        <span className="text-[#e6edf3]">{holderData.metrics.top_10_concentration?.toFixed(1)}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Whales:</span>
                        <span className="text-[#e6edf3]">{holderData.metrics.whale_count}</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Liquidity Metrics */}
                {liquidityData?.metrics && (
                  <div className="bg-[#0d1117] rounded-lg p-3 border border-[#21262d]">
                    <div className="flex items-center gap-2 mb-2">
                      <Droplets className="h-4 w-4 text-[#00ff88]" />
                      <span className="text-xs font-semibold text-[#e6edf3] uppercase">Liquidity</span>
                    </div>
                    <div className="space-y-1 text-xs text-[#8b949e]">
                      <div className="flex justify-between">
                        <span>Total USD:</span>
                        <span className="text-[#e6edf3]">${liquidityData.metrics.total_liquidity_usd?.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>LP Locked:</span>
                        <span className="text-[#e6edf3]">{liquidityData.metrics.lp_locked_percent?.toFixed(1)}%</span>
                      </div>
                      <div className="flex justify-between">
                        <span>LP Burned:</span>
                        <span className="text-[#e6edf3]">{liquidityData.metrics.lp_burned_percent?.toFixed(1)}%</span>
                      </div>
                    </div>
                  </div>
                )}

                {/* Honeypot Status */}
                {honeypotData && (
                  <div className="bg-[#0d1117] rounded-lg p-3 border border-[#21262d]">
                    <div className="flex items-center gap-2 mb-2">
                      <FlaskConical className="h-4 w-4 text-[#00ff88]" />
                      <span className="text-xs font-semibold text-[#e6edf3] uppercase">Honeypot</span>
                    </div>
                    <div className="space-y-1 text-xs">
                      <div className={`flex items-center gap-2 ${honeypotData.is_honeypot ? 'text-red-400' : 'text-green-400'}`}>
                        {honeypotData.is_honeypot ? (
                          <>
                            <XCircle className="h-4 w-4" />
                            <span className="font-semibold">DETECTED</span>
                          </>
                        ) : (
                          <>
                            <CheckCircle className="h-4 w-4" />
                            <span className="font-semibold">Not Detected</span>
                          </>
                        )}
                      </div>
                      {honeypotData.simulation_confidence !== undefined && (
                        <div className="text-[#8b949e]">
                          Confidence: {Math.round(honeypotData.simulation_confidence * 100)}%
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Action Buttons */}
          <div className="space-y-3">
            <button
              onClick={onNewScan}
              className="w-full px-4 py-3 bg-gradient-to-r from-[#00ff88] to-[#00cc6a] text-[#0d1117] rounded-lg font-semibold hover:opacity-90 transition-opacity flex items-center justify-center gap-2"
            >
              <Zap className="h-5 w-5" />
              New Scan
            </button>
            <button
              onClick={downloadReport}
              className="w-full px-4 py-3 bg-[#21262d] text-[#e6edf3] rounded-lg font-semibold hover:bg-[#30363d] transition-colors flex items-center justify-center gap-2"
            >
              <Download className="h-5 w-5" />
              Download Report
            </button>
          </div>
        </div>

        {/* RIGHT COLUMN - Findings */}
        <div className="lg:col-span-2 space-y-6">

          {/* Findings Header */}
          <div className="bg-gradient-to-br from-[#161b22] to-[#0d1117] rounded-2xl border border-[#21262d] p-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <AlertTriangle className="h-6 w-6 text-[#ffd700]" />
                <h2 className="text-2xl font-bold text-[#e6edf3]">Security Findings</h2>
              </div>
              <div className="text-3xl font-bold text-[#00ff88]">{result.findings.length}</div>
            </div>
          </div>

          {/* Findings by Category */}
          {result.findings.length > 0 ? (
            <div className="space-y-4">
              {Object.entries(findingsByCategory).map(([category, findings]) => (
                <div key={category} className="bg-[#161b22] rounded-xl border border-[#21262d] overflow-hidden">
                  <div className="bg-[#0d1117] border-b border-[#21262d] px-4 py-3">
                    <div className="flex items-center gap-2 text-[#00ff88]">
                      {getCategoryIcon(category)}
                      <h3 className="font-semibold uppercase tracking-wider text-sm">{getCategoryName(category)}</h3>
                      <span className="text-xs text-[#6e7681]">({findings.length})</span>
                    </div>
                  </div>

                  <div className="p-4 space-y-2">
                    {findings.map((finding) => {
                      const globalIndex = result.findings.indexOf(finding);
                      const isExpanded = expandedFindings.has(globalIndex);
                      const hasDetails = finding.details && finding.details.length > 0;

                      return (
                        <div
                          key={globalIndex}
                          className={`rounded-lg border overflow-hidden transition-colors ${getSeverityStyles(finding.severity)}`}
                        >
                          <button
                            onClick={() => hasDetails && toggleFinding(globalIndex)}
                            className={`w-full p-3 text-left transition-colors ${
                              hasDetails ? 'hover:bg-[#0d1117]/50 cursor-pointer' : 'cursor-default'
                            }`}
                          >
                            <div className="flex items-start gap-3">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-start justify-between gap-2">
                                  <div className="flex-1">
                                    <h4 className="font-semibold text-sm mb-1">
                                      {finding.message}
                                    </h4>
                                    <div className="flex items-center gap-2">
                                      <span className="text-xs uppercase font-bold tracking-wider">
                                        {finding.severity}
                                      </span>
                                    </div>
                                  </div>
                                  {hasDetails && (
                                    <div className="flex-shrink-0">
                                      {isExpanded ? (
                                        <ChevronDown className="h-5 w-5" />
                                      ) : (
                                        <ChevronRight className="h-5 w-5" />
                                      )}
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          </button>

                          {isExpanded && hasDetails && (
                            <div className="px-3 pb-3 border-t border-current/20 pt-3">
                              <p className="text-xs opacity-80 whitespace-pre-wrap leading-relaxed">
                                {finding.details}
                              </p>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="bg-[#161b22] rounded-xl border border-[#00ff88]/30 p-12 text-center">
              <CheckCircle className="h-16 w-16 text-[#00ff88] mx-auto mb-4" />
              <h3 className="text-2xl font-bold text-[#e6edf3] mb-2">
                No Security Issues Found
              </h3>
              <p className="text-[#8b949e]">
                This contract passed all security checks. However, always conduct your own research.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanResults;
