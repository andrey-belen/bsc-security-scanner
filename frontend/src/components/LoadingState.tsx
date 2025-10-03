import React from 'react';
import { Shield, Clock, AlertTriangle, CheckCircle, Loader2, X } from 'lucide-react';

interface LoadingStateProps {
  analysisId: string;
  address: string;
  isQuickScan: boolean;
  elapsedTime?: number;
  onCancel?: () => void;
}

const LoadingState: React.FC<LoadingStateProps> = ({
  analysisId,
  address,
  isQuickScan,
  elapsedTime = 0,
  onCancel,
}) => {
  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  };

  const estimatedTotal = isQuickScan ? 45 : 90; // seconds (more realistic)
  const progress = Math.min((elapsedTime / estimatedTotal) * 100, 95); // Cap at 95% until complete
  const remainingTime = Math.max(estimatedTotal - elapsedTime, 0);

  // Warning states
  const isSlowAnalysis = elapsedTime > 90;
  const isVerySlowAnalysis = elapsedTime > 110;

  const analysisSteps = isQuickScan
    ? [
        'Verifying contract',
        'Analyzing ownership',
        'Scanning functions',
      ]
    : [
        'Verifying contract',
        'Analyzing ownership',
        'Detecting honeypot patterns',
        'Scanning dangerous functions',
        'Checking liquidity',
        'Computing risk score',
      ];

  const currentStepIndex = Math.min(
    Math.floor((elapsedTime / estimatedTotal) * analysisSteps.length),
    analysisSteps.length - 1
  );

  const getCurrentMessage = () => {
    if (isVerySlowAnalysis) {
      return 'Analysis is taking longer than expected. This may be a complex contract.';
    }
    if (isSlowAnalysis) {
      return 'Analysis taking longer than usual...';
    }
    return analysisSteps[currentStepIndex];
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="bg-[#161b22] rounded-lg border border-[#21262d] p-6 sm:p-8">
        {/* Header with terminal-style spinner */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-6">
            <div className="relative">
              <Shield className="h-16 w-16 text-[#00ff88]" />
              <div className="absolute -top-2 -right-2">
                <Loader2 className="h-8 w-8 text-[#00ff88] animate-spin" />
              </div>
            </div>
          </div>
          <h2 className="text-2xl sm:text-3xl font-bold text-[#e6edf3] mb-3">
            {isQuickScan ? '⚡ Quick Analysis' : '🔍 Security Analysis'} in Progress
          </h2>
          <div className="flex items-center justify-center gap-2 mb-2">
            <span className="text-[#8b949e]">Analyzing:</span>
            <code className="bg-[#0d1117] px-3 py-1.5 rounded border border-[#21262d] text-sm text-[#00ff88] font-mono">
              {address.slice(0, 10)}...{address.slice(-8)}
            </code>
          </div>
        </div>

        {/* Current step message with terminal aesthetic */}
        <div className="mb-6 p-4 bg-[#0d1117] border border-[#21262d] rounded-lg">
          <div className="flex items-center gap-3">
            <span className="text-[#00ff88] font-mono text-lg">&gt;</span>
            <span className="text-[#e6edf3] font-mono text-sm sm:text-base flex-1">
              {getCurrentMessage()}
            </span>
            <div className="flex gap-1">
              <span className="inline-block w-2 h-2 bg-[#00ff88] rounded-full animate-pulse"></span>
              <span className="inline-block w-2 h-2 bg-[#00ff88] rounded-full animate-pulse delay-75"></span>
              <span className="inline-block w-2 h-2 bg-[#00ff88] rounded-full animate-pulse delay-150"></span>
            </div>
          </div>
        </div>

        {/* Progress bar */}
        <div className="mb-6">
          <div className="flex justify-between text-sm text-[#8b949e] mb-2">
            <span>Progress</span>
            <span className="font-mono">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-[#0d1117] rounded-full h-2 border border-[#21262d]">
            <div
              className="bg-gradient-to-r from-[#00ff88] to-[#00cc6a] h-full rounded-full transition-all duration-500 ease-out"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
        </div>

        {/* Time info */}
        <div className="grid grid-cols-2 gap-4 mb-6">
          <div className="p-4 bg-[#0d1117] border border-[#21262d] rounded-lg">
            <div className="flex items-center gap-2 text-[#8b949e] text-xs mb-1">
              <Clock className="h-3.5 w-3.5" />
              <span>Elapsed</span>
            </div>
            <div className="text-[#e6edf3] font-mono text-lg font-semibold">
              {formatTime(elapsedTime)}
            </div>
          </div>
          <div className="p-4 bg-[#0d1117] border border-[#21262d] rounded-lg">
            <div className="text-[#8b949e] text-xs mb-1">Remaining</div>
            <div className="text-[#00ff88] font-mono text-lg font-semibold">
              ~{formatTime(remainingTime)}
            </div>
          </div>
        </div>

        {/* Timeout warnings */}
        {isVerySlowAnalysis && (
          <div className="mb-6 p-4 bg-[#ffd700]/10 border border-[#ffd700]/30 rounded-lg">
            <div className="flex items-start gap-3">
              <AlertTriangle className="h-5 w-5 text-[#ffd700] mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="text-[#ffd700] font-medium mb-1">Taking Longer Than Expected</h4>
                <p className="text-[#e6edf3] text-sm">
                  This contract may be complex or the network is slow. You can cancel and try quick scan mode.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Analysis steps */}
        <div className="mb-6">
          <h3 className="text-sm font-medium text-[#8b949e] mb-4 uppercase tracking-wide">
            Analysis Steps
          </h3>
          <div className="space-y-2">
            {analysisSteps.map((step, index) => (
              <div key={index} className="flex items-center gap-3 p-2 rounded transition-colors">
                {index < currentStepIndex ? (
                  <CheckCircle className="h-5 w-5 text-[#00ff88] flex-shrink-0" />
                ) : index === currentStepIndex ? (
                  <Loader2 className="h-5 w-5 text-[#00ff88] flex-shrink-0 animate-spin" />
                ) : (
                  <div className="h-5 w-5 rounded-full border-2 border-[#21262d] flex-shrink-0"></div>
                )}
                <span
                  className={`text-sm font-mono ${
                    index <= currentStepIndex
                      ? 'text-[#e6edf3] font-medium'
                      : 'text-[#6e7681]'
                  }`}
                >
                  {step}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Loading skeleton preview */}
        <div className="mb-6 p-4 bg-[#0d1117] border border-[#21262d] rounded-lg">
          <div className="space-y-3">
            <div className="h-4 bg-[#21262d] rounded animate-pulse w-3/4"></div>
            <div className="h-4 bg-[#21262d] rounded animate-pulse w-1/2"></div>
            <div className="h-4 bg-[#21262d] rounded animate-pulse w-5/6"></div>
          </div>
        </div>

        {/* Analysis ID */}
        <div className="border-t border-[#21262d] pt-6">
          <div className="text-xs text-[#6e7681] mb-2 uppercase tracking-wide">Analysis ID</div>
          <div className="font-mono text-xs bg-[#0d1117] p-3 rounded border border-[#21262d] text-[#8b949e] break-all">
            {analysisId}
          </div>
        </div>

        {/* Cancel button */}
        {onCancel && (
          <div className="mt-6 flex justify-center">
            <button
              onClick={onCancel}
              className="flex items-center gap-2 px-4 py-2 text-[#8b949e] hover:text-red-400 transition-colors text-sm group"
            >
              <X className="h-4 w-4 group-hover:rotate-90 transition-transform" />
              Cancel Analysis
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default LoadingState;