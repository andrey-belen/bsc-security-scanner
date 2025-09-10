import React from 'react';
import { Shield, Clock, Search, CheckCircle } from 'lucide-react';

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

  const estimatedTotal = isQuickScan ? 60 : 180; // seconds
  const progress = Math.min((elapsedTime / estimatedTotal) * 100, 95); // Cap at 95% until complete

  const analysisSteps = isQuickScan
    ? [
        'Contract verification check',
        'Basic ownership analysis',
        'Quick function scan',
      ]
    : [
        'Contract verification check',
        'Ownership analysis',
        'Honeypot detection',
        'Function analysis',
        'Liquidity analysis',
        'Holder distribution check',
      ];

  const currentStepIndex = Math.min(
    Math.floor((elapsedTime / estimatedTotal) * analysisSteps.length),
    analysisSteps.length - 1
  );

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6">
        {/* Header */}
        <div className="text-center mb-6">
          <div className="flex justify-center mb-4">
            <div className="relative">
              <Shield className="h-12 w-12 text-blue-600" />
              <div className="absolute -top-1 -right-1 h-6 w-6 bg-blue-600 rounded-full flex items-center justify-center">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              </div>
            </div>
          </div>
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            {isQuickScan ? 'Quick Analysis' : 'Security Analysis'} in Progress
          </h2>
          <p className="text-gray-600">
            Analyzing contract: <code className="bg-gray-100 px-2 py-1 rounded text-sm">{address}</code>
          </p>
        </div>

        {/* Progress Bar */}
        <div className="mb-6">
          <div className="flex justify-between text-sm text-gray-600 mb-2">
            <span>Progress</span>
            <span>{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-3">
            <div
              className="bg-gradient-to-r from-blue-500 to-blue-600 h-3 rounded-full transition-all duration-500 ease-out"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
        </div>

        {/* Time Info */}
        <div className="flex justify-between items-center mb-6 p-4 bg-gray-50 rounded-lg">
          <div className="flex items-center text-gray-600">
            <Clock className="h-4 w-4 mr-2" />
            <span className="text-sm">
              Elapsed: <span className="font-medium">{formatTime(elapsedTime)}</span>
            </span>
          </div>
          <div className="text-sm text-gray-600">
            Estimated: <span className="font-medium">{isQuickScan ? '30-60s' : '2-3min'}</span>
          </div>
        </div>

        {/* Analysis Steps */}
        <div className="space-y-3 mb-6">
          <h3 className="font-medium text-gray-900 mb-3">Analysis Steps</h3>
          {analysisSteps.map((step, index) => (
            <div key={index} className="flex items-center space-x-3">
              {index < currentStepIndex ? (
                <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0" />
              ) : index === currentStepIndex ? (
                <div className="h-5 w-5 flex-shrink-0">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-blue-500"></div>
                </div>
              ) : (
                <div className="h-5 w-5 rounded-full border-2 border-gray-300 flex-shrink-0"></div>
              )}
              <span
                className={`text-sm ${
                  index <= currentStepIndex
                    ? 'text-gray-900 font-medium'
                    : 'text-gray-500'
                }`}
              >
                {step}
              </span>
            </div>
          ))}
        </div>

        {/* Analysis ID and Info */}
        <div className="border-t border-gray-200 pt-4">
          <div className="text-xs text-gray-500 mb-2">Analysis ID</div>
          <div className="font-mono text-sm bg-gray-100 p-2 rounded border">
            {analysisId}
          </div>
          
          <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-lg">
            <div className="flex items-start">
              <Search className="h-4 w-4 text-blue-600 mt-0.5 mr-2 flex-shrink-0" />
              <div className="text-sm text-blue-700">
                <strong>What we're analyzing:</strong> Smart contract bytecode, ownership patterns, 
                transaction restrictions, tax mechanisms, and liquidity conditions to identify 
                potential security risks and vulnerabilities.
              </div>
            </div>
          </div>
        </div>

        {/* Cancel Button */}
        {onCancel && (
          <div className="mt-6 text-center">
            <button
              onClick={onCancel}
              className="px-4 py-2 text-gray-600 hover:text-gray-800 text-sm underline"
            >
              Cancel Analysis
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default LoadingState;