import React, { useState, useRef, useEffect } from 'react';
import { Search, AlertCircle, Clock, Zap, X, Check, Clipboard } from 'lucide-react';
import { ApiService } from '../services/api';
import { AnalysisRequest } from '../types/api';

interface ContractAnalysisFormProps {
  onAnalysisStart: (analysisId: string, isQuickScan: boolean) => void;
  isLoading: boolean;
}

const ContractAnalysisForm: React.FC<ContractAnalysisFormProps> = ({
  onAnalysisStart,
  isLoading,
}) => {
  const [address, setAddress] = useState('');
  const [quickScan, setQuickScan] = useState(false);
  const [error, setError] = useState('');
  const [isFocused, setIsFocused] = useState(false);
  const [isValid, setIsValid] = useState<boolean | null>(null);
  const [showPasteButton, setShowPasteButton] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-focus on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  // Check if Clipboard API is available
  useEffect(() => {
    setShowPasteButton('clipboard' in navigator && 'readText' in navigator.clipboard);
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validate address
    if (!address.trim()) {
      setError('Please enter a contract address');
      return;
    }

    const trimmedAddress = address.trim().toLowerCase();
    if (!ApiService.isValidBSCAddress(trimmedAddress)) {
      setError('Invalid BSC address format. Address should be 40 characters starting with 0x');
      return;
    }

    try {
      const request: AnalysisRequest = {
        address: trimmedAddress,
        quickScan,
      };

      const response = await ApiService.startAnalysis(request);
      onAnalysisStart(response.analysisId, quickScan);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start analysis');
    }
  };

  const validateAddress = (value: string) => {
    if (!value.trim()) {
      setIsValid(null);
      return;
    }
    const trimmed = value.trim().toLowerCase();
    setIsValid(ApiService.isValidBSCAddress(trimmed));
  };

  const handleAddressChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.trim().toLowerCase();
    setAddress(value);
    validateAddress(value);

    // Clear error when user starts typing
    if (error && value.trim()) {
      setError('');
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setAddress(text.trim().toLowerCase());
      validateAddress(text.trim().toLowerCase());
      setError('');
    } catch (err) {
      console.error('Failed to read clipboard:', err);
    }
  };

  const handleClear = () => {
    setAddress('');
    setError('');
    setIsValid(null);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && isValid && !isLoading) {
      handleSubmit(e as any);
    }
    if (e.key === 'Escape') {
      handleClear();
    }
  };

  const exampleAddresses = [
    '0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763',
    '0xe9e7cea3dedca5984780bafc599bd69add087d56',
    '0x55d398326f99059ff775485246999027b3197955',
  ];

  const fillExampleAddress = (exampleAddress: string) => {
    setAddress(exampleAddress.toLowerCase());
    validateAddress(exampleAddress.toLowerCase());
    setError('');
  };

  const getBorderColor = () => {
    if (error) return 'border-red-500';
    if (isFocused) return 'border-[#00ff88]';
    if (isValid === true) return 'border-[#00ff88]';
    if (isValid === false) return 'border-red-500';
    return 'border-[#21262d]';
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="bg-[#161b22] rounded-lg border border-[#21262d] p-6 sm:p-8">
        <div className="text-center mb-8">
          <h2 className="text-2xl sm:text-3xl font-bold text-[#e6edf3] mb-2">
            BSC Security Scanner
          </h2>
          <p className="text-[#8b949e]">
            Analyze smart contracts on Binance Smart Chain for security vulnerabilities
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Terminal-style input */}
          <div>
            <label
              htmlFor="address"
              className="block text-sm font-medium text-[#e6edf3] mb-3"
            >
              Contract Address
            </label>
            <div className="relative">
              {/* Terminal prefix */}
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-[#00ff88] font-mono text-lg pointer-events-none">
                &gt;
              </span>

              <input
                ref={inputRef}
                type="text"
                id="address"
                value={address}
                onChange={handleAddressChange}
                onFocus={() => setIsFocused(true)}
                onBlur={() => setIsFocused(false)}
                onKeyDown={handleKeyDown}
                placeholder="Paste BSC contract address (0x...)"
                className={`w-full h-12 sm:h-14 pl-10 pr-24 bg-[#0d1117] text-[#e6edf3] font-mono text-sm sm:text-base border-2 ${getBorderColor()} rounded-lg focus:outline-none focus:ring-2 focus:ring-[#00ff88]/20 transition-all placeholder:text-[#6e7681]`}
                disabled={isLoading}
                aria-label="BSC contract address input"
                aria-invalid={!!error}
                aria-describedby={error ? "address-error" : undefined}
              />

              {/* Action icons */}
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                {showPasteButton && !address && (
                  <button
                    type="button"
                    onClick={handlePaste}
                    className="p-2 text-[#8b949e] hover:text-[#00ff88] transition-colors"
                    aria-label="Paste from clipboard"
                    title="Paste from clipboard"
                  >
                    <Clipboard className="h-4 w-4" />
                  </button>
                )}

                {address && (
                  <button
                    type="button"
                    onClick={handleClear}
                    className="p-2 text-[#8b949e] hover:text-red-500 transition-colors"
                    aria-label="Clear input"
                    title="Clear (Esc)"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}

                {/* Validation indicator */}
                {isValid === true && (
                  <div className="p-2 text-[#00ff88]" aria-label="Valid address">
                    <Check className="h-4 w-4" />
                  </div>
                )}
                {isValid === false && address && (
                  <div className="p-2 text-red-500" aria-label="Invalid address">
                    <X className="h-4 w-4" />
                  </div>
                )}
              </div>
            </div>

            {error && (
              <div id="address-error" className="mt-3 flex items-start gap-2 text-red-400 text-sm" role="alert">
                <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <span>
                  {error}
                  <span className="block mt-1 text-xs text-[#8b949e]">
                    BSC addresses start with 0x and contain 40 hex characters (0-9, a-f)
                  </span>
                </span>
              </div>
            )}
          </div>

          {/* Quick scan toggle */}
          <div className="flex items-center gap-3 p-4 bg-[#0d1117] border border-[#21262d] rounded-lg">
            <input
              type="checkbox"
              id="quickScan"
              checked={quickScan}
              onChange={(e) => setQuickScan(e.target.checked)}
              className="h-4 w-4 accent-[#00ff88] border-[#21262d] rounded focus:ring-2 focus:ring-[#00ff88]/20"
              disabled={isLoading}
            />
            <label htmlFor="quickScan" className="text-sm text-[#e6edf3] flex items-center cursor-pointer flex-1">
              <Zap className="h-4 w-4 mr-2 text-[#ffd700]" />
              Quick scan (faster, basic analysis only)
            </label>
          </div>

          {/* Analysis time info */}
          <div className="bg-[#0d1117] border border-[#21262d] rounded-lg p-4">
            <div className="flex items-start gap-3">
              <Clock className="h-5 w-5 text-[#00ff88] mt-0.5 flex-shrink-0" />
              <div>
                <h4 className="font-medium text-[#e6edf3] mb-1">Estimated Time</h4>
                <p className="text-sm text-[#8b949e]">
                  {quickScan
                    ? '⚡ Quick scan: 30-60 seconds'
                    : '🔍 Full scan: 60-120 seconds'
                  }
                </p>
              </div>
            </div>
          </div>

          {/* Submit button */}
          <button
            type="submit"
            disabled={isLoading || !isValid}
            className={`w-full h-12 sm:h-14 px-6 rounded-lg font-medium transition-all focus:outline-none focus:ring-2 focus:ring-[#00ff88]/40 ${
              isLoading || !isValid
                ? 'bg-[#21262d] text-[#6e7681] cursor-not-allowed'
                : 'bg-[#00ff88] text-[#0d1117] hover:bg-[#00ff88]/90 active:scale-[0.98]'
            }`}
            aria-label={quickScan ? 'Start quick analysis' : 'Start full analysis'}
          >
            {isLoading ? (
              <div className="flex items-center justify-center gap-3">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-[#6e7681]"></div>
                Analyzing Contract...
              </div>
            ) : (
              <div className="flex items-center justify-center gap-2">
                <Search className="h-5 w-5" />
                {quickScan ? 'Start Quick Analysis' : 'Start Full Analysis'}
              </div>
            )}
          </button>

          {/* Keyboard hint */}
          <p className="text-xs text-center text-[#6e7681]">
            Press <kbd className="px-1.5 py-0.5 bg-[#21262d] rounded border border-[#30363d] font-mono">Enter</kbd> to submit, <kbd className="px-1.5 py-0.5 bg-[#21262d] rounded border border-[#30363d] font-mono">Esc</kbd> to clear
          </p>
        </form>

        {/* Example addresses */}
        <div className="mt-6 pt-6 border-t border-[#21262d]">
          <h4 className="text-sm font-medium text-[#e6edf3] mb-3">Try these examples:</h4>
          <div className="space-y-2">
            {exampleAddresses.map((exampleAddr, index) => (
              <button
                key={index}
                onClick={() => fillExampleAddress(exampleAddr)}
                className="block w-full text-left px-4 py-2.5 text-sm bg-[#0d1117] hover:bg-[#21262d] rounded border border-[#21262d] hover:border-[#30363d] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                disabled={isLoading}
              >
                <code className="text-[#00ff88] font-mono text-xs sm:text-sm">{exampleAddr}</code>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ContractAnalysisForm;