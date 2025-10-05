import { useState, useEffect } from 'react';
import ContractAnalysisForm from './components/ContractAnalysisForm';
import LoadingState from './components/LoadingState';
import ScanResults from './components/ScanResults';
import { ApiService } from './services/api';
import { ScanResult } from './types/api';
import { Shield, Github, ExternalLink, Trash2 } from 'lucide-react';
import './App.css';

type AppState = 'form' | 'loading' | 'results' | 'error';

function App() {
  const [state, setState] = useState<AppState>('form');
  const [analysisId, setAnalysisId] = useState<string>('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string>('');
  const [elapsedTime, setElapsedTime] = useState(0);
  const [isQuickScan, setIsQuickScan] = useState(false);
  const [currentAddress, setCurrentAddress] = useState('');
  const [isClearingCache, setIsClearingCache] = useState(false);
  const [cacheMessage, setCacheMessage] = useState('');

  // Timer for elapsed time during analysis
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (state === 'loading') {
      interval = setInterval(() => {
        setElapsedTime(prev => prev + 1);
      }, 1000);
    } else {
      setElapsedTime(0);
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [state]);

  const handleAnalysisStart = async (newAnalysisId: string, quickScan: boolean) => {
    setAnalysisId(newAnalysisId);
    setIsQuickScan(quickScan);
    setState('loading');
    setError('');

    try {
      // Poll for results
      const finalStatus = await ApiService.pollAnalysisStatus(newAnalysisId);
      
      if (finalStatus.status === 'completed' && finalStatus.result) {
        setScanResult(finalStatus.result);
        setCurrentAddress(finalStatus.result.address);
        setState('results');
      } else {
        throw new Error(finalStatus.error || 'Analysis failed');
      }
    } catch (err) {
      console.error('Analysis failed:', err);
      setError(err instanceof Error ? err.message : 'Analysis failed');
      setState('error');
    }
  };

  const handleNewScan = () => {
    setState('form');
    setAnalysisId('');
    setScanResult(null);
    setError('');
    setElapsedTime(0);
    setCurrentAddress('');
  };

  const handleCancel = () => {
    setState('form');
    setAnalysisId('');
    setError('');
    setElapsedTime(0);
  };

  const handleClearCache = async () => {
    setIsClearingCache(true);
    setCacheMessage('');

    try {
      const result = await ApiService.clearCache();
      setCacheMessage('✓ Cache cleared successfully');
      console.log('Cache cleared:', result);

      // Clear message after 3 seconds
      setTimeout(() => {
        setCacheMessage('');
      }, 3000);
    } catch (err) {
      console.error('Failed to clear cache:', err);
      setCacheMessage('✗ Failed to clear cache');

      setTimeout(() => {
        setCacheMessage('');
      }, 3000);
    } finally {
      setIsClearingCache(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0d1117]">
      {/* Header */}
      <header className="bg-[#161b22] border-b border-[#21262d]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-[#00ff88] mr-3" />
              <div>
                <h1 className="text-xl font-bold text-[#e6edf3]">BSC Security Scanner</h1>
                <p className="text-sm text-[#8b949e]">Smart Contract Security Analysis</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              {cacheMessage && (
                <span className={`text-sm ${cacheMessage.includes('✓') ? 'text-green-400' : 'text-red-400'}`}>
                  {cacheMessage}
                </span>
              )}
              <button
                onClick={handleClearCache}
                disabled={isClearingCache}
                className="flex items-center gap-2 px-3 py-1.5 text-sm bg-[#21262d] text-[#e6edf3] rounded-lg hover:bg-[#30363d] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                title="Clear all caches"
              >
                <Trash2 className="h-4 w-4" />
                {isClearingCache ? 'Clearing...' : 'Clear Cache'}
              </button>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[#8b949e] hover:text-[#e6edf3] transition-colors"
                aria-label="GitHub"
              >
                <Github className="h-5 w-5" />
              </a>
              <a
                href="https://bscscan.com"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center text-sm text-[#8b949e] hover:text-[#e6edf3] transition-colors"
              >
                BSCScan <ExternalLink className="h-3 w-3 ml-1" />
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:py-12 px-4 sm:px-6 lg:px-8">
        {state === 'form' && (
          <ContractAnalysisForm
            onAnalysisStart={handleAnalysisStart}
            isLoading={false}
          />
        )}

        {state === 'loading' && (
          <LoadingState
            analysisId={analysisId}
            address={currentAddress || 'Loading...'}
            isQuickScan={isQuickScan}
            elapsedTime={elapsedTime}
            onCancel={handleCancel}
          />
        )}

        {state === 'results' && scanResult && (
          <ScanResults
            result={scanResult}
            onNewScan={handleNewScan}
          />
        )}

        {state === 'error' && (
          <div className="w-full max-w-2xl mx-auto">
            <div className="bg-[#161b22] border border-red-500/50 rounded-lg p-6">
              <div className="flex items-center mb-4">
                <Shield className="h-6 w-6 text-red-500 mr-3" />
                <h2 className="text-lg font-semibold text-[#e6edf3]">Analysis Failed</h2>
              </div>
              <p className="text-red-400 mb-6">{error}</p>
              <div className="flex gap-3">
                <button
                  onClick={handleNewScan}
                  className="px-6 py-2.5 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors font-medium"
                >
                  Try Again
                </button>
                <button
                  onClick={handleCancel}
                  className="px-6 py-2.5 bg-[#21262d] text-[#e6edf3] rounded-lg hover:bg-[#30363d] transition-colors font-medium"
                >
                  Go Back
                </button>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="bg-[#161b22] border-t border-[#21262d] mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="text-sm text-[#8b949e]">
              © 2025 BSC Security Scanner - Built for security analysis and educational purposes
            </div>
            <div className="flex items-center gap-4 sm:gap-6 text-sm text-[#8b949e]">
              <span>Binance Smart Chain</span>
              <span className="hidden sm:inline">•</span>
              <span>Security Analysis</span>
              <span className="hidden sm:inline">•</span>
              <span>Portfolio Project</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
