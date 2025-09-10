import React, { useState, useEffect } from 'react';
import ContractAnalysisForm from './components/ContractAnalysisForm';
import LoadingState from './components/LoadingState';
import ScanResults from './components/ScanResults';
import { ApiService } from './services/api';
import { ScanResult, AnalysisStatus } from './types/api';
import { Shield, Github, ExternalLink } from 'lucide-react';
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

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">BSC Security Scanner</h1>
                <p className="text-sm text-gray-500">Smart Contract Security Analysis</p>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-gray-500 hover:text-gray-700"
              >
                <Github className="h-5 w-5" />
              </a>
              <a
                href="https://bscscan.com"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center text-sm text-gray-500 hover:text-gray-700"
              >
                BSCScan <ExternalLink className="h-3 w-3 ml-1" />
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        <div className="px-4 py-6 sm:px-0">
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
              <div className="bg-red-50 border border-red-200 rounded-lg p-6">
                <div className="flex items-center mb-4">
                  <Shield className="h-6 w-6 text-red-600 mr-3" />
                  <h2 className="text-lg font-semibold text-red-900">Analysis Failed</h2>
                </div>
                <p className="text-red-700 mb-4">{error}</p>
                <div className="flex space-x-3">
                  <button
                    onClick={handleNewScan}
                    className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
                  >
                    Try Again
                  </button>
                  <button
                    onClick={handleCancel}
                    className="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition-colors"
                  >
                    Go Back
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div className="text-sm text-gray-500">
              © 2024 BSC Security Scanner - Built for security analysis and educational purposes
            </div>
            <div className="flex items-center space-x-6 text-sm text-gray-500">
              <span>Binance Smart Chain</span>
              <span>•</span>
              <span>Security Analysis</span>
              <span>•</span>
              <span>Portfolio Project</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
