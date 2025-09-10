import React, { useState } from 'react';
import { Search, AlertCircle, Clock, Zap } from 'lucide-react';
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // Validate address
    if (!address.trim()) {
      setError('Please enter a contract address');
      return;
    }

    if (!ApiService.isValidBSCAddress(address.trim())) {
      setError('Invalid BSC address format. Address should be 40 characters starting with 0x');
      return;
    }

    try {
      const request: AnalysisRequest = {
        address: address.trim(),
        quickScan,
      };

      const response = await ApiService.startAnalysis(request);
      onAnalysisStart(response.analysisId, quickScan);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start analysis');
    }
  };

  const handleAddressChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setAddress(value);
    
    // Clear error when user starts typing
    if (error && value.trim()) {
      setError('');
    }
  };

  const exampleAddresses = [
    '0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763',
    '0xe9e7cea3dedca5984780bafc599bd69add087d56',
    '0x55d398326f99059ff775485246999027b3197955',
  ];

  const fillExampleAddress = (exampleAddress: string) => {
    setAddress(exampleAddress);
    setError('');
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="bg-white rounded-lg shadow-lg border border-gray-200 p-6">
        <div className="text-center mb-6">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">
            BSC Security Scanner
          </h2>
          <p className="text-gray-600">
            Analyze smart contracts on Binance Smart Chain for security vulnerabilities
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label 
              htmlFor="address" 
              className="block text-sm font-medium text-gray-700 mb-2"
            >
              Contract Address
            </label>
            <div className="relative">
              <input
                type="text"
                id="address"
                value={address}
                onChange={handleAddressChange}
                placeholder="0x..."
                className={`w-full px-4 py-3 pr-12 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent ${
                  error ? 'border-red-500' : 'border-gray-300'
                }`}
                disabled={isLoading}
              />
              <Search className="absolute right-3 top-3 h-5 w-5 text-gray-400" />
            </div>
            {error && (
              <div className="mt-2 flex items-center text-red-600 text-sm">
                <AlertCircle className="h-4 w-4 mr-1" />
                {error}
              </div>
            )}
          </div>

          <div className="flex items-center space-x-3">
            <input
              type="checkbox"
              id="quickScan"
              checked={quickScan}
              onChange={(e) => setQuickScan(e.target.checked)}
              className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              disabled={isLoading}
            />
            <label htmlFor="quickScan" className="text-sm text-gray-700 flex items-center">
              <Zap className="h-4 w-4 mr-1 text-yellow-500" />
              Quick scan (faster, basic analysis only)
            </label>
          </div>

          <div className="bg-gray-50 rounded-lg p-4">
            <div className="flex items-start space-x-3">
              <Clock className="h-5 w-5 text-blue-500 mt-0.5" />
              <div>
                <h4 className="font-medium text-gray-900 mb-1">Analysis Time</h4>
                <p className="text-sm text-gray-600">
                  {quickScan 
                    ? 'Quick scan: 30-60 seconds (basic security checks)'
                    : 'Full scan: 2-3 minutes (comprehensive security analysis)'
                  }
                </p>
              </div>
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading || !address.trim()}
            className={`w-full py-3 px-4 rounded-lg font-medium transition-colors ${
              isLoading || !address.trim()
                ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
                : 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-4 focus:ring-blue-300'
            }`}
          >
            {isLoading ? (
              <div className="flex items-center justify-center">
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Analyzing Contract...
              </div>
            ) : (
              <div className="flex items-center justify-center">
                <Search className="h-5 w-5 mr-2" />
                {quickScan ? 'Start Quick Analysis' : 'Start Full Analysis'}
              </div>
            )}
          </button>
        </form>

        {/* Example addresses */}
        <div className="mt-6 border-t border-gray-200 pt-4">
          <h4 className="text-sm font-medium text-gray-700 mb-2">Try these examples:</h4>
          <div className="space-y-2">
            {exampleAddresses.map((exampleAddr, index) => (
              <button
                key={index}
                onClick={() => fillExampleAddress(exampleAddr)}
                className="block w-full text-left px-3 py-2 text-sm bg-gray-50 hover:bg-gray-100 rounded border transition-colors"
                disabled={isLoading}
              >
                <code className="text-blue-600">{exampleAddr}</code>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ContractAnalysisForm;