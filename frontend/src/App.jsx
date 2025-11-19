import React, { useState, useEffect } from 'react';
import { Search, Shield, AlertTriangle, CheckCircle, XCircle, Download, Layers, Activity, TrendingUp, RefreshCw, ChevronDown, ChevronRight, Database, Zap, Lock, Server, FileWarning, Clock, BarChart3, PieChart, Settings, AlertCircleIcon } from 'lucide-react';

// API Configuration
const API_BASE_URL = ''; // Empty for proxy

// Real API calls to FastAPI backend
const api = {
  scanImage: async (imageName) => {
    const response = await fetch(`${API_BASE_URL}/api/scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ image_name: imageName })
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Scan failed');
    }
    
    return response.json();
  },
  
  getHistory: async () => {
    const response = await fetch(`${API_BASE_URL}/api/history?limit=50`);
    if (!response.ok) throw new Error('Failed to fetch history');
    const data = await response.json();
    return data.scans;
  },
  
  getAnalytics: async () => {
    const response = await fetch(`${API_BASE_URL}/api/analytics`);
    if (!response.ok) throw new Error('Failed to fetch analytics');
    return response.json();
  },
  
  startBatchScan: async (images, workers = 3, timeout = 300) => {
    const response = await fetch(`${API_BASE_URL}/api/batch-scan`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        images,
        parallel_workers: workers,
        timeout
      })
    });
    
    if (!response.ok) throw new Error('Failed to start batch scan');
    return response.json();
  },
  
  getBatchProgress: async (jobId) => {
    const response = await fetch(`${API_BASE_URL}/api/batch-scan/${jobId}`);
    if (!response.ok) throw new Error('Failed to fetch batch progress');
    return response.json();
  },
  
  getModelInfo: async () => {
    const response = await fetch(`${API_BASE_URL}/api/model-info`);
    if (!response.ok) throw new Error('Failed to fetch model info');
    return response.json();
  },
  
  trainModel: async () => {
    const response = await fetch(`${API_BASE_URL}/api/train`, {
      method: 'POST',
    });
    if (!response.ok) throw new Error('Failed to start training');
    return response.json();
  }
};

// Progress Bar Component
function ProgressBar({ progress, label, color = 'cyan' }) {
  const colorClasses = {
    cyan: 'bg-cyan-500',
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    yellow: 'bg-yellow-500',
    red: 'bg-red-500'
  };

  return (
    <div className="w-full">
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm text-slate-300">{label}</span>
        <span className="text-sm font-semibold text-slate-200">{progress}%</span>
      </div>
      <div className="w-full bg-slate-700 rounded-full h-2.5 overflow-hidden">
        <div
          className={`h-2.5 rounded-full transition-all duration-300 ${colorClasses[color]}`}
          style={{ width: `${progress}%` }}
        >
          <div className="h-full w-full bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer"></div>
        </div>
      </div>
    </div>
  );
}

// Error Alert Component
function ErrorAlert({ message, onClose }) {
  return (
    <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-start space-x-3 animate-slideIn">
      <AlertCircleIcon className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
      <div className="flex-1">
        <h4 className="font-semibold text-red-400 mb-1">Scan Failed</h4>
        <p className="text-sm text-red-300">{message}</p>
      </div>
      <button
        onClick={onClose}
        className="text-red-400 hover:text-red-300 transition-colors"
      >
        <XCircle className="w-5 h-5" />
      </button>
    </div>
  );
}

// Scanning Progress Component
function ScanningProgress({ imageName, progress }) {
  const stages = [
    { label: 'Pulling image', progress: 20 },
    { label: 'Running Trivy scan', progress: 40 },
    { label: 'Running Syft analysis', progress: 60 },
    { label: 'Behavioral analysis', progress: 80 },
    { label: 'ML prediction', progress: 95 },
    { label: 'Generating report', progress: 100 }
  ];

  const currentStage = stages.find(s => progress < s.progress) || stages[stages.length - 1];
  const stageIndex = stages.indexOf(currentStage);

  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="relative">
            <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Scanning in Progress</h3>
            <p className="text-sm text-slate-400">{imageName}</p>
          </div>
        </div>
        <div className="text-right">
          <div className="text-3xl font-bold text-cyan-400">{progress}%</div>
          <div className="text-xs text-slate-400">Complete</div>
        </div>
      </div>

      <ProgressBar progress={progress} label="Overall Progress" color="cyan" />

      <div className="space-y-3">
        <div className="text-sm font-semibold text-slate-300">Scan Stages:</div>
        {stages.map((stage, idx) => (
          <div
            key={idx}
            className={`flex items-center space-x-3 transition-all duration-300 ${
              idx < stageIndex ? 'opacity-50' : idx === stageIndex ? 'opacity-100' : 'opacity-30'
            }`}
          >
            {idx < stageIndex ? (
              <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
            ) : idx === stageIndex ? (
              <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin flex-shrink-0" />
            ) : (
              <div className="w-4 h-4 border-2 border-slate-600 rounded-full flex-shrink-0" />
            )}
            <span className={`text-sm ${idx === stageIndex ? 'text-cyan-400 font-semibold' : 'text-slate-400'}`}>
              {stage.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Main App Component
export default function DockerSecurityScanner() {
  const [activeTab, setActiveTab] = useState('scan');
  const [imageName, setImageName] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);

  useEffect(() => {
    api.getHistory().then(setHistory).catch(console.error);
    api.getAnalytics().then(setAnalytics).catch(console.error);
  }, []);

  const handleScan = async () => {
    if (!imageName.trim()) {
      setError('Please enter an image name');
      return;
    }

    setScanning(true);
    setScanResult(null);
    setError(null);
    setScanProgress(0);

    // Simulate progress (since backend doesn't send progress updates)
    const progressInterval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 95) {
          clearInterval(progressInterval);
          return 95;
        }
        return prev + 5;
      });
    }, 1000);

    try {
      const result = await api.scanImage(imageName);
      setScanProgress(100);
      setScanResult(result);
      
      // Refresh history
      const newHistory = await api.getHistory();
      setHistory(newHistory);
      
      // Clear progress after a delay
      setTimeout(() => {
        clearInterval(progressInterval);
      }, 500);
    } catch (err) {
      clearInterval(progressInterval);
      setScanProgress(0);
      
      // Enhanced error messages
      let errorMessage = err.message;
      if (errorMessage.includes('Image not found') || errorMessage.includes('404')) {
        errorMessage = `Image "${imageName}" not found. Please check the image name and tag.`;
      } else if (errorMessage.includes('pull access denied')) {
        errorMessage = `Access denied for "${imageName}". The image may be private or doesn't exist.`;
      } else if (errorMessage.includes('timeout')) {
        errorMessage = `Scan timed out for "${imageName}". The image may be too large or the registry is slow.`;
      }
      
      setError(errorMessage);
      console.error('Scan failed:', err);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-slate-700 bg-slate-900/50 backdrop-blur">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="w-8 h-8 text-cyan-400" />
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
                  Docker Security Scanner
                </h1>
                <p className="text-sm text-slate-400">AI-Powered Image Threat Detection</p>
              </div>
            </div>
            <div className="flex items-center space-x-6 text-sm">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-green-400" />
                <span className="text-slate-300">Status: <span className="text-green-400 font-semibold">Online</span></span>
              </div>
              <div className="text-slate-400">
                Model AUC: <span className="text-cyan-400 font-semibold">0.9687</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="border-b border-slate-700 bg-slate-900/30">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex space-x-8">
            {[
              { id: 'scan', label: 'Scan', icon: Search },
              { id: 'history', label: 'Scan History', icon: Clock },
              { id: 'analytics', label: 'Analytics', icon: BarChart3 },
              { id: 'batch', label: 'Batch Scanner', icon: Database },
              { id: 'training', label: 'Model Training', icon: Zap }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 py-4 border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-cyan-400 text-cyan-400'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <tab.icon className="w-4 h-4" />
                <span className="font-medium">{tab.label}</span>
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8">
        {activeTab === 'scan' && (
          <ScanTab
            imageName={imageName}
            setImageName={setImageName}
            scanning={scanning}
            handleScan={handleScan}
            scanResult={scanResult}
            error={error}
            setError={setError}
            scanProgress={scanProgress}
          />
        )}
        {activeTab === 'history' && <HistoryTab history={history} />}
        {activeTab === 'analytics' && <AnalyticsTab analytics={analytics} />}
        {activeTab === 'batch' && <BatchTab />}
        {activeTab === 'training' && <TrainingTab />}
      </main>
    </div>
  );
}

// Scan Tab Component
function ScanTab({ imageName, setImageName, scanning, handleScan, scanResult, error, setError, scanProgress }) {
  return (
    <div className="space-y-8">
      {/* Hero Section */}
      <div className="bg-gradient-to-r from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-xl p-8">
        <div className="max-w-2xl mx-auto text-center space-y-6">
          <h2 className="text-3xl font-bold">Scan Docker Image for Security Threats</h2>
          <p className="text-slate-300">
            Powered by XGBoost ML model with 24+ behavioral features and layer-by-layer analysis
          </p>
          
          <div className="flex space-x-3">
            <input
              type="text"
              value={imageName}
              onChange={(e) => setImageName(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleScan()}
              placeholder="Enter image name (e.g., nginx:latest, ubuntu:14.04)"
              className="flex-1 px-4 py-3 bg-slate-800 border border-slate-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-400 text-white placeholder-slate-400"
              disabled={scanning}
            />
            <button
              onClick={handleScan}
              disabled={scanning || !imageName.trim()}
              className="px-8 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 disabled:from-slate-600 disabled:to-slate-700 disabled:cursor-not-allowed rounded-lg font-semibold transition-all flex items-center space-x-2"
            >
              {scanning ? (
                <>
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <Search className="w-5 h-5" />
                  <span>Scan Image</span>
                </>
              )}
            </button>
          </div>

          <div className="flex justify-center space-x-6 text-sm text-slate-400">
            <span>Quick tests:</span>
            {['nginx:alpine', 'ubuntu:14.04', 'python:2.7'].map(img => (
              <button
                key={img}
                onClick={() => setImageName(img)}
                className="text-cyan-400 hover:text-cyan-300 underline disabled:opacity-50"
                disabled={scanning}
              >
                {img}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <ErrorAlert message={error} onClose={() => setError(null)} />
      )}

      {/* Scanning Progress */}
      {scanning && (
        <ScanningProgress imageName={imageName} progress={scanProgress} />
      )}

      {/* Scan Result */}
      {scanResult && !scanning && <ScanResult result={scanResult} />}
    </div>
  );
}

// Keep your existing ScanResult and other components below...
// (I'll continue in the next message with the rest of the components)
// Scan Result Component
function ScanResult({ result }) {
  const [expandedLayer, setExpandedLayer] = useState(null);

  const getRiskColor = (score) => {
    if (score >= 0.7) return 'text-red-400 border-red-500/30 bg-red-500/10';
    if (score >= 0.5) return 'text-orange-400 border-orange-500/30 bg-orange-500/10';
    if (score >= 0.3) return 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10';
    return 'text-green-400 border-green-500/30 bg-green-500/10';
  };

  const getRiskIcon = (isRisky) => {
    return isRisky ? XCircle : CheckCircle;
  };

  const RiskIcon = getRiskIcon(result.is_risky);

  return (
    <div className="space-y-6">
      {/* Verdict Card */}
      <div className={`border-2 rounded-xl p-6 ${getRiskColor(result.risk_score)}`}>
        <div className="flex items-start justify-between">
          <div className="flex items-start space-x-4">
            <RiskIcon className="w-12 h-12 mt-1" />
            <div>
              <div className="flex items-center space-x-3">
                <h3 className="text-3xl font-bold">{result.verdict}</h3>
                <span className="px-3 py-1 bg-slate-900/50 rounded-full text-sm font-semibold">
                  {result.severity}
                </span>
              </div>
              <p className="text-xl mt-1 text-slate-300">{result.image}</p>
              <div className="flex items-center space-x-6 mt-4 text-sm">
                <div>
                  <span className="text-slate-400">Risk Score:</span>
                  <span className="ml-2 text-2xl font-bold">{(result.risk_score * 100).toFixed(1)}%</span>
                </div>
                <div>
                  <span className="text-slate-400">Confidence:</span>
                  <span className="ml-2 font-semibold">{result.confidence}</span>
                </div>
                <div>
                  <span className="text-slate-400">Status:</span>
                  <span className="ml-2 font-semibold capitalize">{result.scan_status}</span>
                </div>
              </div>
            </div>
          </div>
          <div className="flex space-x-2">
            <button className="p-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors">
              <Download className="w-5 h-5" />
            </button>
            <button className="p-2 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors">
              <RefreshCw className="w-5 h-5" />
            </button>
          </div>
        </div>
      </div>

      {/* Top Risk Factors */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h4 className="text-xl font-bold mb-4 flex items-center">
          <AlertTriangle className="w-5 h-5 mr-2 text-yellow-400" />
          Top Security Concerns
        </h4>
        <div className="space-y-3">
          {result.top_risk_factors.map((factor, idx) => (
            <div key={idx} className="flex items-center justify-between">
              <div className="flex-1">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-300 font-medium">{factor.feature.replace(/_/g, ' ')}</span>
                  <span className="text-sm text-slate-400">Value: {factor.value}</span>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2">
                  <div
                    className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full"
                    style={{ width: `${factor.importance * 100}%` }}
                  />
                </div>
              </div>
              <span className="ml-4 text-sm text-slate-400 w-16 text-right">
                {(factor.importance * 100).toFixed(1)}%
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Feature Dashboard */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        {Object.entries({
          'Cryptominer Binary': result.all_features.cryptominer_binary,
          'Known CVEs': result.all_features.known_cves,
          'Runs as Root': result.all_features.runs_as_root,
          'Image Age (days)': result.all_features.image_age_days,
          'Hardcoded Secrets': result.all_features.hardcoded_secrets,
          'SSH Backdoor': result.all_features.ssh_backdoor
        }).map(([label, value]) => {
          const isRisky = label === 'Known CVEs' ? value >= 5 : value > 0;
          const StatusIcon = isRisky ? XCircle : CheckCircle;
          return (
            <div key={label} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <p className="text-sm text-slate-400 mb-1">{label}</p>
                  <p className="text-2xl font-bold">{value}</p>
                </div>
                <StatusIcon className={`w-5 h-5 ${isRisky ? 'text-red-400' : 'text-green-400'}`} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Behavioral Analysis */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h4 className="text-xl font-bold mb-4 flex items-center">
          <Layers className="w-5 h-5 mr-2 text-purple-400" />
          Behavioral Analysis (Layer-by-Layer)
        </h4>
        
        <div className="mb-6 grid grid-cols-4 gap-4">
          <div className="text-center">
            <p className="text-sm text-slate-400">Total Layers</p>
            <p className="text-2xl font-bold">{result.layer_analyses.length}</p>
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-400">High-Risk Layers</p>
            <p className="text-2xl font-bold text-red-400">
              {result.layer_analyses.filter(l => l.risk_score >= 0.5).length}
            </p>
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-400">Max Risk</p>
            <p className="text-2xl font-bold text-orange-400">
              {(Math.max(...result.layer_analyses.map(l => l.risk_score)) * 100).toFixed(0)}%
            </p>
          </div>
          <div className="text-center">
            <p className="text-sm text-slate-400">Avg Risk</p>
            <p className="text-2xl font-bold">
              {(result.layer_analyses.reduce((a, b) => a + b.risk_score, 0) / result.layer_analyses.length * 100).toFixed(0)}%
            </p>
          </div>
        </div>

        <div className="space-y-3">
          {result.layer_analyses.filter(layer => layer.risk_score >= 0.3).map((layer, idx) => (
            <div
              key={idx}
              className={`border rounded-lg overflow-hidden ${getRiskColor(layer.risk_score)}`}
            >
              <button
                onClick={() => setExpandedLayer(expandedLayer === idx ? null : idx)}
                className="w-full p-4 flex items-center justify-between hover:bg-slate-900/30 transition-colors"
              >
                <div className="flex items-center space-x-3">
                  {expandedLayer === idx ? <ChevronDown className="w-5 h-5" /> : <ChevronRight className="w-5 h-5" />}
                  <span className="font-semibold">{layer.layer_id.toUpperCase()}</span>
                  <span className="text-sm opacity-75">Risk: {(layer.risk_score * 100).toFixed(0)}%</span>
                </div>
                <div className="text-sm text-slate-300 max-w-2xl truncate">
                  {layer.command}
                </div>
              </button>
              
              {expandedLayer === idx && (
                <div className="p-4 bg-slate-900/50 border-t border-slate-700">
                  <div className="space-y-3">
                    <div>
                      <p className="text-sm text-slate-400 mb-1">Command:</p>
                      <code className="block bg-slate-950 px-3 py-2 rounded text-sm overflow-x-auto">
                        {layer.command}
                      </code>
                    </div>
                    <div>
                      <p className="text-sm text-slate-400 mb-1">Size:</p>
                      <p className="font-mono">{(layer.size_bytes / (1024 * 1024)).toFixed(2)} MB</p>
                    </div>
                    {layer.findings.length > 0 && (
                      <div>
                        <p className="text-sm text-slate-400 mb-2">Findings:</p>
                        <ul className="space-y-1">
                          {layer.findings.map((finding, i) => (
                            <li key={i} className="flex items-start space-x-2">
                              <span className="text-red-400 mt-1">•</span>
                              <span>{finding}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Remediations */}
      {result.remediations && result.remediations.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <h4 className="text-xl font-bold mb-4 flex items-center">
            <Lock className="w-5 h-5 mr-2 text-cyan-400" />
            Remediation Recommendations
          </h4>
          
          <div className="space-y-4">
            {result.remediations.map((rem, idx) => (
              <div key={idx} className="border border-slate-600 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${
                      rem.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' :
                      rem.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-400' :
                      'bg-yellow-500/20 text-yellow-400'
                    }`}>
                      {rem.severity}
                    </span>
                    <span className="ml-2 text-slate-400 text-sm">Layer: {rem.layer_id}</span>
                  </div>
                </div>
                <h5 className="font-semibold mb-2">{rem.issue}</h5>
                <p className="text-sm text-slate-300 mb-3">{rem.remediation}</p>
                {rem.example_fix && (
                  <div>
                    <p className="text-xs text-slate-400 mb-1">Example fix:</p>
                    <code className="block bg-slate-950 px-3 py-2 rounded text-xs">
                      {rem.example_fix}
                    </code>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// History Tab
function HistoryTab({ history }) {
  return (
    <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
      <h3 className="text-2xl font-bold mb-6">Scan History</h3>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-slate-700">
              <th className="text-left py-3 px-4 text-slate-400 font-medium">Image</th>
              <th className="text-left py-3 px-4 text-slate-400 font-medium">Risk Score</th>
              <th className="text-left py-3 px-4 text-slate-400 font-medium">Verdict</th>
              <th className="text-left py-3 px-4 text-slate-400 font-medium">CVEs</th>
              <th className="text-left py-3 px-4 text-slate-400 font-medium">Scanned</th>
            </tr>
          </thead>
          <tbody>
            {history.map((item, idx) => (
              <tr key={idx} className="border-b border-slate-700/50 hover:bg-slate-700/30">
                <td className="py-3 px-4 font-mono text-sm">{item.image}</td>
                <td className="py-3 px-4">
                  <span className={`font-bold ${
                    item.risk_score >= 0.7 ? 'text-red-400' :
                    item.risk_score >= 0.5 ? 'text-orange-400' :
                    item.risk_score >= 0.3 ? 'text-yellow-400' :
                    'text-green-400'
                  }`}>
                    {(item.risk_score * 100).toFixed(0)}%
                  </span>
                </td>
                <td className="py-3 px-4">
                  <span className={`px-2 py-1 rounded text-xs font-semibold ${
                    item.verdict === 'RISKY' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                  }`}>
                    {item.verdict}
                  </span>
                </td>
                <td className="py-3 px-4">{item.cves}</td>
                <td className="py-3 px-4 text-slate-400 text-sm">{item.scanned}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// Analytics Tab
function AnalyticsTab({ analytics }) {
  if (!analytics) return <div>Loading...</div>;

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-6">
        <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-xl p-6">
          <p className="text-slate-400 mb-2">Total Scans</p>
          <p className="text-4xl font-bold">{analytics.total_scans.toLocaleString()}</p>
        </div>
        <div className="bg-gradient-to-br from-red-500/10 to-orange-500/10 border border-red-500/20 rounded-xl p-6">
          <p className="text-slate-400 mb-2">Risky Images</p>
          <p className="text-4xl font-bold text-red-400">{analytics.risky_count}</p>
          <p className="text-sm text-slate-400 mt-1">
            {((analytics.risky_count / analytics.total_scans) * 100).toFixed(1)}%
          </p>
        </div>
        <div className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/20 rounded-xl p-6">
          <p className="text-slate-400 mb-2">Safe Images</p>
          <p className="text-4xl font-bold text-green-400">{analytics.safe_count}</p>
          <p className="text-sm text-slate-400 mt-1">
            {((analytics.safe_count / analytics.total_scans) * 100).toFixed(1)}%
          </p>
        </div>
      </div>

      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h3 className="text-xl font-bold mb-6">Most Common Threats</h3>
        <div className="space-y-4">
          {analytics.common_threats.map((threat, idx) => (
            <div key={idx}>
              <div className="flex items-center justify-between mb-2">
                <span className="font-medium">{threat.name}</span>
                <span className="text-slate-400">{threat.percentage}%</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all duration-500"
                  style={{ width: `${threat.percentage}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// Batch Tab
function BatchTab() {
  const [batchFile, setBatchFile] = useState(null);
  const [batchProgress, setBatchProgress] = useState(null);
  const [batchResults, setBatchResults] = useState([]);

  const handleBatchScan = async () => {
    setBatchProgress({
      total: 150,
      completed: 0,
      inProgress: 3,
      queued: 147,
      failed: 0
    });

    // Simulate batch scanning
    const interval = setInterval(() => {
      setBatchProgress(prev => {
        if (!prev || prev.completed >= prev.total) {
          clearInterval(interval);
          return prev;
        }
        return {
          ...prev,
          completed: prev.completed + 1,
          queued: prev.queued - 1
        };
      });
    }, 100);

    // Mock results
    setTimeout(() => {
      setBatchResults([
        { image: 'nginx:alpine', verdict: 'SAFE', risk_score: 0.12, duration: '12s' },
        { image: 'ubuntu:14.04', verdict: 'RISKY', risk_score: 0.87, duration: '18s' },
        { image: 'python:3.11-slim', verdict: 'SAFE', risk_score: 0.15, duration: '14s' }
      ]);
    }, 3000);
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h3 className="text-2xl font-bold mb-6 flex items-center">
          <Database className="w-6 h-6 mr-2" />
          Batch Scanner
        </h3>

        <div className="space-y-4">
          <div className="border-2 border-dashed border-slate-600 rounded-lg p-8 text-center hover:border-cyan-500 transition-colors cursor-pointer">
            <input
              type="file"
              accept=".csv"
              onChange={(e) => setBatchFile(e.target.files[0])}
              className="hidden"
              id="batch-upload"
            />
            <label htmlFor="batch-upload" className="cursor-pointer">
              <Database className="w-12 h-12 mx-auto mb-3 text-slate-400" />
              <p className="text-slate-300 mb-1">
                {batchFile ? batchFile.name : 'Drop CSV here or click to upload'}
              </p>
              <p className="text-sm text-slate-400">CSV should contain image names</p>
            </label>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-slate-400 mb-2">Parallel Workers</label>
              <select className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white">
                <option>3</option>
                <option>5</option>
                <option>10</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-slate-400 mb-2">Timeout (seconds)</label>
              <input
                type="number"
                defaultValue="300"
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white"
              />
            </div>
          </div>

          <button
            onClick={handleBatchScan}
            className="w-full px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 rounded-lg font-semibold transition-all"
          >
            Start Batch Scan
          </button>
        </div>
      </div>

      {batchProgress && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <h4 className="text-xl font-bold mb-4">Scanning Progress</h4>
          
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-400">
                {batchProgress.completed} / {batchProgress.total} images
              </span>
              <span className="text-cyan-400 font-semibold">
                {((batchProgress.completed / batchProgress.total) * 100).toFixed(0)}%
              </span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-3">
              <div
                className="bg-gradient-to-r from-cyan-500 to-blue-500 h-3 rounded-full transition-all duration-300"
                style={{ width: `${(batchProgress.completed / batchProgress.total) * 100}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-4 gap-4 mb-6">
            <div className="bg-slate-700/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-green-400">{batchProgress.completed}</p>
              <p className="text-xs text-slate-400">Completed</p>
            </div>
            <div className="bg-slate-700/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-cyan-400">{batchProgress.inProgress}</p>
              <p className="text-xs text-slate-400">In Progress</p>
            </div>
            <div className="bg-slate-700/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-slate-400">{batchProgress.queued}</p>
              <p className="text-xs text-slate-400">Queued</p>
            </div>
            <div className="bg-slate-700/50 rounded-lg p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{batchProgress.failed}</p>
              <p className="text-xs text-slate-400">Failed</p>
            </div>
          </div>

          {batchResults.length > 0 && (
            <div>
              <h5 className="font-semibold mb-3">Recent Results:</h5>
              <div className="space-y-2">
                {batchResults.map((result, idx) => (
                  <div key={idx} className="flex items-center justify-between bg-slate-700/30 rounded-lg p-3">
                    <span className="font-mono text-sm">{result.image}</span>
                    <div className="flex items-center space-x-3">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        result.verdict === 'RISKY' ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'
                      }`}>
                        {result.verdict}
                      </span>
                      <span className="text-sm text-slate-400">{result.duration}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Training Tab
function TrainingTab() {
  const [training, setTraining] = useState(false);
  const [trainingMetrics, setTrainingMetrics] = useState(null);

  const handleTrain = async () => {
    setTraining(true);
    setTimeout(() => {
      setTrainingMetrics({
        epoch: 150,
        train_auc: 0.9687,
        test_auc: 0.9654,
        accuracy: 0.943,
        loss: 0.156
      });
      setTraining(false);
    }, 3000);
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h3 className="text-2xl font-bold mb-6 flex items-center">
          <Zap className="w-6 h-6 mr-2 text-yellow-400" />
          Model Training
        </h3>

        <div className="grid grid-cols-3 gap-6 mb-6">
          <div className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-lg p-4">
            <p className="text-slate-400 text-sm mb-1">Current AUC</p>
            <p className="text-3xl font-bold text-cyan-400">0.9687</p>
            <p className="text-xs text-green-400 mt-1">↑ Best Model</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-4">
            <p className="text-slate-400 text-sm mb-1">Accuracy</p>
            <p className="text-3xl font-bold">94.3%</p>
          </div>
          <div className="bg-slate-700/50 rounded-lg p-4">
            <p className="text-slate-400 text-sm mb-1">Last Trained</p>
            <p className="text-xl font-bold">2 days ago</p>
          </div>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-slate-400 mb-2">Dataset Path</label>
            <input
              type="text"
              defaultValue="data/merged_docker_features.csv"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white"
            />
          </div>

          <button
            onClick={handleTrain}
            disabled={training}
            className="w-full px-6 py-3 bg-gradient-to-r from-yellow-500 to-orange-500 hover:from-yellow-600 hover:to-orange-600 disabled:from-slate-600 disabled:to-slate-700 rounded-lg font-semibold transition-all flex items-center justify-center space-x-2"
          >
            {training ? (
              <>
                <RefreshCw className="w-5 h-5 animate-spin" />
                <span>Training Model...</span>
              </>
            ) : (
              <>
                <Zap className="w-5 h-5" />
                <span>Train New Model</span>
              </>
            )}
          </button>
        </div>
      </div>

      {trainingMetrics && (
        <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
          <h4 className="text-xl font-bold mb-4">Training Results</h4>
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-slate-700/50 rounded-lg p-4">
              <p className="text-sm text-slate-400 mb-1">Train AUC</p>
              <p className="text-2xl font-bold text-cyan-400">{trainingMetrics.train_auc}</p>
            </div>
            <div className="bg-slate-700/50 rounded-lg p-4">
              <p className="text-sm text-slate-400 mb-1">Test AUC</p>
              <p className="text-2xl font-bold text-cyan-400">{trainingMetrics.test_auc}</p>
            </div>
            <div className="bg-slate-700/50 rounded-lg p-4">
              <p className="text-sm text-slate-400 mb-1">Accuracy</p>
              <p className="text-2xl font-bold">{(trainingMetrics.accuracy * 100).toFixed(1)}%</p>
            </div>
            <div className="bg-slate-700/50 rounded-lg p-4">
              <p className="text-sm text-slate-400 mb-1">Loss</p>
              <p className="text-2xl font-bold">{trainingMetrics.loss}</p>
            </div>
          </div>

          <div className="mt-6">
            <h5 className="font-semibold mb-3">Training History</h5>
            <div className="space-y-2">
              {[
                { date: '2025-01-15', auc: 0.9687, status: 'Best' },
                { date: '2025-01-10', auc: 0.9542, status: '' },
                { date: '2025-01-05', auc: 0.9401, status: '' }
              ].map((entry, idx) => (
                <div key={idx} className="flex items-center justify-between bg-slate-700/30 rounded-lg p-3">
                  <span className="text-sm text-slate-400">{entry.date}</span>
                  <div className="flex items-center space-x-3">
                    <span className="font-mono">AUC: {entry.auc}</span>
                    {entry.status && (
                      <span className="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs font-semibold">
                        {entry.status}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
        <h4 className="text-xl font-bold mb-4">Feature Importance</h4>
        <div className="space-y-3">
          {[
            { feature: 'image_age_days', importance: 0.32 },
            { feature: 'known_cves', importance: 0.28 },
            { feature: 'cryptominer_binary', importance: 0.15 },
            { feature: 'outdated_base', importance: 0.12 },
            { feature: 'runs_as_root', importance: 0.08 }
          ].map((item, idx) => (
            <div key={idx}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-sm font-medium">{item.feature}</span>
                <span className="text-sm text-slate-400">{(item.importance * 100).toFixed(1)}%</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className="bg-gradient-to-r from-purple-500 to-pink-500 h-2 rounded-full"
                  style={{ width: `${item.importance * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}