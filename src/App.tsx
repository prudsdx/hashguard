import { useCallback, useState } from 'react';
import { Upload, Shield, AlertTriangle, AlertCircle, CheckCircle, FileText, Hash as HashIcon, Clock, Download } from 'lucide-react';

type Verdict = 'SAFE' | 'DANGEROUS' | 'SUSPICIOUS' | 'UNKNOWN';

interface AnalysisResult {
  verdict: Verdict;
  analysis: string;
  hash: string;
  fileName: string;
  fileSize: string;
  malicious: number;
  suspicious: number;
  harmless: number;
  total: number;
  timestamp: number;
}

const detectVerdict = (text: string): Verdict => {
  const upperText = text.toUpperCase();
  if (upperText.includes('DANGEROUS')) return 'DANGEROUS';
  if (upperText.includes('SUSPICIOUS')) return 'SUSPICIOUS';
  if (upperText.includes('SAFE')) return 'SAFE';
  return 'UNKNOWN';
};

const WEBHOOK_URL = 'https://harness-roving-twelve.ngrok-free.app/webhook/9a214cf4-0d63-4a50-b941-00cc1bf51412';

function App() {
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [activeTab, setActiveTab] = useState<'upload' | 'history'>('upload');

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const calculateSHA256 = async (file: File): Promise<string> => {
    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const sendToWebhook = async (hash: string, fileName: string, fileSize: string) => {
    const response = await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash }),
    });

    if (!response.ok) throw new Error('Failed to analyze');

    const data = await response.json();

    const newResult: AnalysisResult = {
      verdict: detectVerdict(data.analysis || ''),
      analysis: data.analysis || 'No analysis available',
      hash,
      fileName,
      fileSize,
      malicious: Number(data.malicious) || 0,
      suspicious: Number(data.suspicious) || 0,
      harmless: Number(data.harmless) || 0,
      total: Number(data.total) || 0,
      timestamp: Date.now(),
    };

    setResult(newResult);
    setHistory(prev => [newResult, ...prev.slice(0, 9)]);
  };

  const analyzeFile = useCallback(async (file: File) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    try {
      const hash = await calculateSHA256(file);
      await sendToWebhook(hash, file.name, formatFileSize(file.size));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const exportResult = (r: AnalysisResult) => {
    const exportData = {
      fileName: r.fileName,
      fileSize: r.fileSize,
      hash: r.hash,
      verdict: r.verdict,
      analysis: r.analysis,
      virusTotal: {
        malicious: r.malicious,
        suspicious: r.suspicious,
        harmless: r.harmless,
        total: r.total,
      },
      timestamp: new Date(r.timestamp).toISOString(),
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `hashguard-${r.hash.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(true); }, []);
  const handleDragLeave = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(false); }, []);
  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files.length > 0) analyzeFile(e.dataTransfer.files[0]);
  }, [analyzeFile]);
  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) analyzeFile(e.target.files[0]);
  }, [analyzeFile]);

  const getVerdictConfig = (verdict: Verdict) => {
    switch (verdict) {
      case 'SAFE': return { color: 'text-emerald-400', bgColor: 'bg-emerald-500/10 border-emerald-500/30', icon: CheckCircle, label: 'SAFE' };
      case 'DANGEROUS': return { color: 'text-red-400', bgColor: 'bg-red-500/10 border-red-500/30', icon: AlertCircle, label: 'DANGEROUS' };
      case 'SUSPICIOUS': return { color: 'text-amber-400', bgColor: 'bg-amber-500/10 border-amber-500/30', icon: AlertTriangle, label: 'SUSPICIOUS' };
      default: return { color: 'text-zinc-400', bgColor: 'bg-zinc-500/10 border-zinc-500/30', icon: AlertCircle, label: 'UNKNOWN' };
    }
  };

  const verdictDotColor = (verdict: Verdict) => {
    switch (verdict) {
      case 'SAFE': return 'bg-emerald-400';
      case 'DANGEROUS': return 'bg-red-400';
      case 'SUSPICIOUS': return 'bg-amber-400';
      default: return 'bg-zinc-400';
    }
  };

  return (
    <div className="min-h-screen bg-black flex flex-col items-center p-4 sm:p-8 pt-10">
      <div className="w-full max-w-2xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-3 mb-3">
            <Shield className="w-10 h-10 text-emerald-400" />
            <h1 className="text-4xl sm:text-5xl font-bold text-white tracking-tight">
              Hash<span className="text-emerald-400">Guard</span>
            </h1>
          </div>
          <p className="text-zinc-600 text-lg">Advanced file hash analyzer for cybersecurity threat detection</p>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-zinc-950 border border-zinc-800 rounded-xl p-1">
          {(['upload', 'history'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`flex-1 py-2 rounded-lg text-sm font-medium transition-all ${
                activeTab === tab ? 'bg-zinc-800 text-white' : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {tab === 'upload' ? '📁 Upload File' : `🕓 History (${history.length})`}
            </button>
          ))}
        </div>

        {/* Upload Tab */}
        {activeTab === 'upload' && (
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`relative border-2 border-dashed rounded-2xl p-8 sm:p-12 transition-all duration-300 cursor-pointer
              ${isDragging ? 'border-emerald-400 bg-emerald-500/10 scale-[1.02]' : 'border-zinc-800 bg-zinc-950/50 hover:border-zinc-700'}`}
          >
            <input type="file" onChange={handleFileInput} className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" />
            <div className="flex flex-col items-center gap-4">
              <div className={`p-4 rounded-full transition-colors duration-300 ${isDragging ? 'bg-emerald-500/20' : 'bg-zinc-900'}`}>
                <Upload className={`w-8 h-8 ${isDragging ? 'text-emerald-400' : 'text-zinc-500'}`} />
              </div>
              <div className="text-center">
                <p className="text-white font-medium text-lg mb-1">{isDragging ? 'Drop your file here' : 'Drag & drop your file'}</p>
                <p className="text-zinc-600 text-sm">or click to browse</p>
              </div>
              <p className="text-zinc-700 text-xs mt-2">Supports all file types</p>
            </div>
          </div>
        )}

        {/* History Tab */}
        {activeTab === 'history' && (
          <div className="bg-zinc-950 border border-zinc-800 rounded-2xl overflow-hidden">
            {history.length === 0 ? (
              <div className="p-8 text-center text-zinc-600">
                <Clock className="w-8 h-8 mx-auto mb-2 opacity-40" />
                <p>No scans yet</p>
              </div>
            ) : (
              history.map((item, i) => {
                const config = getVerdictConfig(item.verdict);
                return (
                  <div
                    key={i}
                    onClick={() => { setResult(item); setActiveTab('upload'); }}
                    className="flex items-center gap-3 p-4 border-b border-zinc-800 hover:bg-zinc-900 cursor-pointer transition-colors last:border-0"
                  >
                    <div className={`w-2 h-2 rounded-full flex-shrink-0 ${verdictDotColor(item.verdict)}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-white text-sm font-medium truncate">{item.fileName}</p>
                      <p className="text-zinc-600 text-xs font-mono truncate">{item.hash.slice(0, 16)}...</p>
                    </div>
                    <span className={`text-xs font-bold ${config.color}`}>{item.verdict}</span>
                  </div>
                );
              })
            )}
          </div>
        )}

        {/* Loading */}
        {isLoading && (
          <div className="mt-8 flex flex-col items-center gap-4">
            <div className="relative">
              <div className="w-16 h-16 border-4 border-zinc-800 rounded-full" />
              <div className="absolute inset-0 w-16 h-16 border-4 border-emerald-400 rounded-full border-t-transparent animate-spin" />
            </div>
            <p className="text-zinc-500 font-medium">Analyzing file...</p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="mt-8 p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-red-400 font-medium">Error</p>
              <p className="text-red-300/70 text-sm">{error}</p>
            </div>
          </div>
        )}

        {/* Results */}
        {result && !isLoading && (() => {
          const config = getVerdictConfig(result.verdict);
          const Icon = config.icon;
          const detectionRate = result.total > 0 ? ((result.malicious / result.total) * 100).toFixed(1) : '0';
          return (
            <div className="mt-8 bg-zinc-950 border border-zinc-800 rounded-2xl overflow-hidden">
              {/* File Info */}
              <div className="p-4 sm:p-6 border-b border-zinc-800 flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <FileText className="w-5 h-5 text-zinc-600 mt-0.5" />
                  <div className="min-w-0">
                    <p className="text-white font-medium truncate">{result.fileName}</p>
                    <p className="text-zinc-600 text-sm">{result.fileSize}</p>
                  </div>
                </div>
                <button
                  onClick={() => exportResult(result)}
                  className="flex items-center gap-1.5 text-zinc-500 hover:text-emerald-400 transition-colors text-sm flex-shrink-0"
                >
                  <Download className="w-4 h-4" />
                  Export
                </button>
              </div>

              {/* Hash */}
              <div className="p-4 sm:p-6 border-b border-zinc-800">
                <div className="flex items-center gap-2 mb-2">
                  <HashIcon className="w-4 h-4 text-zinc-600" />
                  <p className="text-zinc-600 text-sm font-medium">SHA-256 Hash</p>
                </div>
                <p className="text-zinc-400 font-mono text-xs sm:text-sm break-all bg-zinc-900 p-3 rounded-lg">{result.hash}</p>
              </div>

              {/* Verdict */}
              <div className={`p-4 sm:p-6 border-b border-zinc-800 ${config.bgColor}`}>
                <div className="flex items-center gap-3">
                  <Icon className={`w-6 h-6 ${config.color}`} />
                  <div>
                    <p className={`text-sm font-medium ${config.color}`}>Verdict</p>
                    <p className={`text-2xl font-bold ${config.color}`}>{config.label}</p>
                  </div>
                </div>
              </div>

              {/* VirusTotal Stats */}
              <div className="p-4 sm:p-6 border-b border-zinc-800">
                <p className="text-zinc-600 text-sm font-medium mb-4">VirusTotal Scan Results</p>
                <div className="grid grid-cols-4 gap-3 mb-4">
                  {[
                    { label: 'Malicious', value: result.malicious, color: 'text-red-400' },
                    { label: 'Suspicious', value: result.suspicious, color: 'text-amber-400' },
                    { label: 'Harmless', value: result.harmless, color: 'text-emerald-400' },
                    { label: 'Total', value: result.total, color: 'text-zinc-300' },
                  ].map(stat => (
                    <div key={stat.label} className="bg-zinc-900 rounded-xl p-3 text-center">
                      <p className={`text-xl font-bold ${stat.color}`}>{stat.value}</p>
                      <p className="text-zinc-600 text-xs mt-1">{stat.label}</p>
                    </div>
                  ))}
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex-1 bg-zinc-900 rounded-full h-2">
                    <div
                      className="bg-red-500 h-2 rounded-full transition-all"
                      style={{ width: `${Math.min(100, Number(detectionRate))}%` }}
                    />
                  </div>
                  <span className="text-zinc-500 text-xs">{detectionRate}% detection rate</span>
                </div>
              </div>

              {/* AI Analysis */}
              <div className="p-4 sm:p-6">
                <p className="text-zinc-600 text-sm font-medium mb-3">AI Analysis</p>
                <p className={`leading-relaxed ${config.color}`}>{result.analysis}</p>
              </div>
            </div>
          );
        })()}

        <p className="text-center text-zinc-700 text-sm mt-10">Powered by advanced threat intelligence and AI analysis</p>
      </div>
    </div>
  );
}

export default App;
