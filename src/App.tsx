import { useCallback, useState } from 'react';
import { Upload, Shield, AlertTriangle, AlertCircle, CheckCircle, FileText, Hash as HashIcon } from 'lucide-react';

type Verdict = 'SAFE' | 'DANGEROUS' | 'SUSPICIOUS' | 'UNKNOWN';

interface AnalysisResult {
  verdict: Verdict;
  analysis: string;
  hash: string;
  fileName: string;
  fileSize: string;
}

const detectVerdict = (text: string): Verdict => {
  const upperText = text.toUpperCase();
  if (upperText.includes('DANGEROUS')) return 'DANGEROUS';
  if (upperText.includes('SUSPICIOUS')) return 'SUSPICIOUS';
  if (upperText.includes('SAFE')) return 'SAFE';
  return 'UNKNOWN';
};

function App() {
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);

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

  const analyzeFile = useCallback(async (file: File) => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const hash = await calculateSHA256(file);

      const response = await fetch('https://harness-roving-twelve.ngrok-free.dev/webhook/9a214cf4-0d63-4a50-b941-00cc1bf51412', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ hash }),
      });

      if (!response.ok) {
        throw new Error('Failed to analyze file');
      }

      const analysisText = await response.text();

      setResult({
        verdict: detectVerdict(analysisText),
        analysis: analysisText || 'No analysis available',
        hash,
        fileName: file.name,
        fileSize: formatFileSize(file.size),
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setIsLoading(false);
    }
  }, []);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      analyzeFile(files[0]);
    }
  }, [analyzeFile]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      analyzeFile(files[0]);
    }
  }, [analyzeFile]);

  const getVerdictConfig = (verdict: Verdict) => {
    switch (verdict) {
      case 'SAFE':
        return {
          color: 'text-emerald-400',
          bgColor: 'bg-emerald-500/10 border-emerald-500/30',
          icon: CheckCircle,
          label: 'SAFE',
        };
      case 'DANGEROUS':
        return {
          color: 'text-red-400',
          bgColor: 'bg-red-500/10 border-red-500/30',
          icon: AlertCircle,
          label: 'DANGEROUS',
        };
      case 'SUSPICIOUS':
        return {
          color: 'text-amber-400',
          bgColor: 'bg-amber-500/10 border-amber-500/30',
          icon: AlertTriangle,
          label: 'SUSPICIOUS',
        };
      case 'UNKNOWN':
        return {
          color: 'text-zinc-400',
          bgColor: 'bg-zinc-500/10 border-zinc-500/30',
          icon: AlertCircle,
          label: 'UNKNOWN',
        };
      default:
        return null;
    }
  };

  return (
    <div className="min-h-screen bg-black flex flex-col items-center justify-center p-4 sm:p-8">
      <div className="w-full max-w-2xl">
        {/* Header */}
        <div className="text-center mb-10">
          <div className="inline-flex items-center gap-3 mb-4">
            <Shield className="w-10 h-10 text-emerald-400" />
            <h1 className="text-4xl sm:text-5xl font-bold text-white tracking-tight">
              Hash<span className="text-emerald-400">Guard</span>
            </h1>
          </div>
          <p className="text-zinc-600 text-lg">
            Advanced file hash analyzer for cybersecurity threat detection
          </p>
        </div>

        {/* Upload Area */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          className={`
            relative border-2 border-dashed rounded-2xl p-8 sm:p-12
            transition-all duration-300 ease-out cursor-pointer
            ${isDragging
              ? 'border-emerald-400 bg-emerald-500/10 scale-[1.02]'
              : 'border-zinc-800 bg-zinc-950/50 hover:border-zinc-700 hover:bg-zinc-950/70'}
          `}
        >
          <input
            type="file"
            onChange={handleFileInput}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          />

          <div className="flex flex-col items-center gap-4">
            <div className={`
              p-4 rounded-full transition-colors duration-300
              ${isDragging ? 'bg-emerald-500/20' : 'bg-zinc-900'}
            `}>
              <Upload className={`w-8 h-8 ${isDragging ? 'text-emerald-400' : 'text-zinc-500'}`} />
            </div>

            <div className="text-center">
              <p className="text-white font-medium text-lg mb-1">
                {isDragging ? 'Drop your file here' : 'Drag & drop your file'}
              </p>
              <p className="text-zinc-600 text-sm">
                or click to browse
              </p>
            </div>

            <p className="text-zinc-700 text-xs mt-2">
              Supports all file types
            </p>
          </div>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="mt-8 flex flex-col items-center gap-4">
            <div className="relative">
              <div className="w-16 h-16 border-4 border-zinc-800 rounded-full"></div>
              <div className="absolute inset-0 w-16 h-16 border-4 border-emerald-400 rounded-full border-t-transparent animate-spin"></div>
            </div>
            <p className="text-zinc-500 font-medium">Analyzing file...</p>
          </div>
        )}

        {/* Error State */}
        {error && (
          <div className="mt-8 p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="text-red-400 font-medium">Error</p>
              <p className="text-red-300/70 text-sm">{error}</p>
            </div>
          </div>
        )}

        {/* Results Card */}
        {result && !isLoading && (
          <div className="mt-8 bg-zinc-950 border border-zinc-800 rounded-2xl overflow-hidden">
            {/* File Info Header */}
            <div className="p-4 sm:p-6 border-b border-zinc-800">
              <div className="flex items-start gap-3">
                <FileText className="w-5 h-5 text-zinc-600 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <p className="text-white font-medium truncate">{result.fileName}</p>
                  <p className="text-zinc-600 text-sm">{result.fileSize}</p>
                </div>
              </div>
            </div>

            {/* Hash Display */}
            <div className="p-4 sm:p-6 border-b border-zinc-800">
              <div className="flex items-center gap-2 mb-2">
                <HashIcon className="w-4 h-4 text-zinc-600" />
                <p className="text-zinc-600 text-sm font-medium">SHA-256 Hash</p>
              </div>
              <p className="text-zinc-400 font-mono text-xs sm:text-sm break-all bg-zinc-900 p-3 rounded-lg">
                {result.hash}
              </p>
            </div>

            {/* Verdict */}
            {result.verdict && getVerdictConfig(result.verdict) && (
              <div className={`p-4 sm:p-6 border-b border-zinc-800 ${getVerdictConfig(result.verdict)?.bgColor}`}>
                <div className="flex items-center gap-3">
                  {(() => {
                    const config = getVerdictConfig(result.verdict);
                    if (!config) return null;
                    const Icon = config.icon;
                    return (
                      <>
                        <Icon className={`w-6 h-6 ${config.color}`} />
                        <div>
                          <p className={`text-sm font-medium ${config.color}`}>Verdict</p>
                          <p className={`text-2xl font-bold ${config.color}`}>{config.label}</p>
                        </div>
                      </>
                    );
                  })()}
                </div>
              </div>
            )}

            {/* AI Analysis */}
            <div className="p-4 sm:p-6">
              <p className="text-zinc-600 text-sm font-medium mb-3">AI Analysis</p>
              <p className={`leading-relaxed ${getVerdictConfig(result.verdict)?.color || 'text-zinc-400'}`}>{result.analysis}</p>
            </div>
          </div>
        )}

        {/* Footer */}
        <p className="text-center text-zinc-700 text-sm mt-10">
          Powered by advanced threat intelligence and AI analysis
        </p>
      </div>
    </div>
  );
}

export default App;
