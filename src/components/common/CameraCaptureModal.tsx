import React, { useState, useRef, useEffect, useCallback } from 'react';
import {
  requestUniversalCameraStream,
  getAvailableVideoDevices,
  stopMediaStream,
  parseCameraError,
  CameraDeviceInfo,
  CameraErrorCode,
} from '../../utils/cameraUtils';
import { sha256Text } from '../../services/cryptoService';
import {
  Camera,
  X,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  Lock,
  MonitorOff,
  Radio,
  Sparkles,
} from 'lucide-react';

interface CameraCaptureModalProps {
  isOpen: boolean;
  onClose: () => void;
  onPhotoCaptured: (data: { imageUrl: string; fileHash: string; fileName: string }) => void;
  title?: string;
  subtitle?: string;
}

export const CameraCaptureModal: React.FC<CameraCaptureModalProps> = ({
  isOpen,
  onClose,
  onPhotoCaptured,
  title = 'Forensic Evidence Camera Capture',
  subtitle = 'Capture live crime scene evidence photo with cryptographic SHA-256 hashing',
}) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const streamRef = useRef<MediaStream | null>(null);

  // Camera connection status
  const [cameraState, setCameraState] = useState<'IDLE' | 'STARTING' | 'STREAMING' | 'CAPTURED' | 'ERROR'>('IDLE');
  const [cameraError, setCameraError] = useState<{ message: string; code: CameraErrorCode } | null>(null);

  // Hardware devices
  const [availableCameras, setAvailableCameras] = useState<CameraDeviceInfo[]>([]);
  const [selectedCameraId, setSelectedCameraId] = useState<string>('');
  const [facingMode, setFacingMode] = useState<'environment' | 'user'>('environment');

  // Preview captured photo before applying
  const [capturedPreview, setCapturedPreview] = useState<{ imageUrl: string; fileHash: string } | null>(null);

  // Stop camera tracks cleanly
  const stopCamera = useCallback(() => {
    if (streamRef.current) {
      stopMediaStream(streamRef.current);
      streamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    if (cameraState === 'STREAMING' || cameraState === 'STARTING') {
      setCameraState('IDLE');
    }
  }, [cameraState]);

  // Clean up when unmounting or closing
  useEffect(() => {
    if (!isOpen) {
      stopCamera();
      setCameraState('IDLE');
      setCameraError(null);
      setCapturedPreview(null);
    }
    return () => {
      stopCamera();
    };
  }, [isOpen, stopCamera]);

  // Explicit user action: "Start Camera" / "Open Camera"
  const startCamera = async () => {
    stopCamera();
    setCameraError(null);
    setCapturedPreview(null);
    setCameraState('STARTING');

    try {
      const stream = await requestUniversalCameraStream({
        facingMode,
        deviceId: selectedCameraId || undefined,
        idealWidth: 1920,
        idealHeight: 1080,
      });

      streamRef.current = stream;

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        videoRef.current.setAttribute('playsinline', 'true');
        await videoRef.current.play();
      }

      setCameraState('STREAMING');

      // Fetch devices list for switcher
      const devices = await getAvailableVideoDevices();
      setAvailableCameras(devices);
    } catch (err: any) {
      const parsed = parseCameraError(err);
      console.warn('[CameraCaptureModal] Camera initialization error:', parsed);
      setCameraError({ message: parsed.message, code: parsed.code });
      setCameraState('ERROR');
      stopCamera();
    }
  };

  // Flip camera (Rear <-> Front)
  const toggleFacingMode = () => {
    const nextMode = facingMode === 'environment' ? 'user' : 'environment';
    setFacingMode(nextMode);
    if (cameraState === 'STREAMING') {
      // Re-trigger start with new mode
      setTimeout(() => {
        startCamera();
      }, 50);
    }
  };

  // Switch camera by device ID
  const handleDeviceChange = (deviceId: string) => {
    setSelectedCameraId(deviceId);
    if (cameraState === 'STREAMING') {
      setTimeout(() => {
        startCamera();
      }, 50);
    }
  };

  // Explicit user action: "Capture Photo"
  const handleCapturePhoto = async () => {
    const video = videoRef.current;
    if (!video || cameraState !== 'STREAMING') {
      return;
    }

    const videoWidth = video.videoWidth || 1280;
    const videoHeight = video.videoHeight || 720;

    const canvas = document.createElement('canvas');
    canvas.width = videoWidth;
    canvas.height = videoHeight;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Draw frame onto canvas
    ctx.drawImage(video, 0, 0, videoWidth, videoHeight);

    // Export image as high quality JPEG
    const imageUrl = canvas.toDataURL('image/jpeg', 0.92);

    // Calculate real cryptographic SHA-256 checksum of the captured image
    const fileHash = await sha256Text(imageUrl);
    const fileName = `EVIDENCE_PHOTO_${Date.now()}.jpg`;

    // Stop active camera tracks now that photo is taken
    stopCamera();

    setCapturedPreview({ imageUrl, fileHash });
    setCameraState('CAPTURED');

    onPhotoCaptured({
      imageUrl,
      fileHash,
      fileName,
    });
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-150">
      <div className="relative w-full max-w-xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-950/70">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Camera className="w-4 h-4" />
            </div>
            <div>
              <h3 className="font-semibold text-sm text-white tracking-wide">{title}</h3>
              <p className="text-[11px] text-slate-400 font-mono">{subtitle}</p>
            </div>
          </div>
          <button
            onClick={() => {
              stopCamera();
              onClose();
            }}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Viewport Area */}
        <div className="relative bg-black flex items-center justify-center min-h-[320px] max-h-[420px] overflow-hidden">
          {/* Active Live Video Stream */}
          <video
            ref={videoRef}
            className={`w-full h-full object-cover max-h-[420px] ${
              cameraState === 'STREAMING' ? 'block' : 'hidden'
            }`}
            playsInline
            muted
          />

          {/* Initial State: Camera not started */}
          {cameraState === 'IDLE' && !capturedPreview && (
            <div className="p-8 text-center space-y-4 max-w-sm">
              <div className="w-16 h-16 rounded-2xl bg-cyan-950/60 border border-cyan-500/40 flex items-center justify-center text-cyan-400 mx-auto">
                <Camera className="w-8 h-8" />
              </div>
              <div className="space-y-1">
                <h4 className="text-white font-semibold text-sm">Camera Hardware Standby</h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Click the button below to initialize your system camera and preview the live evidence feed.
                </p>
              </div>
              <button
                type="button"
                onClick={startCamera}
                className="py-2.5 px-6 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs flex items-center justify-center gap-2 mx-auto cursor-pointer shadow-lg shadow-cyan-950/40 transition-all font-mono"
              >
                <Radio className="w-4 h-4" />
                <span>Start Camera</span>
              </button>
            </div>
          )}

          {/* Loading / Starting State */}
          {cameraState === 'STARTING' && (
            <div className="p-8 text-center space-y-3">
              <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
              <p className="text-xs font-mono text-cyan-300">
                Requesting camera access & initializing optical sensor...
              </p>
            </div>
          )}

          {/* Error States with specific error codes and messages */}
          {cameraState === 'ERROR' && cameraError && (
            <div className="p-6 text-center space-y-3 max-w-md bg-slate-950/90 rounded-xl border border-rose-500/50 m-4">
              <div className="w-12 h-12 rounded-full bg-rose-950/80 border border-rose-500/80 flex items-center justify-center text-rose-400 mx-auto">
                {cameraError.code === 'PERMISSION_DENIED' ? (
                  <Lock className="w-6 h-6" />
                ) : cameraError.code === 'NOT_FOUND' ? (
                  <MonitorOff className="w-6 h-6" />
                ) : (
                  <AlertCircle className="w-6 h-6" />
                )}
              </div>

              <div>
                <h4 className="text-white font-semibold text-sm">
                  {cameraError.code === 'PERMISSION_DENIED' && 'Camera Permission Denied'}
                  {cameraError.code === 'NOT_FOUND' && 'Camera Device Not Found'}
                  {cameraError.code === 'ALREADY_IN_USE' && 'Camera Already In Use'}
                  {cameraError.code === 'UNSUPPORTED' && 'Browser Not Supported'}
                  {cameraError.code === 'UNAVAILABLE' && 'Camera Unavailable'}
                </h4>
                <p className="text-xs text-rose-200/90 mt-1.5 leading-relaxed font-sans">
                  {cameraError.message}
                </p>
              </div>

              <div className="pt-2 flex justify-center gap-2">
                <button
                  type="button"
                  onClick={startCamera}
                  className="py-1.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs flex items-center gap-1.5 cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5" />
                  <span>Retry Camera</span>
                </button>
              </div>
            </div>
          )}

          {/* Photo Captured State Preview */}
          {cameraState === 'CAPTURED' && capturedPreview && (
            <div className="relative w-full h-full flex flex-col items-center justify-center">
              <img
                src={capturedPreview.imageUrl}
                alt="Captured Evidence"
                className="w-full h-full object-cover max-h-[380px]"
              />
              <div className="absolute inset-x-0 bottom-0 p-3 bg-slate-950/80 backdrop-blur-sm border-t border-slate-800 text-left">
                <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-semibold">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Photo Captured & Cryptographically Hashed</span>
                </div>
                <div className="text-[10px] font-mono text-slate-400 mt-0.5 truncate">
                  SHA-256: {capturedPreview.fileHash}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Live Controls & Action Bar */}
        <div className="p-4 bg-slate-950/90 border-t border-slate-800 space-y-3">
          {cameraState === 'STREAMING' && (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={toggleFacingMode}
                  className="py-1.5 px-3 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Flip ({facingMode === 'environment' ? 'Rear' : 'Front'})</span>
                </button>

                {availableCameras.length > 1 && (
                  <select
                    value={selectedCameraId}
                    onChange={e => handleDeviceChange(e.target.value)}
                    className="py-1.5 px-2.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                  >
                    {availableCameras.map(c => (
                      <option key={c.deviceId} value={c.deviceId}>
                        {c.label || `Camera ${c.deviceId.slice(0, 6)}`}
                      </option>
                    ))}
                  </select>
                )}
              </div>

              {/* Prominent Capture Photo Button */}
              <button
                type="button"
                onClick={handleCapturePhoto}
                className="py-2 px-5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-950/50"
              >
                <Camera className="w-4 h-4 text-white" />
                <span>Capture Photo</span>
              </button>
            </div>
          )}

          {cameraState === 'CAPTURED' && (
            <div className="flex items-center justify-between">
              <button
                type="button"
                onClick={startCamera}
                className="py-1.5 px-3.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Retake Photo</span>
              </button>

              <button
                type="button"
                onClick={onClose}
                className="py-1.5 px-4 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold cursor-pointer"
              >
                Done
              </button>
            </div>
          )}

          {cameraState === 'IDLE' && (
            <div className="flex justify-end">
              <button
                type="button"
                onClick={onClose}
                className="py-1.5 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs cursor-pointer"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
