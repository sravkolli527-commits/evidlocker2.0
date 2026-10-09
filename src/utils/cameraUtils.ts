/**
 * Universal cross-platform camera utility supporting:
 * - Laptops (integrated webcams, MacBook FaceTime HD, USB webcams)
 * - Desktop PCs (external USB cameras, capture devices)
 * - Mobile Phones & Tablets (front selfie camera & rear environment cameras)
 */

export type CameraErrorCode =
  | 'PERMISSION_DENIED'
  | 'UNAVAILABLE'
  | 'ALREADY_IN_USE'
  | 'UNSUPPORTED'
  | 'NOT_FOUND';

export class CameraAccessError extends Error {
  code: CameraErrorCode;

  constructor(message: string, code: CameraErrorCode) {
    super(message);
    this.name = 'CameraAccessError';
    this.code = code;
  }
}

export interface CameraDeviceInfo {
  deviceId: string;
  label: string;
  kind: MediaDeviceKind;
}

export function parseCameraError(err: any): CameraAccessError {
  if (err instanceof CameraAccessError) {
    return err;
  }

  const name = err?.name || '';
  const message = err?.message || '';

  if (
    name === 'NotAllowedError' ||
    name === 'PermissionDeniedError' ||
    name === 'SecurityError' ||
    message.toLowerCase().includes('permission') ||
    message.toLowerCase().includes('denied')
  ) {
    return new CameraAccessError(
      'Camera permission was denied. Please allow camera access in your browser address bar or device privacy settings.',
      'PERMISSION_DENIED'
    );
  }

  if (
    name === 'NotFoundError' ||
    name === 'DevicesNotFoundError' ||
    message.toLowerCase().includes('not found') ||
    message.toLowerCase().includes('no device')
  ) {
    return new CameraAccessError(
      'No camera hardware device found on this system. Please connect an external webcam or enable your built-in camera.',
      'NOT_FOUND'
    );
  }

  if (
    name === 'NotReadableError' ||
    name === 'TrackStartError' ||
    message.toLowerCase().includes('already in use') ||
    message.toLowerCase().includes('could not start')
  ) {
    return new CameraAccessError(
      'Camera is already in use by another application or browser tab. Please close other applications using the camera and try again.',
      'ALREADY_IN_USE'
    );
  }

  if (
    name === 'OverconstrainedError' ||
    name === 'AbortError' ||
    name === 'ConstraintNotSatisfiedError'
  ) {
    return new CameraAccessError(
      'Camera hardware is currently unavailable or the requested resolution/lens is not supported.',
      'UNAVAILABLE'
    );
  }

  return new CameraAccessError(
    message || 'Camera is currently unavailable. Please verify your device connection and permissions.',
    'UNAVAILABLE'
  );
}

export async function getAvailableVideoDevices(): Promise<CameraDeviceInfo[]> {
  if (!navigator?.mediaDevices || typeof navigator.mediaDevices.enumerateDevices !== 'function') {
    return [];
  }
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    return devices
      .filter(d => d.kind === 'videoinput')
      .map((d, index) => ({
        deviceId: d.deviceId,
        label: d.label || `Camera ${index + 1} (${d.deviceId.slice(0, 5)}...)`,
        kind: d.kind,
      }));
  } catch {
    return [];
  }
}

export async function requestUniversalCameraStream(options?: {
  facingMode?: 'user' | 'environment';
  deviceId?: string;
  idealWidth?: number;
  idealHeight?: number;
}): Promise<MediaStream> {
  // Check browser API support
  if (!navigator?.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
    throw new CameraAccessError(
      'Camera API (getUserMedia) is not supported in this browser environment or requires an HTTPS secure connection.',
      'UNSUPPORTED'
    );
  }

  const idealWidth = options?.idealWidth || 1280;
  const idealHeight = options?.idealHeight || 720;
  const facingMode = options?.facingMode || 'environment';

  // 1. Try with specific deviceId if provided
  if (options?.deviceId) {
    try {
      return await navigator.mediaDevices.getUserMedia({
        video: {
          deviceId: { exact: options.deviceId },
          width: { ideal: idealWidth },
          height: { ideal: idealHeight },
        },
        audio: false,
      });
    } catch (err: any) {
      if (
        err?.name === 'NotAllowedError' ||
        err?.name === 'PermissionDeniedError' ||
        err?.name === 'SecurityError'
      ) {
        throw parseCameraError(err);
      }
      console.warn(`[CameraUtil] deviceId: ${options.deviceId} failed, trying fallback:`, err);
    }
  }

  // 2. Try with requested facingMode and ideal resolution
  try {
    return await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: { ideal: facingMode },
        width: { ideal: idealWidth },
        height: { ideal: idealHeight },
      },
      audio: false,
    });
  } catch (err: any) {
    // If permission was explicitly denied or already in use or device missing, throw immediately!
    if (
      err?.name === 'NotAllowedError' ||
      err?.name === 'PermissionDeniedError' ||
      err?.name === 'SecurityError' ||
      err?.name === 'NotReadableError' ||
      err?.name === 'TrackStartError' ||
      err?.name === 'NotFoundError' ||
      err?.name === 'DevicesNotFoundError'
    ) {
      throw parseCameraError(err);
    }
    console.warn(`[CameraUtil] ideal constraints failed, attempting basic video fallback:`, err);
  }

  // 3. Fallback: Generic video constraint without resolution/facing constraints
  try {
    return await navigator.mediaDevices.getUserMedia({
      video: true,
      audio: false,
    });
  } catch (err: any) {
    throw parseCameraError(err);
  }
}

export function stopMediaStream(stream: MediaStream | null | undefined): void {
  if (!stream) return;
  try {
    stream.getTracks().forEach(track => {
      try {
        track.stop();
      } catch {
        // ignore individual track error
      }
    });
  } catch {
    // ignore
  }
}
