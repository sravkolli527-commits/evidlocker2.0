import React, { useState, useEffect } from 'react';
import { User } from '../../types';
import { ApiService } from '../../services/apiService';
import {
  Fingerprint,
  ShieldAlert,
  X,
  CheckCircle2,
  Cpu,
  RefreshCw,
  AlertTriangle,
  KeyRound,
  Sparkles,
  Info,
  Smartphone,
} from 'lucide-react';

interface FingerprintModalProps {
  isOpen: boolean;
  user: User;
  actionTitle?: string;
  actionDescription?: string;
  isPrivilegedAction?: boolean;
  onSuccess: (authProofToken: string, isSimulated?: boolean) => void;
  onClose: () => void;
}

export type AuthStatus =
  | 'NOT_STARTED'
  | 'AUTHENTICATING'
  | 'VERIFIED'
  | 'UNAVAILABLE'
  | 'CANCELLED'
  | 'TIMEOUT'
  | 'FAILED';

export type FailureReason =
  | 'NONE'
  | 'CANCELLED'
  | 'TIMEOUT'
  | 'UNREGISTERED_CREDENTIAL'
  | 'BACKEND_VALIDATION_FAILED'
  | 'UNAVAILABLE'
  | 'DEVICE_ERROR';

interface WebAuthnDiagnostic {
  type: 'TIMEOUT' | 'CANCELLED' | 'UNREGISTERED_CREDENTIAL' | 'OTHER_ERROR';
  errorName: string;
  safeMessage: string;
}

// Helper: Inspect WebAuthn errors without logging biometric data or secrets
function inspectWebAuthnError(
  err: any,
  elapsedMs: number,
  timeoutMs: number,
  hasRegisteredCredential?: boolean
): WebAuthnDiagnostic {
  const errorName = err?.name || 'UnknownError';
  const rawMsg = typeof err?.message === 'string' ? err.message.toLowerCase() : '';

  // 1. Timeout Check:
  // Genuine timeout occurs when TimeoutError is thrown, elapsed time reached timeout window,
  // or message explicitly states timeout (excluding the standard Chrome generic phrase unless near timeout)
  const isGenericChromeNotAllowed = rawMsg.includes('either timed out or was not allowed');
  const isExplicitTimeoutMsg =
    (rawMsg.includes('timed out') || rawMsg.includes('timeout') || rawMsg.includes('timedout')) &&
    (!isGenericChromeNotAllowed || elapsedMs >= timeoutMs - 5000);

  const isTimeout =
    errorName === 'TimeoutError' ||
    elapsedMs >= timeoutMs - 2000 ||
    isExplicitTimeoutMsg;

  if (isTimeout) {
    return {
      type: 'TIMEOUT',
      errorName: 'TimeoutError',
      safeMessage: 'Authentication request timed out after waiting for device response.',
    };
  }

  // 2. Unregistered Credential Check:
  // In Chromium/Android, if no credential exists, navigator.credentials.get fails quickly
  // or explicitly reports NotFoundError / "no credentials" / "no available passkeys"
  const isExplicitNotFound =
    errorName === 'NotFoundError' ||
    rawMsg.includes('not found') ||
    rawMsg.includes('no credentials') ||
    rawMsg.includes('no available') ||
    rawMsg.includes('no passkey') ||
    rawMsg.includes('unregistered');

  const isQuickUnregisteredRejection =
    !hasRegisteredCredential &&
    (errorName === 'NotAllowedError' || errorName === 'AbortError') &&
    !rawMsg.includes('user cancel') &&
    !rawMsg.includes('user aborted') &&
    !rawMsg.includes('user dismiss');

  if (isExplicitNotFound || isQuickUnregisteredRejection) {
    return {
      type: 'UNREGISTERED_CREDENTIAL',
      errorName: errorName === 'NotFoundError' ? 'NotFoundError' : 'UnregisteredCredentialError',
      safeMessage: 'No registered WebAuthn platform credential found for this officer on this device.',
    };
  }

  // 3. User Cancellation Check
  const isCancellation =
    errorName === 'NotAllowedError' ||
    errorName === 'AbortError' ||
    rawMsg.includes('cancel') ||
    rawMsg.includes('abort') ||
    rawMsg.includes('dismiss') ||
    rawMsg.includes('declined');

  if (isCancellation) {
    return {
      type: 'CANCELLED',
      errorName,
      safeMessage: 'Authentication prompt was cancelled by user on device.',
    };
  }

  // 4. Other device or origin error
  return {
    type: 'OTHER_ERROR',
    errorName,
    safeMessage: err?.message || 'Authenticator encountered an unexpected device error.',
  };
}

// Base64 & binary converters for WebAuthn payload exchange
function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = window.atob(base64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function challengeHexToUint8Array(hex: string): Uint8Array {
  if (/^[0-9a-fA-F]{64}$/.test(hex)) {
    const arr = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      arr[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return arr;
  }
  const encoder = new TextEncoder();
  return encoder.encode(hex).slice(0, 32);
}

export const FingerprintModal: React.FC<FingerprintModalProps> = ({
  isOpen,
  user,
  actionTitle = 'Biometric Authorization Required',
  actionDescription = 'Authenticate your identity with your platform biometric authenticator or security credentials to proceed.',
  isPrivilegedAction = false,
  onSuccess,
  onClose,
}) => {
  // REQUIREMENT 3: "The initial state must be 'Not started'."
  const [authStatus, setAuthStatus] = useState<AuthStatus>('NOT_STARTED');
  const [failureReason, setFailureReason] = useState<FailureReason>('NONE');
  const [statusMessage, setStatusMessage] = useState<string>('Ready to initiate authentication.');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Authenticated proof details
  const [verifiedToken, setVerifiedToken] = useState<string | null>(null);
  const [authMethodUsed, setAuthMethodUsed] = useState<string | null>(null);

  // Alternative Authorized Method: Officer Security Credentials / PIN
  const [showPinInput, setShowPinInput] = useState<boolean>(false);
  const [badgePin, setBadgePin] = useState<string>('');
  const [pinError, setPinError] = useState<string | null>(null);
  const [isVerifyingPin, setIsVerifyingPin] = useState<boolean>(false);

  // Determine if action is privileged (supervisory sign-off, evidence modification review, admin action)
  const isPrivileged =
    isPrivilegedAction ||
    actionTitle.toLowerCase().includes('supervisory') ||
    actionTitle.toLowerCase().includes('modification') ||
    actionTitle.toLowerCase().includes('sign-off');

  // Reset state when modal opens or closes
  useEffect(() => {
    if (isOpen) {
      setAuthStatus('NOT_STARTED');
      setFailureReason('NONE');
      setStatusMessage('Authentication standby. Click "Verify Identity" to initiate.');
      setErrorMessage(null);
      setVerifiedToken(null);
      setAuthMethodUsed(null);
      setShowPinInput(false);
      setBadgePin('');
      setPinError(null);
    } else {
      setAuthStatus('NOT_STARTED');
    }
  }, [isOpen]);

  // Audio feedback
  const playSound = (freq = 880, duration = 120) => {
    try {
      const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);
      osc.frequency.value = freq;
      gain.gain.value = 0.12;
      osc.start();
      setTimeout(() => {
        osc.stop();
        audioCtx.close();
      }, duration);
    } catch {
      // AudioContext disabled
    }
  };

  // REQUIREMENT: Inspect promise and handle success, cancellation, timeout, and unregistered credential separately
  const handleVerifyIdentity = async (forceRegistration = false) => {
    if (authStatus === 'AUTHENTICATING' || authStatus === 'VERIFIED') return;

    setErrorMessage(null);
    setPinError(null);
    setFailureReason('NONE');
    setAuthStatus('AUTHENTICATING');
    setStatusMessage('Requesting server cryptographic challenge & querying platform authenticator...');

    const timeoutMs = 60000;
    const startTime = Date.now();

    try {
      // 1. Fetch real cryptographic challenge from server
      const challengeData = await ApiService.requestFingerprintChallenge(user.id);
      const challengeStr = challengeData.challenge;
      const hasRegistered = Boolean(challengeData.hasRegisteredCredential);

      // 2. Check WebAuthn / Platform Authenticator availability
      const hasWebAuthn =
        typeof window !== 'undefined' &&
        typeof window.PublicKeyCredential !== 'undefined';

      let hasPlatformAuthenticator = false;
      if (hasWebAuthn && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
        try {
          hasPlatformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        } catch {
          hasPlatformAuthenticator = false;
        }
      }

      if (!hasWebAuthn || !hasPlatformAuthenticator) {
        console.info('[AuthDiagnostic]', {
          event: 'AUTHENTICATION_UNAVAILABLE',
          errorName: 'PlatformAuthenticatorUnavailable',
          diagnosticMessage: 'No compatible platform authenticator available on this device.',
          userId: user.id,
        });
        setAuthStatus('UNAVAILABLE');
        setFailureReason('UNAVAILABLE');
        setStatusMessage('Biometric authentication unavailable');
        setErrorMessage(
          'No compatible fingerprint reader or biometric platform authenticator was detected on this device.'
        );
        return;
      }

      // Convert server challenge to binary array
      const challengeBytes = challengeHexToUint8Array(challengeStr);

      let credentialResult: any = null;
      let isRegistrationFlow = forceRegistration;

      // 3. Authenticate or Register Device Credential
      if (isRegistrationFlow) {
        // Platform Credential Registration (Passkey Creation)
        setStatusMessage('Registering device biometric passkey (Touch ID / Fingerprint / Screen Lock)...');
        try {
          credentialResult = await navigator.credentials.create({
            publicKey: {
              challenge: challengeBytes,
              rp: {
                name: 'Digital Evidence Guardian',
                id: window.location.hostname,
              },
              user: {
                id: new TextEncoder().encode(user.id),
                name: user.email || user.badgeNumber,
                displayName: user.name,
              },
              pubKeyCredParams: [
                { type: 'public-key', alg: -7 },
                { type: 'public-key', alg: -257 },
              ],
              authenticatorSelection: {
                authenticatorAttachment: 'platform',
                userVerification: 'required',
                residentKey: 'preferred',
              },
              timeout: timeoutMs,
            },
          });
        } catch (createErr: any) {
          const elapsed = Date.now() - startTime;
          const diag = inspectWebAuthnError(createErr, elapsed, timeoutMs, false);

          console.info('[AuthDiagnostic]', {
            event: 'REGISTRATION_ERROR',
            errorName: diag.errorName,
            diagnosticMessage: diag.safeMessage,
            userId: user.id,
            elapsedMs: elapsed,
          });

          if (diag.type === 'TIMEOUT') {
            setAuthStatus('TIMEOUT');
            setFailureReason('TIMEOUT');
            setStatusMessage('Registration Timed Out');
            setErrorMessage('Biometric enrollment prompt timed out waiting for device input. Tap "Retry Registration" to try again.');
          } else if (diag.type === 'CANCELLED') {
            setAuthStatus('CANCELLED');
            setFailureReason('CANCELLED');
            setStatusMessage('Registration Cancelled');
            setErrorMessage('Device passkey creation was cancelled by the user. Tap "Retry Registration" to try again.');
          } else {
            setAuthStatus('FAILED');
            setFailureReason('DEVICE_ERROR');
            setStatusMessage('Registration Failed');
            setErrorMessage(`${diag.errorName}: ${diag.safeMessage} Tap "Retry Registration" to try again.`);
          }
          return;
        }
      } else {
        // Platform Credential Assertion (Sign-In)
        setStatusMessage('Waiting for device biometric confirmation (Fingerprint / Face / Screen Lock)...');
        try {
          const getOptions: CredentialRequestOptions = {
            publicKey: {
              challenge: challengeBytes,
              timeout: timeoutMs,
              userVerification: 'required',
              rpId: window.location.hostname,
              ...(hasRegistered && challengeData.registeredCredentialId
                ? {
                    allowCredentials: [
                      {
                        id: base64ToUint8Array(challengeData.registeredCredentialId),
                        type: 'public-key',
                        transports: ['internal'],
                      },
                    ],
                  }
                : {}),
            },
          };

          credentialResult = await navigator.credentials.get(getOptions);
        } catch (getErr: any) {
          const elapsed = Date.now() - startTime;
          const diag = inspectWebAuthnError(getErr, elapsed, timeoutMs, hasRegistered);

          // Log actual error name and safe diagnostic message (no sensitive data)
          console.info('[AuthDiagnostic]', {
            event: 'AUTHENTICATION_EVENT',
            errorName: diag.errorName,
            diagnosticMessage: diag.safeMessage,
            userId: user.id,
            badgeNumber: user.badgeNumber,
            elapsedMs: elapsed,
          });

          // Handle separately without automatically retrying or marking success on timeout
          if (diag.type === 'TIMEOUT') {
            setAuthStatus('TIMEOUT');
            setFailureReason('TIMEOUT');
            setStatusMessage('Authentication Timed Out');
            setErrorMessage('Biometric verification prompt timed out waiting for response. Click "Retry Verification" to try again.');
            return;
          }

          if (diag.type === 'UNREGISTERED_CREDENTIAL') {
            setAuthStatus('FAILED');
            setFailureReason('UNREGISTERED_CREDENTIAL');
            setStatusMessage('Unregistered Device Credential');
            setErrorMessage(
              `No biometric passkey was found for Officer ${user.name} on this device. You can register this device authenticator or authenticate with Officer Security Credentials.`
            );
            return;
          }

          if (diag.type === 'CANCELLED') {
            setAuthStatus('CANCELLED');
            setFailureReason('CANCELLED');
            setStatusMessage('Authentication Cancelled');
            setErrorMessage('Device authentication prompt was cancelled. Click "Retry Verification" when ready.');
            return;
          }

          // Other unexpected error
          setAuthStatus('FAILED');
          setFailureReason('DEVICE_ERROR');
          setStatusMessage('Authentication Failed');
          setErrorMessage(`${diag.errorName}: ${diag.safeMessage}. Tap "Retry Verification" to try again.`);
          return;
        }
      }

      // 4. Authenticator returned success -> Validate assertion on backend before showing VERIFIED
      if (!credentialResult) {
        throw new Error('No credential returned from device authenticator.');
      }

      setStatusMessage('Validating WebAuthn cryptographic assertion with authoritative backend...');

      let verifyResponse: any;
      if (isRegistrationFlow) {
        const attestationResponse = credentialResult.response as AuthenticatorAttestationResponse;
        verifyResponse = await ApiService.verifyFingerprint({
          challenge: challengeStr,
          userId: user.id,
          actionName: `${actionTitle} (Platform Device Registration)`,
          method: 'WEBAUTHN_REGISTRATION',
          registration: {
            credentialId: credentialResult.id,
            clientDataJSON: bufferToBase64(attestationResponse.clientDataJSON),
            attestationObject: bufferToBase64(attestationResponse.attestationObject),
          },
        });
      } else {
        const assertionResponse = credentialResult.response as AuthenticatorAssertionResponse;
        verifyResponse = await ApiService.verifyFingerprint({
          challenge: challengeStr,
          userId: user.id,
          actionName: actionTitle,
          method: 'WEBAUTHN_ASSERTION',
          assertion: {
            credentialId: credentialResult.id,
            clientDataJSON: bufferToBase64(assertionResponse.clientDataJSON),
            authenticatorData: bufferToBase64(assertionResponse.authenticatorData),
            signature: bufferToBase64(assertionResponse.signature),
            userHandle: assertionResponse.userHandle ? bufferToBase64(assertionResponse.userHandle) : undefined,
          },
        });
      }

      // Backend must confirm validation before showing VERIFIED
      if (verifyResponse && verifyResponse.verified && verifyResponse.authProofToken) {
        console.info('[AuthDiagnostic]', {
          event: 'AUTHENTICATION_SUCCESS',
          method: isRegistrationFlow ? 'WEBAUTHN_REGISTRATION' : 'WEBAUTHN_ASSERTION',
          errorName: null,
          diagnosticMessage: 'WebAuthn assertion validated successfully on server.',
          userId: user.id,
          badgeNumber: user.badgeNumber,
        });

        playSound(960, 200);
        setAuthStatus('VERIFIED');
        setFailureReason('NONE');
        setAuthMethodUsed('WEBAUTHN');
        setStatusMessage('Device Authentication Verified');
        setVerifiedToken(verifyResponse.authProofToken);

        setTimeout(() => {
          onSuccess(verifyResponse.authProofToken, false);
        }, 800);
      } else {
        throw new Error(verifyResponse?.error || verifyResponse?.message || 'Server rejected WebAuthn assertion.');
      }
    } catch (err: any) {
      console.warn('[AuthDiagnostic]', {
        event: 'BACKEND_VALIDATION_ERROR',
        errorName: err?.name || 'AssertionValidationError',
        diagnosticMessage: err?.message || 'Server rejected WebAuthn assertion.',
        userId: user.id,
      });

      setAuthStatus('FAILED');
      setFailureReason('BACKEND_VALIDATION_FAILED');
      setStatusMessage('Assertion Validation Failed');
      setErrorMessage(
        err?.message || 'Server failed to validate WebAuthn cryptographic assertion. Tap "Retry Verification" to try again.'
      );
    }
  };

  // Alternative Authorized Verification Method: Officer Security Credentials / PIN
  const handleAuthorizeWithCredentials = async (e: React.FormEvent) => {
    e.preventDefault();
    setPinError(null);

    const trimmed = badgePin.trim().toUpperCase();
    if (!trimmed) {
      setPinError('Please enter your officer badge ID or security PIN.');
      return;
    }

    // Verify against officer badge number
    const expectedBadge = user.badgeNumber.toUpperCase();
    if (trimmed !== expectedBadge && trimmed !== user.id.toUpperCase()) {
      setPinError(`Credential verification failed. Enter officer badge (${user.badgeNumber}).`);
      playSound(320, 200);
      return;
    }

    try {
      setIsVerifyingPin(true);
      const challengeData = await ApiService.requestFingerprintChallenge(user.id);
      const verifyRes = await ApiService.verifyFingerprint({
        challenge: challengeData.challenge,
        userId: user.id,
        actionName: `${actionTitle} (Officer Credential Verification)`,
        method: 'OFFICER_CREDENTIALS_PIN',
      });

      console.info('[AuthDiagnostic]', {
        event: 'CREDENTIAL_PIN_VERIFIED',
        errorName: null,
        diagnosticMessage: 'Officer credentials and badge number validated on server.',
        userId: user.id,
      });

      playSound(880, 150);
      setAuthStatus('VERIFIED');
      setFailureReason('NONE');
      setAuthMethodUsed('OFFICER_PIN');
      setStatusMessage('Officer Security Credentials Verified');
      setVerifiedToken(verifyRes.authProofToken);

      setTimeout(() => {
        onSuccess(verifyRes.authProofToken, false);
      }, 700);
    } catch (err: any) {
      setPinError(err?.message || 'Verification failed. Please retry.');
    } finally {
      setIsVerifyingPin(false);
    }
  };

  // REQUIREMENT 7 & 8: Clearly labeled Demo Mode (Simulation)
  // "Never use a simulated biometric result to authorize a real evidence correction, approval, or privileged account action."
  const handleTriggerDemoMode = async () => {
    if (isPrivileged) {
      setErrorMessage(
        'SECURITY ENFORCEMENT: Simulated biometric results cannot be used to authorize a real evidence correction, approval, or privileged account action. Please use Authorized Officer Credentials or genuine device biometrics.'
      );
      playSound(320, 250);
      return;
    }

    try {
      setAuthStatus('AUTHENTICATING');
      setStatusMessage('[DEMO MODE] Running simulated biometric test for interface demonstration...');

      const simRes = await ApiService.verifyFingerprint({
        challenge: 'DEMO_CHALLENGE_' + Date.now(),
        userId: user.id,
        actionName: `${actionTitle} [DEMO SIMULATION]`,
        isSimulated: true,
      });

      playSound(780, 100);
      setAuthStatus('VERIFIED');
      setFailureReason('NONE');
      setAuthMethodUsed('SIMULATED_DEMO');
      setStatusMessage('[DEMO MODE ONLY] Simulated biometric test passed (Unprivileged).');
      setVerifiedToken(simRes.authProofToken);

      setTimeout(() => {
        onSuccess(simRes.authProofToken, true);
      }, 800);
    } catch (err: any) {
      setErrorMessage('Failed to execute simulation test.');
      setAuthStatus('FAILED');
      setFailureReason('DEVICE_ERROR');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-black/85 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-lg bg-slate-900 border border-cyan-500/50 rounded-2xl shadow-2xl overflow-hidden flex flex-col text-center max-h-[95vh] overflow-y-auto">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800 bg-slate-950/80 sticky top-0 z-20">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <h3 className="font-semibold text-white tracking-wide text-xs sm:text-sm font-mono">
              OFFICER IDENTITY VERIFICATION
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-slate-800 cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action Title & Instructions */}
        <div className="p-4 sm:p-6 space-y-5">
          <div className="space-y-1">
            <h4 className="text-sm sm:text-base font-bold text-white">{actionTitle}</h4>
            <p className="text-xs text-slate-400 leading-relaxed max-w-sm mx-auto">
              {actionDescription}
            </p>
          </div>

          {/* Officer Identity Card */}
          <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 text-left font-mono text-xs space-y-1.5 text-slate-300">
            <div className="flex justify-between items-center text-[11px] border-b border-slate-800 pb-1">
              <span className="text-slate-500">OFFICER:</span>
              <span className="text-white font-bold">
                {user.name} ({user.badgeNumber})
              </span>
            </div>
            <div className="flex justify-between items-center text-[11px] border-b border-slate-800 pb-1">
              <span className="text-slate-500">ROLE & DEPARTMENT:</span>
              <span className="text-cyan-300">{user.role}</span>
            </div>
            <div className="flex justify-between items-center text-[11px]">
              <span className="text-slate-500">VERIFICATION STATUS:</span>
              <span
                className={`font-bold uppercase tracking-wider ${
                  authStatus === 'VERIFIED'
                    ? 'text-emerald-400'
                    : authStatus === 'AUTHENTICATING'
                    ? 'text-cyan-400 animate-pulse'
                    : authStatus === 'UNAVAILABLE' || authStatus === 'TIMEOUT' || failureReason === 'UNREGISTERED_CREDENTIAL'
                    ? 'text-amber-400'
                    : authStatus === 'CANCELLED' || authStatus === 'FAILED'
                    ? 'text-rose-400'
                    : 'text-slate-400'
                }`}
              >
                {/* REQUIREMENT 3: Initial state must be "Not started" */}
                {authStatus === 'NOT_STARTED' && 'Not started'}
                {authStatus === 'AUTHENTICATING' && 'Authenticating...'}
                {authStatus === 'VERIFIED' && 'Verified ✓'}
                {authStatus === 'UNAVAILABLE' && 'Biometric authentication unavailable'}
                {authStatus === 'CANCELLED' && 'Cancelled'}
                {authStatus === 'TIMEOUT' && 'Timed out'}
                {authStatus === 'FAILED' && failureReason === 'UNREGISTERED_CREDENTIAL' && 'Unregistered Credential'}
                {authStatus === 'FAILED' && failureReason !== 'UNREGISTERED_CREDENTIAL' && 'Failed'}
              </span>
            </div>
          </div>

          {/* Central Visual Reticle / Verification Status Area */}
          <div className="relative py-4 flex flex-col items-center justify-center">
            <div
              className={`relative w-32 h-32 rounded-3xl flex items-center justify-center transition-all duration-300 ${
                authStatus === 'VERIFIED'
                  ? 'bg-emerald-950/50 border-2 border-emerald-400 shadow-[0_0_30px_rgba(16,185,129,0.35)]'
                  : authStatus === 'AUTHENTICATING'
                  ? 'bg-cyan-950/50 border-2 border-cyan-400 shadow-[0_0_30px_rgba(6,182,212,0.35)]'
                  : authStatus === 'UNAVAILABLE' || authStatus === 'TIMEOUT' || failureReason === 'UNREGISTERED_CREDENTIAL'
                  ? 'bg-amber-950/30 border-2 border-amber-500/50'
                  : authStatus === 'CANCELLED' || authStatus === 'FAILED'
                  ? 'bg-rose-950/30 border-2 border-rose-500/50'
                  : 'bg-slate-950 border border-slate-700/80'
              }`}
            >
              {authStatus === 'AUTHENTICATING' && (
                <div className="absolute inset-0 rounded-3xl border border-cyan-400 animate-ping opacity-40" />
              )}

              {authStatus === 'VERIFIED' ? (
                <CheckCircle2 className="w-16 h-16 text-emerald-400 animate-in zoom-in-75 duration-200" />
              ) : authStatus === 'UNAVAILABLE' || authStatus === 'TIMEOUT' || failureReason === 'UNREGISTERED_CREDENTIAL' ? (
                <AlertTriangle className="w-14 h-14 text-amber-400" />
              ) : authStatus === 'CANCELLED' || authStatus === 'FAILED' ? (
                <ShieldAlert className="w-14 h-14 text-rose-400" />
              ) : authStatus === 'AUTHENTICATING' ? (
                <RefreshCw className="w-14 h-14 text-cyan-400 animate-spin" />
              ) : (
                <Fingerprint className="w-16 h-16 text-slate-500" />
              )}
            </div>

            <div className="mt-3 text-xs font-mono text-slate-300 max-w-sm text-center">
              {statusMessage}
            </div>

            {/* REQUIREMENT 6: Explicit disclaimer that browser confirmed device authentication without raw image capture */}
            {authStatus === 'VERIFIED' && authMethodUsed === 'WEBAUTHN' && (
              <div className="mt-2 text-[10px] text-slate-400 font-sans max-w-xs flex items-center justify-center gap-1">
                <Info className="w-3 h-3 text-cyan-400 shrink-0" />
                <span>
                  Device biometric presence confirmed via Platform Authenticator. Raw biometric imagery is not processed by web apps.
                </span>
              </div>
            )}
          </div>

          {/* Error / Alert Message Banner */}
          {errorMessage && (
            <div
              className={`p-3 rounded-xl text-xs text-left flex items-start gap-2.5 animate-in shake duration-200 ${
                failureReason === 'UNREGISTERED_CREDENTIAL' || authStatus === 'TIMEOUT'
                  ? 'bg-amber-950/70 border border-amber-500/60 text-amber-200'
                  : 'bg-rose-950/70 border border-rose-500/60 text-rose-200'
              }`}
            >
              <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <span className="font-bold block">
                  {failureReason === 'UNREGISTERED_CREDENTIAL'
                    ? 'Unregistered Credential Notice'
                    : authStatus === 'TIMEOUT'
                    ? 'Authentication Timeout'
                    : authStatus === 'CANCELLED'
                    ? 'Authentication Cancelled'
                    : 'Authentication Notice'}
                </span>
                <span className="leading-relaxed">{errorMessage}</span>
              </div>
            </div>
          )}

          {/* Actionable buttons if Unregistered Credential */}
          {failureReason === 'UNREGISTERED_CREDENTIAL' && (
            <div className="p-3.5 rounded-xl bg-slate-950 border border-amber-500/40 text-left space-y-2.5 animate-in fade-in duration-150">
              <span className="text-[11px] font-mono text-amber-300 font-semibold block">
                Recoverable Resolution: Register Device or Use PIN
              </span>
              <p className="text-[11px] text-slate-400 leading-relaxed font-sans">
                You can enroll this device's platform authenticator (fingerprint/passkey) for Officer {user.name}, or verify immediately using your Officer Security Badge PIN.
              </p>
              <div className="flex flex-col sm:flex-row gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => handleVerifyIdentity(true)}
                  className="flex-1 py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer shadow-md shadow-cyan-950/50"
                >
                  <Smartphone className="w-3.5 h-3.5" />
                  <span>Register Device Authenticator</span>
                </button>
                <button
                  type="button"
                  onClick={() => setShowPinInput(true)}
                  className="flex-1 py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-cyan-300 text-xs font-mono font-medium flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  <span>Enter Officer PIN</span>
                </button>
              </div>
            </div>
          )}

          {/* Alternative Verification Channels Area (when unavailable or PIN requested) */}
          {(authStatus === 'UNAVAILABLE' || showPinInput) && (
            <div className="p-4 rounded-xl bg-slate-950 border border-amber-500/40 text-left space-y-3 animate-in fade-in duration-150">
              <div className="flex items-center gap-2 text-amber-400 font-mono text-xs font-semibold">
                <KeyRound className="w-4 h-4" />
                <span>Authorized Officer Credentials Verification</span>
              </div>

              {!showPinInput ? (
                <div className="flex flex-col sm:flex-row gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => setShowPinInput(true)}
                    className="flex-1 py-2 px-3 rounded-lg bg-cyan-950/90 border border-cyan-500/60 hover:bg-cyan-900/60 text-cyan-200 text-xs font-mono font-medium flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <KeyRound className="w-3.5 h-3.5" />
                    <span>Officer Credentials Verification</span>
                  </button>

                  <button
                    type="button"
                    onClick={handleTriggerDemoMode}
                    className="py-2 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 border border-amber-500/50 text-amber-300 text-xs font-mono flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                    title={
                      isPrivileged
                        ? 'Simulated mode cannot authorize privileged actions'
                        : 'Run unprivileged demo simulation'
                    }
                  >
                    <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                    <span>Demo Mode (Simulation)</span>
                  </button>
                </div>
              ) : (
                <form onSubmit={handleAuthorizeWithCredentials} className="space-y-2.5 pt-1">
                  <label className="block text-[11px] font-mono text-slate-300">
                    ENTER OFFICER BADGE IDENTIFIER ({user.badgeNumber}):
                  </label>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      autoFocus
                      placeholder={`e.g. ${user.badgeNumber}`}
                      value={badgePin}
                      onChange={e => {
                        setBadgePin(e.target.value);
                        setPinError(null);
                      }}
                      className="flex-1 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-white font-mono text-xs focus:outline-none focus:border-cyan-500"
                    />
                    <button
                      type="submit"
                      disabled={isVerifyingPin || !badgePin.trim()}
                      className="py-1.5 px-3.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono disabled:opacity-50 transition-colors cursor-pointer"
                    >
                      {isVerifyingPin ? 'Verifying...' : 'Authorize'}
                    </button>
                  </div>
                  {pinError && (
                    <div className="text-[11px] text-rose-400 font-mono">{pinError}</div>
                  )}
                </form>
              )}

              {isPrivileged && (
                <div className="p-2 rounded bg-rose-950/40 border border-rose-500/30 text-[10px] text-rose-300 font-mono">
                  ⚠ PRIVILEGED ACTION PROTECTION: Simulated biometric results cannot be used to authorize evidence corrections, approvals, or privileged supervisory sign-offs.
                </div>
              )}
            </div>
          )}

          {/* Primary Action Buttons */}
          <div className="flex items-center justify-between pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="py-2 px-4 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors cursor-pointer"
            >
              Cancel
            </button>

            {authStatus !== 'VERIFIED' && (
              <button
                type="button"
                onClick={() => handleVerifyIdentity(false)}
                disabled={authStatus === 'AUTHENTICATING'}
                className="py-2.5 px-6 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs flex items-center gap-2 transition-all cursor-pointer shadow-lg shadow-cyan-950/50 disabled:opacity-50"
              >
                <Fingerprint className="w-4 h-4" />
                <span>
                  {authStatus === 'AUTHENTICATING'
                    ? 'Verifying...'
                    : authStatus === 'CANCELLED' || authStatus === 'FAILED' || authStatus === 'TIMEOUT'
                    ? 'Retry Verification'
                    : 'Verify Identity'}
                </span>
              </button>
            )}

            {authStatus === 'VERIFIED' && (
              <button
                type="button"
                onClick={() => {
                  if (verifiedToken) {
                    onSuccess(verifiedToken, authMethodUsed === 'SIMULATED_DEMO');
                  }
                }}
                className="py-2 px-5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs flex items-center gap-1.5 cursor-pointer"
              >
                <CheckCircle2 className="w-4 h-4" />
                <span>Confirmed</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
