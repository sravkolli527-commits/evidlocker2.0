import React, { useState } from 'react';
import { User, UserRole } from '../types';
import { AuthService, ROLE_DETAILS } from '../services/authService';
import { FingerprintModal } from '../components/common/FingerprintModal';
import { CreativeBackground } from '../components/common/CreativeBackground';
import {
  Shield,
  KeyRound,
  Lock,
  Eye,
  EyeOff,
  UserPlus,
  LogIn,
  CheckCircle2,
  AlertCircle,
  Fingerprint,
  Sparkles,
  Building2,
  Mail,
  User as UserIcon,
  BadgeCheck,
  ArrowRight,
  RefreshCw,
  HelpCircle,
} from 'lucide-react';

interface LoginViewProps {
  users: User[];
  onSelectUser: (user: User) => void;
  onRefreshData?: () => void;
  initialMode?: 'signin' | 'signup';
}

const DEPARTMENT_PRESETS = [
  'Crime Scene First Response & Evidence Intake Unit',
  'Central Forensic Science Laboratory & Digital Ballistics Section',
  'Major Cyber & Forensic Investigation Division',
  'Chemical, Toxicology & DNA Analysis Division',
  'Judicial Liaison & Supervisory Oversight Division',
  'Department of Digital Security & Cryptographic Forensics',
  'Homicide & Special Operations Task Force',
];

export const LoginView: React.FC<LoginViewProps> = ({
  users,
  onSelectUser,
  onRefreshData,
  initialMode = 'signin',
}) => {
  const [mode, setMode] = useState<'signin' | 'signup'>(initialMode);

  // Sign In Form State - empty by default so user must enter valid credentials
  const [signInOfficerId, setSignInOfficerId] = useState('');
  const [signInPassword, setSignInPassword] = useState('');
  const [showSignInPassword, setShowSignInPassword] = useState(false);
  const [isSigningIn, setIsSigningIn] = useState(false);
  const [signInError, setSignInError] = useState<string | null>(null);

  // Sign Up Form State
  const [signUpOfficerId, setSignUpOfficerId] = useState('');
  const [signUpName, setSignUpName] = useState('');
  const [signUpRole, setSignUpRole] = useState<UserRole>('FIELD_OFFICER');
  const [signUpDepartment, setSignUpDepartment] = useState(DEPARTMENT_PRESETS[0]);
  const [signUpEmail, setSignUpEmail] = useState('');
  const [signUpPassword, setSignUpPassword] = useState('');
  const [signUpConfirmPassword, setSignUpConfirmPassword] = useState('');
  const [showSignUpPassword, setShowSignUpPassword] = useState(false);
  const [enrollBiometrics, setEnrollBiometrics] = useState(true);
  const [isSigningUp, setIsSigningUp] = useState(false);
  const [signUpError, setSignUpError] = useState<string | null>(null);
  const [signUpSuccess, setSignUpSuccess] = useState<string | null>(null);

  // Biometric Target Modal
  const [biometricTargetUser, setBiometricTargetUser] = useState<User | null>(null);

  // Calculate password strength
  const getPasswordStrength = (pwd: string) => {
    if (!pwd) return 0;
    let score = 0;
    if (pwd.length >= 6) score += 1;
    if (pwd.length >= 8) score += 1;
    if (/[A-Z]/.test(pwd)) score += 1;
    if (/[0-9]/.test(pwd)) score += 1;
    if (/[^A-Za-z0-9]/.test(pwd)) score += 1;
    return score;
  };

  const passwordScore = getPasswordStrength(signUpPassword);

  // Auto-generate an Officer ID based on role
  const generateOfficerId = (role: UserRole) => {
    const prefixes: Record<UserRole, string> = {
      FIELD_OFFICER: 'FO',
      FORENSIC_OFFICER: 'FSO',
      INVESTIGATOR: 'INV',
      HIGHER_OFFICIAL: 'HO',
      ADMINISTRATOR: 'ADM',
    };
    const randomNum = Math.floor(1000 + Math.random() * 9000);
    const generated = `${prefixes[role]}-${randomNum}`;
    setSignUpOfficerId(generated);
    if (!signUpEmail || signUpEmail.includes('@forensics.gov.in')) {
      setSignUpEmail(`${generated.toLowerCase()}@forensics.gov.in`);
    }
  };

  // Quick fill credential helper for demo testing
  const handleQuickFill = (user: User) => {
    setSignInOfficerId(user.badgeNumber);
    setSignInPassword(user.password || 'Officer@2026');
    setSignInError(null);
  };

  // Handle Sign In submission
  const handleSignInSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSignInError(null);

    if (!signInOfficerId.trim()) {
      setSignInError('Please enter your Officer Unique ID or Badge Number.');
      return;
    }
    if (!signInPassword.trim()) {
      setSignInError('Please enter your password.');
      return;
    }

    setIsSigningIn(true);
    try {
      const authenticatedUser = await AuthService.loginWithCredentials(
        signInOfficerId.trim(),
        signInPassword.trim()
      );
      if (onRefreshData) onRefreshData();
      onSelectUser(authenticatedUser);
    } catch (err: any) {
      setSignInError(err?.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setIsSigningIn(false);
    }
  };

  // Handle Sign Up submission
  const handleSignUpSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSignUpError(null);
    setSignUpSuccess(null);

    if (!signUpOfficerId.trim()) {
      setSignUpError('Please enter or generate an Officer Unique ID.');
      return;
    }
    if (!signUpName.trim()) {
      setSignUpError('Please enter the officer full name.');
      return;
    }
    if (signUpPassword.length < 6) {
      setSignUpError('Password must be at least 6 characters in length.');
      return;
    }
    if (signUpPassword !== signUpConfirmPassword) {
      setSignUpError('Passwords do not match. Please re-enter.');
      return;
    }

    setIsSigningUp(true);
    try {
      const newUser = await AuthService.registerOfficer({
        officerId: signUpOfficerId.trim().toUpperCase(),
        name: signUpName.trim(),
        password: signUpPassword.trim(),
        role: signUpRole,
        department: signUpDepartment,
        email: signUpEmail.trim() || `${signUpOfficerId.trim().toLowerCase()}@forensics.gov.in`,
      });

      setSignUpSuccess(`Officer ${newUser.name} (ID: ${newUser.badgeNumber}) registered successfully!`);
      if (onRefreshData) onRefreshData();

      // Automatically sign in the newly registered officer after a brief moment
      setTimeout(() => {
        onSelectUser(newUser);
      }, 1200);
    } catch (err: any) {
      setSignUpError(err?.message || 'Failed to register officer. Please try again.');
    } finally {
      setIsSigningUp(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#030712] relative flex flex-col justify-center items-center p-4 selection:bg-cyan-500/20 selection:text-cyan-300">
      <CreativeBackground />

      <div className="max-w-4xl w-full space-y-6 animate-in fade-in duration-200 relative z-10 py-8">
        {/* Top Brand Banner */}
        <div className="text-center space-y-2">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-cyan-600 to-blue-700 flex items-center justify-center text-white shadow-2xl shadow-cyan-900/50 border border-cyan-400/40 mx-auto">
            <Shield className="w-7 h-7 text-cyan-100" />
          </div>

          <div>
            <div className="flex items-center justify-center gap-2">
              <h1 className="text-2xl sm:text-3xl font-extrabold tracking-wider text-white font-mono">
                DIGITAL EVIDENCE GUARDIAN
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-600 font-semibold">
                CJIS-COMPLIANT
              </span>
            </div>
            <p className="text-xs font-semibold text-cyan-400 font-mono tracking-widest mt-1">
              LAW ENFORCEMENT TERMINAL · IMMUTABLE CHAIN OF CUSTODY
            </p>
          </div>
        </div>

        {/* Mode Toggle Tabs: Sign In vs Sign Up */}
        <div className="flex justify-center">
          <div className="bg-slate-900/90 p-1.5 rounded-xl border border-slate-800 backdrop-blur-xl flex items-center gap-1.5 shadow-xl max-w-md w-full">
            <button
              type="button"
              onClick={() => {
                setMode('signin');
                setSignInError(null);
              }}
              className={`flex-1 py-2.5 px-4 rounded-lg font-mono text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer ${
                mode === 'signin'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-lg shadow-cyan-950/50'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <LogIn className="w-4 h-4" />
              <span>Officer Sign In</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setMode('signup');
                setSignUpError(null);
                if (!signUpOfficerId) generateOfficerId(signUpRole);
              }}
              className={`flex-1 py-2.5 px-4 rounded-lg font-mono text-xs font-bold transition-all flex items-center justify-center gap-2 cursor-pointer ${
                mode === 'signup'
                  ? 'bg-gradient-to-r from-cyan-600 to-blue-600 text-white shadow-lg shadow-cyan-950/50'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <UserPlus className="w-4 h-4" />
              <span>Register Officer</span>
            </button>
          </div>
        </div>

        {/* ============================================================ */}
        {/* SIGN IN VIEW */}
        {/* ============================================================ */}
        {mode === 'signin' && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Left Column: Sign In Form */}
            <div className="lg:col-span-7 bg-slate-900/85 border border-slate-800/90 rounded-2xl p-6 sm:p-7 backdrop-blur-xl shadow-2xl space-y-5">
              <div className="border-b border-slate-800 pb-3 flex items-center justify-between">
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2 font-mono">
                    <KeyRound className="w-4 h-4 text-cyan-400" />
                    <span>Officer Access Authorization</span>
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Authenticate using your unique law enforcement ID and password.
                  </p>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-cyan-400 border border-slate-800">
                  SHA-256 Auth
                </span>
              </div>

              {signInError && (
                <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-500/50 text-rose-200 text-xs flex items-start gap-2.5 animate-in fade-in">
                  <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="flex-1 leading-relaxed">{signInError}</div>
                </div>
              )}

              <form onSubmit={handleSignInSubmit} className="space-y-4">
                {/* Officer Unique ID Field */}
                <div>
                  <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <BadgeCheck className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Officer Unique ID / Badge Number</span>
                    </span>
                    <span className="text-[10px] text-slate-500">e.g. FO-8841</span>
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      value={signInOfficerId}
                      onChange={e => setSignInOfficerId(e.target.value)}
                      placeholder="e.g. FO-8841, INV-4029, ADM-0001"
                      className="w-full bg-slate-950/80 border border-slate-700 focus:border-cyan-400 rounded-lg py-2.5 pl-3.5 pr-10 text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all uppercase"
                      required
                    />
                    <div className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 font-mono text-[10px]">
                      ID
                    </div>
                  </div>
                </div>

                {/* Password Field */}
                <div>
                  <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Officer Security Password</span>
                    </span>
                    <span className="text-[10px] text-cyan-400/80 font-mono">
                      Default: Officer@2026
                    </span>
                  </label>
                  <div className="relative">
                    <input
                      type={showSignInPassword ? 'text' : 'password'}
                      value={signInPassword}
                      onChange={e => setSignInPassword(e.target.value)}
                      placeholder="Enter officer security password"
                      className="w-full bg-slate-950/80 border border-slate-700 focus:border-cyan-400 rounded-lg py-2.5 pl-3.5 pr-10 text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowSignInPassword(!showSignInPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                      title={showSignInPassword ? 'Hide password' : 'Show password'}
                    >
                      {showSignInPassword ? (
                        <EyeOff className="w-4 h-4" />
                      ) : (
                        <Eye className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                </div>

                {/* Demo Helper Banner */}
                <div className="p-3 rounded-lg bg-cyan-950/40 border border-cyan-800/40 flex items-center justify-between text-[11px] text-cyan-300">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Demo Terminal Master Password:</span>
                  </div>
                  <code className="bg-slate-950 px-2 py-0.5 rounded border border-cyan-800 text-cyan-300 font-mono font-bold">
                    Officer@2026
                  </code>
                </div>

                {/* Submit Action */}
                <button
                  type="submit"
                  disabled={isSigningIn}
                  className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-600 hover:from-cyan-500 to-blue-600 hover:to-blue-500 text-white font-mono text-sm font-bold flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/50 transition-all cursor-pointer disabled:opacity-50"
                >
                  {isSigningIn ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-cyan-200" />
                      <span>Authenticating Officer...</span>
                    </>
                  ) : (
                    <>
                      <LogIn className="w-4 h-4" />
                      <span>Unlock Law Enforcement Terminal</span>
                      <ArrowRight className="w-4 h-4 ml-1" />
                    </>
                  )}
                </button>
              </form>

              {/* Biometric Quick Hardware Verification Shortcut */}
              <div className="pt-3 border-t border-slate-800/80">
                <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                  <span className="font-mono text-[11px] uppercase tracking-wider">
                    Or Verify Hardware Biometrics:
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setBiometricTargetUser(users[0])}
                  className="w-full py-2.5 px-3 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-900 text-slate-300 font-mono text-xs flex items-center justify-center gap-2 transition-all cursor-pointer"
                >
                  <Fingerprint className="w-4 h-4 text-cyan-400 animate-pulse" />
                  <span>Verify Identity via Platform Biometric Sensor</span>
                </button>
              </div>
            </div>

            {/* Right Column: Pre-configured Officer Quick-Switch Matrix */}
            <div className="lg:col-span-5 bg-slate-900/85 border border-slate-800/90 rounded-2xl p-6 backdrop-blur-xl shadow-2xl space-y-3.5">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                <div>
                  <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                    Active Duty Personnel Roster
                  </h3>
                  <p className="text-[11px] text-slate-400">
                    Click any officer to auto-populate credentials
                  </p>
                </div>
                <span className="text-[10px] font-mono text-cyan-400">
                  1-Click Select
                </span>
              </div>

              <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
                {users.map(u => {
                  const rConf = ROLE_DETAILS[u.role] || {
                    label: u.role,
                    badgeClass: 'text-slate-400 border-slate-700 bg-slate-800',
                  };
                  const isSelected = signInOfficerId.toUpperCase() === u.badgeNumber.toUpperCase();

                  return (
                    <div
                      key={u.id}
                      onClick={() => handleQuickFill(u)}
                      className={`p-3 rounded-xl border transition-all cursor-pointer group flex flex-col justify-between ${
                        isSelected
                          ? 'bg-cyan-950/60 border-cyan-500/70 shadow-md shadow-cyan-950/40 ring-1 ring-cyan-500/30'
                          : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 hover:bg-slate-950'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-semibold text-xs text-white group-hover:text-cyan-300 transition-colors truncate">
                              {u.name}
                            </span>
                            {isSelected && (
                              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                            )}
                          </div>
                          <div className="text-[11px] font-mono text-cyan-400 flex items-center gap-1.5 mt-0.5">
                            <span className="bg-slate-900 px-1.5 py-0.2 rounded border border-slate-700 text-white font-bold">
                              {u.badgeNumber}
                            </span>
                            <span className="text-slate-500">·</span>
                            <span>{rConf.label}</span>
                          </div>
                        </div>

                        <span
                          className={`text-[9px] font-mono px-2 py-0.5 rounded border shrink-0 ${rConf.badgeClass}`}
                        >
                          {u.role.replace('_', ' ')}
                        </span>
                      </div>

                      <div className="text-[10px] text-slate-400 truncate mt-1">
                        {u.department}
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 text-[10px] text-slate-400 font-mono space-y-1">
                <div className="text-slate-300 font-semibold flex items-center gap-1">
                  <Shield className="w-3 h-3 text-cyan-400" />
                  <span>Role Permissions:</span>
                </div>
                <div>• Field Officer: Register evidence & lock photos</div>
                <div>• Forensic Officer: Lab analyses & certify forensic findings</div>
                <div>• Investigator: Track chain of custody movement</div>
                <div>• Higher Official: Approve/reject modifications</div>
                <div>• Administrator: Full ledger audit & user control</div>
              </div>

              <div className="pt-2 text-center">
                <button
                  type="button"
                  onClick={() => {
                    setMode('signup');
                    generateOfficerId('FIELD_OFFICER');
                  }}
                  className="text-xs text-cyan-400 hover:text-cyan-300 font-mono inline-flex items-center gap-1 transition-colors cursor-pointer"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  <span>Not in roster? Register new officer</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ============================================================ */}
        {/* SIGN UP / REGISTER OFFICER VIEW */}
        {/* ============================================================ */}
        {mode === 'signup' && (
          <div className="bg-slate-900/85 border border-slate-800/90 rounded-2xl p-6 sm:p-8 backdrop-blur-xl shadow-2xl space-y-6 max-w-2xl mx-auto">
            <div className="border-b border-slate-800 pb-4">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-bold text-white flex items-center gap-2 font-mono">
                  <UserPlus className="w-5 h-5 text-cyan-400" />
                  <span>Law Enforcement Officer Registration</span>
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-700">
                  New Credential
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Provision a unique officer ID, role privileges, and cryptographic password into the duty roster.
              </p>
            </div>

            {signUpError && (
              <div className="p-3.5 rounded-lg bg-rose-950/60 border border-rose-500/50 text-rose-200 text-xs flex items-start gap-2.5 animate-in fade-in">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <div className="flex-1 leading-relaxed">{signUpError}</div>
              </div>
            )}

            {signUpSuccess && (
              <div className="p-3.5 rounded-lg bg-emerald-950/60 border border-emerald-500/50 text-emerald-200 text-xs flex items-center gap-2.5 animate-in fade-in">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <div className="flex-1 font-mono">{signUpSuccess}</div>
              </div>
            )}

            <form onSubmit={handleSignUpSubmit} className="space-y-4.5">
              {/* Operational Role Selector Cards */}
              <div>
                <label className="block text-xs font-mono font-medium text-slate-300 mb-2">
                  Select Law Enforcement Role & Authority Level *
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
                  {(
                    [
                      'FIELD_OFFICER',
                      'FORENSIC_OFFICER',
                      'INVESTIGATOR',
                      'HIGHER_OFFICIAL',
                      'ADMINISTRATOR',
                    ] as UserRole[]
                  ).map(roleOption => {
                    const rConf = ROLE_DETAILS[roleOption];
                    const isSelected = signUpRole === roleOption;

                    return (
                      <div
                        key={roleOption}
                        onClick={() => {
                          setSignUpRole(roleOption);
                          generateOfficerId(roleOption);
                        }}
                        className={`p-3 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                          isSelected
                            ? 'bg-cyan-950/70 border-cyan-400 text-white shadow-md shadow-cyan-950/40 ring-1 ring-cyan-500/50'
                            : 'bg-slate-950/70 border-slate-800 text-slate-400 hover:border-slate-700'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-xs text-white">
                            {rConf.label}
                          </span>
                          <span
                            className={`text-[9px] font-mono px-1.5 py-0.2 rounded border ${rConf.badgeClass}`}
                          >
                            {roleOption.slice(0, 3)}
                          </span>
                        </div>
                        <p className="text-[10px] text-slate-400 leading-tight">
                          {roleOption === 'FIELD_OFFICER' && 'Crime scene intake & evidence tagging'}
                          {roleOption === 'FORENSIC_OFFICER' && 'Lab testing, ballistics & evidence certification'}
                          {roleOption === 'INVESTIGATOR' && 'Case detective & forensic custody movement'}
                          {roleOption === 'HIGHER_OFFICIAL' && 'Supervisory approval for modification'}
                          {roleOption === 'ADMINISTRATOR' && 'Full user & cryptographic audit authority'}
                        </p>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Officer Unique ID & Full Name in 2 columns */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Officer Unique ID */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-mono font-medium text-slate-300 flex items-center gap-1.5">
                      <BadgeCheck className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Officer Unique ID *</span>
                    </label>
                    <button
                      type="button"
                      onClick={() => generateOfficerId(signUpRole)}
                      className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer"
                      title="Generate unique badge identifier"
                    >
                      <RefreshCw className="w-3 h-3" />
                      <span>Auto-Gen</span>
                    </button>
                  </div>
                  <input
                    type="text"
                    value={signUpOfficerId}
                    onChange={e => setSignUpOfficerId(e.target.value.toUpperCase())}
                    placeholder="e.g. FO-9412 or OFFICER-7801"
                    className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg py-2.5 px-3 text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all uppercase"
                    required
                  />
                </div>

                {/* Full Name & Rank */}
                <div>
                  <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                    <UserIcon className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Officer Full Name & Title *</span>
                  </label>
                  <input
                    type="text"
                    value={signUpName}
                    onChange={e => setSignUpName(e.target.value)}
                    placeholder="e.g. Officer Daniel Craig"
                    className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg py-2.5 px-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                    required
                  />
                </div>
              </div>

              {/* Department & Email in 2 columns */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Department */}
                <div>
                  <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                    <Building2 className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Assigned Department / Division</span>
                  </label>
                  <select
                    value={signUpDepartment}
                    onChange={e => setSignUpDepartment(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg py-2.5 px-3 text-xs text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                  >
                    {DEPARTMENT_PRESETS.map(dept => (
                      <option key={dept} value={dept}>
                        {dept}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Email */}
                <div>
                  <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                    <Mail className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Official Police Email</span>
                  </label>
                  <input
                    type="email"
                    value={signUpEmail}
                    onChange={e => setSignUpEmail(e.target.value)}
                    placeholder="e.g. officer@forensics.gov.in"
                    className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg py-2.5 px-3 text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                  />
                </div>
              </div>

              {/* Password & Confirm Password in 2 columns */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Password */}
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="text-xs font-mono font-medium text-slate-300 flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Officer Password *</span>
                    </label>
                    <span className="text-[10px] text-slate-500">Min 6 chars</span>
                  </div>
                  <div className="relative">
                    <input
                      type={showSignUpPassword ? 'text' : 'password'}
                      value={signUpPassword}
                      onChange={e => setSignUpPassword(e.target.value)}
                      placeholder="Create secure password"
                      className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg py-2.5 pl-3 pr-10 text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowSignUpPassword(!showSignUpPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                    >
                      {showSignUpPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {/* Strength indicator */}
                  {signUpPassword && (
                    <div className="mt-1.5 flex items-center gap-1">
                      {[1, 2, 3, 4, 5].map(level => (
                        <div
                          key={level}
                          className={`h-1 flex-1 rounded-full transition-colors ${
                            passwordScore >= level
                              ? passwordScore <= 2
                                ? 'bg-amber-400'
                                : 'bg-emerald-400'
                              : 'bg-slate-800'
                          }`}
                        />
                      ))}
                      <span className="text-[10px] font-mono text-slate-400 ml-1">
                        {passwordScore <= 2 ? 'Fair' : passwordScore <= 4 ? 'Good' : 'Strong'}
                      </span>
                    </div>
                  )}
                </div>

                {/* Confirm Password */}
                <div>
                  <label className="block text-xs font-mono font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                    <span className="flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                      <span>Confirm Password *</span>
                    </span>
                    {signUpConfirmPassword && signUpPassword === signUpConfirmPassword && (
                      <span className="text-[10px] text-emerald-400 font-mono flex items-center gap-0.5">
                        <CheckCircle2 className="w-3 h-3" /> Matches
                      </span>
                    )}
                  </label>
                  <input
                    type={showSignUpPassword ? 'text' : 'password'}
                    value={signUpConfirmPassword}
                    onChange={e => setSignUpConfirmPassword(e.target.value)}
                    placeholder="Repeat password"
                    className={`w-full bg-slate-950 border rounded-lg py-2.5 px-3 text-sm text-white placeholder-slate-500 font-mono focus:outline-none focus:ring-1 transition-all ${
                      signUpConfirmPassword && signUpPassword !== signUpConfirmPassword
                        ? 'border-rose-500 focus:ring-rose-500'
                        : 'border-slate-700 focus:border-cyan-400 focus:ring-cyan-500'
                    }`}
                    required
                  />
                </div>
              </div>

              {/* Hardware Biometrics Checkbox */}
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Fingerprint className="w-4 h-4 text-cyan-400" />
                  <div>
                    <div className="text-xs font-semibold text-white">
                      Enroll Platform Biometrics & Hardware Key
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Enables Touch ID / WebAuthn passkey authentication for this terminal.
                    </div>
                  </div>
                </div>
                <input
                  type="checkbox"
                  checked={enrollBiometrics}
                  onChange={e => setEnrollBiometrics(e.target.checked)}
                  className="w-4 h-4 rounded text-cyan-500 bg-slate-900 border-slate-700 focus:ring-cyan-400 cursor-pointer"
                />
              </div>

              {/* Submit Button */}
              <div className="pt-2">
                <button
                  type="submit"
                  disabled={isSigningUp}
                  className="w-full py-3 px-4 rounded-xl bg-gradient-to-r from-cyan-600 hover:from-cyan-500 to-blue-600 hover:to-blue-500 text-white font-mono text-sm font-bold flex items-center justify-center gap-2 shadow-lg shadow-cyan-950/50 transition-all cursor-pointer disabled:opacity-50"
                >
                  {isSigningUp ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-cyan-200" />
                      <span>Registering Officer Credentials...</span>
                    </>
                  ) : (
                    <>
                      <UserPlus className="w-4 h-4" />
                      <span>Register Officer & Unlock Terminal Access</span>
                      <ArrowRight className="w-4 h-4 ml-1" />
                    </>
                  )}
                </button>
              </div>

              {/* Switch back to Sign In */}
              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setMode('signin');
                    setSignUpError(null);
                  }}
                  className="text-xs text-slate-400 hover:text-cyan-300 font-mono transition-colors cursor-pointer"
                >
                  Already have an Officer ID? <span className="text-cyan-400 underline underline-offset-2">Sign in to terminal</span>
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Global Terminal Footer */}
        <div className="text-center text-[11px] font-mono text-slate-500 space-y-1">
          <div>
            DIGITAL EVIDENCE GUARDIAN · LAW ENFORCEMENT ACCESS CONTROL
          </div>
          <div>
            Tamper-evident chain of custody · Dual-custody authorization · Zero silent modifications
          </div>
        </div>

        {/* Biometric Verification Modal */}
        {biometricTargetUser && (
          <FingerprintModal
            isOpen={!!biometricTargetUser}
            user={biometricTargetUser}
            actionTitle="Law Enforcement Identity Verification"
            actionDescription="Verify device identity or authorized officer credentials to unlock terminal access."
            onClose={() => setBiometricTargetUser(null)}
            onSuccess={() => {
              const u = biometricTargetUser;
              setBiometricTargetUser(null);
              onSelectUser(u);
            }}
          />
        )}
      </div>
    </div>
  );
};
