import React, { useState } from 'react';
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  Lock,
  Mail,
  ShieldCheck,
  User as UserIcon,
} from 'lucide-react';
import { User, UserRole } from '../types';
import {
  apiAuthForgotLookup,
  apiAuthLogin,
  apiAuthRegister,
  apiAuthResetPassword,
} from '../lib/storage';

interface AuthScreenProps {
  onLogin: (user: User, token: string) => void;
  initialEmail?: string;
}

type AuthMode = 'signin' | 'signup' | 'forgot';

const SECURITY_QUESTIONS = [
  'What is your secret 4-to-8 digit Recovery PIN?',
  'What is your birth city or hometown?',
  'What was the name of your first project site?',
  "What is your mother's maiden name?",
];

export const AuthScreen: React.FC<AuthScreenProps> = ({ onLogin, initialEmail = '' }) => {
  const [authMode, setAuthMode] = useState<AuthMode>('signin');
  const [email, setEmail] = useState(initialEmail);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [role, setRole] = useState<UserRole>('ADMIN');

  // Signup recovery setup
  const [securityQuestion, setSecurityQuestion] = useState(SECURITY_QUESTIONS[0]);
  const [securityAnswer, setSecurityAnswer] = useState('');
  const [showSecurityAnswer, setShowSecurityAnswer] = useState(false);

  // Forgot password 2-step flow
  const [forgotStep, setForgotStep] = useState<1 | 2>(1);
  const [forgotLookupName, setForgotLookupName] = useState('');
  const [forgotQuestion, setForgotQuestion] = useState('');
  const [forgotAnswer, setForgotAnswer] = useState('');
  const [showForgotAnswer, setShowForgotAnswer] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmNewPassword, setConfirmNewPassword] = useState('');
  const [showNewPassword, setShowNewPassword] = useState(false);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const switchMode = (nextMode: AuthMode) => {
    setAuthMode(nextMode);
    setErrorMessage('');
    setSuccessMessage('');
    if (nextMode === 'forgot') {
      setForgotStep(1);
      setForgotLookupName('');
      setForgotQuestion('');
      setForgotAnswer('');
      setNewPassword('');
      setConfirmNewPassword('');
    }
  };

  const validateFields = (requireName: boolean): string | null => {
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return 'Please enter a valid email address.';
    }
    if (requireName && name.trim().length < 2) {
      return 'Please enter your full name (at least 2 characters).';
    }
    if (!password) {
      return 'Please enter your password.';
    }
    if (requireName && password.length < 6) {
      return 'Password must be at least 6 characters long.';
    }
    if (requireName && securityAnswer.trim().length < 2) {
      return 'Please enter a Security Answer or Recovery PIN (at least 2 characters) for password recovery.';
    }
    return null;
  };

  const authenticateUser = async (provider: 'password' | 'google') => {
    setErrorMessage('');
    setSuccessMessage('');
    const isSignUp = authMode === 'signup';
    const validationError = validateFields(isSignUp);
    if (validationError) {
      setErrorMessage(validationError);
      return;
    }

    const cleanEmail = email.trim().toLowerCase();
    setIsSubmitting(true);
    try {
      if (isSignUp) {
        const res = await apiAuthRegister({
          name: name.trim(),
          email: cleanEmail,
          password,
          role,
          provider,
          securityQuestion,
          securityAnswer: securityAnswer.trim(),
        });
        onLogin(res.user, res.token);
      } else {
        const res = await apiAuthLogin({
          email: cleanEmail,
          password,
        });
        onLogin(res.user, res.token);
      }
    } catch (err: any) {
      setErrorMessage(err?.message || 'Authentication failed. Please check your email and password.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    authenticateUser('password');
  };

  const handleGoogleAuth = () => {
    setErrorMessage('');
    setSuccessMessage('');
    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      setErrorMessage('Please enter your Google Email address below first.');
      return;
    }
    if (!password) {
      setErrorMessage(
        authMode === 'signup'
          ? 'Please enter a password (min 6 characters) to secure your Google email workspace.'
          : 'Please enter the password for your Google email account.'
      );
      return;
    }
    authenticateUser('google');
  };

  const handleForgotLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    const cleanEmail = email.trim().toLowerCase();
    if (!cleanEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      setErrorMessage('Please enter your registered email address.');
      return;
    }

    setIsSubmitting(true);
    try {
      const data = await apiAuthForgotLookup(cleanEmail);
      setForgotLookupName(data.name);
      setForgotQuestion(data.securityQuestion);
      setForgotStep(2);
    } catch (err: any) {
      setErrorMessage(err?.message || 'Could not locate an account with that email address.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleForgotReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');

    const cleanEmail = email.trim().toLowerCase();
    if (!forgotAnswer.trim()) {
      setErrorMessage('Please enter your Security Answer or Recovery PIN.');
      return;
    }
    if (newPassword.length < 6) {
      setErrorMessage('New password must be at least 6 characters long.');
      return;
    }
    if (newPassword !== confirmNewPassword) {
      setErrorMessage('New password and confirmation do not match.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await apiAuthResetPassword({
        email: cleanEmail,
        securityAnswer: forgotAnswer.trim(),
        newPassword,
      });
      setAuthMode('signin');
      setPassword('');
      setForgotStep(1);
      setForgotAnswer('');
      setNewPassword('');
      setConfirmNewPassword('');
      setSuccessMessage(res.message || 'Password updated successfully. You can now Sign In.');
    } catch (err: any) {
      setErrorMessage(err?.message || 'Unable to verify recovery answer or update password.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070b14] flex flex-col justify-center items-center p-4 relative overflow-hidden font-sans">
      {/* Subtle Background Accents */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-amber-500/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-25 pointer-events-none" />

      {/* Main Centered Auth Card */}
      <div className="w-full max-w-md bg-slate-900/90 border border-slate-800 backdrop-blur-xl rounded-3xl p-8 shadow-2xl relative z-10 space-y-5">
        {/* Brand Header */}
        <div className="text-center space-y-2.5">
          <div className="w-16 h-16 rounded-2xl overflow-hidden border border-amber-500/30 shadow-lg shadow-amber-500/20 mx-auto bg-slate-950">
            <img
              src="/sr-erp-icon.jpg"
              alt="SR GROUP ERP Logo"
              referrerPolicy="no-referrer"
              className="w-full h-full object-cover"
            />
          </div>
          <div>
            <h1 className="text-xl font-extrabold text-white tracking-tight">SR GROUP ERP</h1>
            <p className="text-xs text-amber-400/90 font-mono tracking-wider font-semibold uppercase mt-0.5">
              Engineering Operations &amp; Billing 2026
            </p>
          </div>
          <p className="text-xs text-slate-400 pt-0.5">
            {authMode === 'signup'
              ? 'Create a verified account with your email and password. Your workspace data stays saved securely.'
              : authMode === 'forgot'
                ? forgotStep === 1
                  ? 'Enter your registered email address to verify your recovery question.'
                  : 'Answer your security question and set a new password.'
                : 'Sign in with your registered email and password to access your saved workspace.'}
          </p>
        </div>

        {/* Mode Switcher Tabs: Sign In vs Create Account */}
        {authMode !== 'forgot' ? (
          <div className="grid grid-cols-2 gap-1.5 bg-slate-950 p-1 rounded-xl border border-slate-800 text-xs font-semibold">
            <button
              type="button"
              onClick={() => switchMode('signin')}
              className={`py-2 rounded-lg transition cursor-pointer ${
                authMode === 'signin'
                  ? 'bg-amber-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => switchMode('signup')}
              className={`py-2 rounded-lg transition cursor-pointer ${
                authMode === 'signup'
                  ? 'bg-amber-500 text-slate-950 font-bold shadow-sm'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Create Account
            </button>
          </div>
        ) : (
          <div className="flex items-center justify-between text-xs border-b border-slate-800 pb-3">
            <button
              type="button"
              onClick={() => switchMode('signin')}
              className="inline-flex items-center gap-1.5 text-slate-400 hover:text-amber-400 font-semibold transition cursor-pointer"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Sign In</span>
            </button>
            <span className="text-[11px] font-mono text-slate-400 tabular-nums">
              Step {forgotStep} of 2
            </span>
          </div>
        )}

        {/* Success notification */}
        {successMessage && (
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
            <span>{successMessage}</span>
          </div>
        )}

        {/* Error notification */}
        {errorMessage && (
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-start gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <span>{errorMessage}</span>
              {authMode === 'signin' && errorMessage.toLowerCase().includes('no account found') && (
                <div>
                  <button
                    type="button"
                    onClick={() => switchMode('signup')}
                    className="text-amber-400 underline font-semibold hover:text-amber-300 cursor-pointer"
                  >
                    Switch to Create Account →
                  </button>
                </div>
              )}
              {authMode === 'signin' && errorMessage.toLowerCase().includes('incorrect password') && (
                <div>
                  <button
                    type="button"
                    onClick={() => switchMode('forgot')}
                    className="text-amber-400 underline font-semibold hover:text-amber-300 cursor-pointer"
                  >
                    Reset via Forgot Password →
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* SIGN IN & CREATE ACCOUNT FORM */}
        {authMode !== 'forgot' && (
          <>
            <form onSubmit={handleSubmit} className="space-y-4 text-xs">
              {authMode === 'signup' && (
                <div>
                  <label className="text-slate-400 block mb-1 font-semibold">Full Name</label>
                  <div className="relative">
                    <UserIcon className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                    <input
                      type="text"
                      required
                      placeholder="Enter your full name"
                      value={name}
                      onChange={(e) => {
                        setName(e.target.value);
                        setErrorMessage('');
                      }}
                      className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                    />
                  </div>
                </div>
              )}

              <div>
                <label className="text-slate-400 block mb-1 font-semibold">Email Address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                  <input
                    type="email"
                    required
                    autoComplete="email"
                    placeholder="Enter your email address"
                    value={email}
                    onChange={(e) => {
                      setEmail(e.target.value);
                      setErrorMessage('');
                    }}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-slate-400 font-semibold">
                    Password{' '}
                    {authMode === 'signup' && (
                      <span className="text-slate-500 font-normal">(min 6 characters)</span>
                    )}
                  </label>
                  {authMode === 'signin' && (
                    <button
                      type="button"
                      onClick={() => switchMode('forgot')}
                      className="text-amber-400 hover:text-amber-300 font-semibold text-[11px] transition cursor-pointer"
                    >
                      Forgot Password?
                    </button>
                  )}
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    required
                    autoComplete={authMode === 'signup' ? 'new-password' : 'current-password'}
                    placeholder="Enter your password"
                    value={password}
                    onChange={(e) => {
                      setPassword(e.target.value);
                      setErrorMessage('');
                    }}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-10 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {authMode === 'signup' && (
                <>
                  <div>
                    <label className="text-slate-400 block mb-1 font-semibold">System Role</label>
                    <select
                      value={role}
                      onChange={(e) => setRole(e.target.value as UserRole)}
                      className="w-full bg-slate-950 border border-slate-700 rounded-xl p-2.5 text-white focus:outline-none focus:border-amber-500"
                    >
                      <option value="ADMIN">Super Admin (Full Access)</option>
                      <option value="MANAGER">Project &amp; Billing Manager</option>
                      <option value="ACCOUNTANT">Billing &amp; Site Accountant</option>
                      <option value="SUPERVISOR">Site Supervisor</option>
                    </select>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 space-y-2.5">
                    <div className="flex items-center gap-1.5 text-[11px] font-semibold text-amber-400">
                      <KeyRound className="w-3.5 h-3.5 shrink-0" />
                      <span>Password Recovery Setup</span>
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1 text-[11px]">Security Question</label>
                      <select
                        value={securityQuestion}
                        onChange={(e) => setSecurityQuestion(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-2 text-xs text-white focus:outline-none focus:border-amber-500"
                      >
                        {SECURITY_QUESTIONS.map((q) => (
                          <option key={q} value={q}>
                            {q}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="text-slate-400 block mb-1 text-[11px]">
                        Security Answer / Recovery PIN
                      </label>
                      <div className="relative">
                        <input
                          type={showSecurityAnswer ? 'text' : 'password'}
                          required
                          placeholder="Remember this to reset password later"
                          value={securityAnswer}
                          onChange={(e) => {
                            setSecurityAnswer(e.target.value);
                            setErrorMessage('');
                          }}
                          className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-3 pr-9 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                        />
                        <button
                          type="button"
                          onClick={() => setShowSecurityAnswer(!showSecurityAnswer)}
                          className="absolute right-2.5 top-2 text-slate-500 hover:text-slate-300 cursor-pointer"
                          aria-label={showSecurityAnswer ? 'Hide answer' : 'Show answer'}
                        >
                          {showSecurityAnswer ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  </div>
                </>
              )}

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-3 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-amber-500/20 active:scale-[0.99] disabled:opacity-50 cursor-pointer"
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Verifying...</span>
                  </>
                ) : (
                  <>
                    <span>
                      {authMode === 'signup' ? 'Create Account & Open Workspace' : 'Sign In to Workspace'}
                    </span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            {/* Continue with Google option */}
            <div className="space-y-3">
              <div className="flex items-center gap-3">
                <div className="flex-1 h-px bg-slate-800" />
                <span className="text-[10px] font-mono uppercase text-slate-500">or with Google Email</span>
                <div className="flex-1 h-px bg-slate-800" />
              </div>

              <button
                type="button"
                disabled={isSubmitting}
                onClick={handleGoogleAuth}
                className="w-full py-2.5 px-4 bg-white hover:bg-slate-100 text-slate-900 font-semibold text-xs rounded-xl transition flex items-center justify-center gap-3 shadow-md hover:shadow-lg active:scale-[0.99] disabled:opacity-50 cursor-pointer"
              >
                <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                <span>
                  {authMode === 'signup' ? 'Register Google Email & Password' : 'Continue with Google Email'}
                </span>
              </button>
            </div>
          </>
        )}

        {/* FORGOT PASSWORD: STEP 1 */}
        {authMode === 'forgot' && forgotStep === 1 && (
          <form onSubmit={handleForgotLookup} className="space-y-4 text-xs">
            <div>
              <label className="text-slate-400 block mb-1 font-semibold">Registered Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type="email"
                  required
                  autoComplete="email"
                  placeholder="Enter your registered email"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    setErrorMessage('');
                  }}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-3 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-amber-500/20 disabled:opacity-50 cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Checking Account...</span>
                </>
              ) : (
                <>
                  <span>Verify Email &amp; Continue</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        )}

        {/* FORGOT PASSWORD: STEP 2 */}
        {authMode === 'forgot' && forgotStep === 2 && (
          <form onSubmit={handleForgotReset} className="space-y-3.5 text-xs">
            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="text-[11px] text-slate-400">Account Holder</div>
                <div className="text-xs font-bold text-white truncate">
                  {forgotLookupName}{' '}
                  <span className="font-mono text-amber-400 font-normal">({email.trim().toLowerCase()})</span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setForgotStep(1);
                  setErrorMessage('');
                }}
                className="text-[11px] text-amber-400 hover:text-amber-300 font-semibold shrink-0 cursor-pointer"
              >
                Change
              </button>
            </div>

            <div className="p-3 rounded-xl bg-amber-500/5 border border-amber-500/25 space-y-1">
              <div className="text-[10px] font-mono uppercase tracking-wider text-amber-400 font-semibold">
                Security Question
              </div>
              <div className="text-xs font-semibold text-slate-100">{forgotQuestion}</div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-semibold">
                Your Security Answer / PIN
              </label>
              <div className="relative">
                <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type={showForgotAnswer ? 'text' : 'password'}
                  required
                  placeholder="Enter your recovery answer or PIN"
                  value={forgotAnswer}
                  onChange={(e) => {
                    setForgotAnswer(e.target.value);
                    setErrorMessage('');
                  }}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-10 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                />
                <button
                  type="button"
                  onClick={() => setShowForgotAnswer(!showForgotAnswer)}
                  className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
                  aria-label={showForgotAnswer ? 'Hide recovery answer' : 'Show recovery answer'}
                >
                  {showForgotAnswer ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-semibold">
                New Password <span className="text-slate-500 font-normal">(min 6 characters)</span>
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  required
                  autoComplete="new-password"
                  placeholder="Enter new password"
                  value={newPassword}
                  onChange={(e) => {
                    setNewPassword(e.target.value);
                    setErrorMessage('');
                  }}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-10 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 cursor-pointer"
                  aria-label={showNewPassword ? 'Hide new password' : 'Show new password'}
                >
                  {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="text-slate-400 block mb-1 font-semibold">Confirm New Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
                <input
                  type={showNewPassword ? 'text' : 'password'}
                  required
                  autoComplete="new-password"
                  placeholder="Re-enter new password"
                  value={confirmNewPassword}
                  onChange={(e) => {
                    setConfirmNewPassword(e.target.value);
                    setErrorMessage('');
                  }}
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl pl-9 pr-3 py-2.5 text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-3 bg-gradient-to-r from-amber-500 to-amber-600 hover:from-amber-400 hover:to-amber-500 text-slate-950 font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 shadow-lg shadow-amber-500/20 disabled:opacity-50 cursor-pointer"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Updating Password...</span>
                </>
              ) : (
                <>
                  <span>Reset Password</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        )}
      </div>

      {/* Security note */}
      <div className="flex items-center gap-1.5 text-slate-500 text-[11px] font-mono mt-6">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
        <span>Password-Verified Server Authentication • Isolated Account Storage</span>
      </div>
    </div>
  );
};
