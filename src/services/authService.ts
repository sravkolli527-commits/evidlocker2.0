import { User, UserRole, EvidenceItem } from '../types';
import {
  loadUsers,
  saveUsers,
  getCurrentUserId,
  setCurrentUserId,
  isTerminalAuthenticated,
  setTerminalAuthenticated,
  registerUserLocal,
} from './storageService';
import { ApiService } from './apiService';
import { hashPassword, verifyPassword } from './cryptoService';
import { AuditService } from './auditService';

export const ROLE_DETAILS: Record<UserRole, { label: string; badgeClass: string; description: string }> = {
  FIELD_OFFICER: {
    label: 'Field Officer',
    badgeClass: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
    description: 'First responder at crime scene. Registers evidence, captures photos and locked timestamps. Cannot silently modify.',
  },
  FORENSIC_OFFICER: {
    label: 'Forensic Officer',
    badgeClass: 'text-teal-400 border-teal-500/30 bg-teal-500/10',
    description: 'Laboratory & digital forensic specialist. Examines physical/digital evidence, performs metallurgical/ballistics/DNA analyses, and certifies forensic integrity.',
  },
  INVESTIGATOR: {
    label: 'Investigator',
    badgeClass: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
    description: 'Case detective. Analyzes evidence, tracks chain of custody movement, and views forensic history.',
  },
  HIGHER_OFFICIAL: {
    label: 'Higher Official',
    badgeClass: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
    description: 'Judicial / Internal affairs official. Reviews, approves or rejects evidence modification requests and authorizes court submission.',
  },
  ADMINISTRATOR: {
    label: 'System Administrator',
    badgeClass: 'text-purple-400 border-purple-500/30 bg-purple-500/10',
    description: 'Security operator. Manages personnel roles, enforces RBAC policies, and audits cryptographic chain integrity.',
  },
};

export class AuthService {
  static isAuthenticated(): boolean {
    return isTerminalAuthenticated();
  }

  static logout(): void {
    setTerminalAuthenticated(false);
  }

  static async loginWithCredentials(officerId: string, password: string): Promise<User> {
    const cleanId = officerId.trim();
    const cleanPassword = password.trim();

    // 1. Attempt Backend Server Authentication
    try {
      const response = await ApiService.loginOfficer(cleanId, cleanPassword);
      if (response && response.user) {
        registerUserLocal(response.user);
        setTerminalAuthenticated(true, response.user.id);
        return response.user;
      }
    } catch (err: any) {
      // If server explicitly returned 401 or 403 or specific error, check if local fallback applies or propagate
      const msg = err?.message || '';
      if (msg.includes('Incorrect password') || msg.includes('revoked') || msg.includes('not found')) {
        throw new Error(msg);
      }
      console.warn('[AuthService] Backend login error, evaluating local roster fallback:', err);
    }

    // 2. Client-side Local Storage Fallback
    const users = loadUsers();
    const targetUser = users.find(
      u =>
        u.badgeNumber.toLowerCase() === cleanId.toLowerCase() ||
        (u.officerId && u.officerId.toLowerCase() === cleanId.toLowerCase()) ||
        u.email.toLowerCase() === cleanId.toLowerCase() ||
        u.id.toLowerCase() === cleanId.toLowerCase()
    );

    if (!targetUser) {
      throw new Error(`Officer ID "${cleanId}" not found in police directory. Please check your badge number or register.`);
    }

    if (targetUser.status === 'SUSPENDED') {
      throw new Error('Account Suspended: Law enforcement terminal access has been revoked by Judicial Oversight.');
    }

    const isValid = await verifyPassword(cleanPassword, targetUser.passwordHash, targetUser.password);
    if (!isValid) {
      throw new Error('Authentication failed: Incorrect password for this Officer Unique ID.');
    }

    setTerminalAuthenticated(true, targetUser.id);
    await AuditService.logAction({
      action: 'OFFICER_LOGIN',
      user: targetUser,
      description: `Officer ${targetUser.name} (${targetUser.role}, Badge: ${targetUser.badgeNumber}) authenticated via Officer Unique ID & password.`,
      metadata: {
        officerId: targetUser.badgeNumber,
        loginTimestamp: new Date().toISOString(),
      },
    });

    return targetUser;
  }

  static async registerOfficer(params: {
    officerId: string;
    name: string;
    password: string;
    role: UserRole;
    department?: string;
    email?: string;
  }): Promise<User> {
    const cleanId = params.officerId.trim().toUpperCase();
    const cleanName = params.name.trim();
    const cleanPassword = params.password.trim();
    const cleanDept = (params.department || 'Crime Scene First Response Unit').trim();
    const cleanEmail = (params.email || `${cleanId.toLowerCase()}@forensics.gov.in`).trim().toLowerCase();

    // 1. Attempt Backend Server Registration
    try {
      const response = await ApiService.registerOfficer({
        officerId: cleanId,
        name: cleanName,
        password: cleanPassword,
        role: params.role,
        department: cleanDept,
        email: cleanEmail,
      });

      if (response && response.user) {
        registerUserLocal(response.user);
        setTerminalAuthenticated(true, response.user.id);
        return response.user;
      }
    } catch (err: any) {
      const msg = err?.message || '';
      if (msg.includes('already registered') || msg.includes('mandatory') || msg.includes('at least 6')) {
        throw new Error(msg);
      }
      console.warn('[AuthService] Backend register error, evaluating local storage fallback:', err);
    }

    // 2. Client-side Local Storage Fallback
    const users = loadUsers();
    const existing = users.find(
      u => u.badgeNumber.toUpperCase() === cleanId || u.email.toLowerCase() === cleanEmail
    );
    if (existing) {
      throw new Error(`Officer ID "${cleanId}" or email is already registered to ${existing.name}. Please sign in.`);
    }

    const passwordHash = await hashPassword(cleanPassword);
    const userId = `usr-${cleanId.toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now().toString().slice(-4)}`;

    const newUser: User = {
      id: userId,
      name: cleanName,
      badgeNumber: cleanId,
      officerId: cleanId,
      role: params.role,
      email: cleanEmail,
      department: cleanDept,
      status: 'ACTIVE',
      fingerprintEnrolled: true,
      biometricKeyId: `bio-key-${cleanId.toLowerCase()}`,
      password: cleanPassword,
      passwordHash,
      registeredAt: new Date().toISOString(),
    };

    registerUserLocal(newUser);
    setTerminalAuthenticated(true, newUser.id);

    await AuditService.logAction({
      action: 'OFFICER_REGISTERED',
      user: newUser,
      description: `New law enforcement officer registered: ${newUser.name} (Officer ID: ${cleanId}, Role: ${newUser.role}, Dept: ${cleanDept}).`,
      metadata: {
        officerId: cleanId,
        role: newUser.role,
        department: cleanDept,
        registeredAt: newUser.registeredAt,
      },
    });

    return newUser;
  }

  static async fetchUsers(): Promise<User[]> {
    try {
      const serverUsers = await ApiService.getUsers();
      if (serverUsers && Array.isArray(serverUsers) && serverUsers.length > 0) {
        saveUsers(serverUsers);
        return serverUsers;
      }
    } catch {
      // Fallback
    }
    return loadUsers();
  }

  static getCurrentUser(): User {
    const users = loadUsers();
    const currentId = getCurrentUserId();
    const found = users.find(u => u.id === currentId);
    return found || users[0];
  }

  static switchUser(userId: string): User {
    setCurrentUserId(userId);
    setTerminalAuthenticated(true, userId);
    return this.getCurrentUser();
  }

  static getAllUsers(): User[] {
    return loadUsers();
  }

  static async updateUserRole(userId: string, newRole: UserRole): Promise<User | null> {
    try {
      const updated = await ApiService.updateUserRole(userId, newRole);
      if (updated) {
        const users = loadUsers();
        const idx = users.findIndex(u => u.id === userId);
        if (idx !== -1) users[idx] = updated;
        saveUsers(users);
        return updated;
      }
    } catch (err) {
      console.warn('[AuthService] Backend updateUserRole fallback to local:', err);
    }

    const users = loadUsers();
    const idx = users.findIndex(u => u.id === userId);
    if (idx === -1) return null;
    users[idx].role = newRole;
    saveUsers(users);
    return users[idx];
  }

  static async updateUserStatus(userId: string, status: 'ACTIVE' | 'SUSPENDED'): Promise<User | null> {
    try {
      const updated = await ApiService.updateUserStatus(userId, status);
      if (updated) {
        const users = loadUsers();
        const idx = users.findIndex(u => u.id === userId);
        if (idx !== -1) users[idx] = updated;
        saveUsers(users);
        return updated;
      }
    } catch (err) {
      console.warn('[AuthService] Backend updateUserStatus fallback to local:', err);
    }

    const users = loadUsers();
    const idx = users.findIndex(u => u.id === userId);
    if (idx === -1) return null;
    users[idx].status = status;
    saveUsers(users);
    return users[idx];
  }

  // RBAC permission checks
  static canCreateCase(user: User): boolean {
    return user.status === 'ACTIVE' && (user.role === 'INVESTIGATOR' || user.role === 'HIGHER_OFFICIAL' || user.role === 'ADMINISTRATOR');
  }

  static canRegisterEvidence(user: User): boolean {
    return user.status === 'ACTIVE' && (user.role === 'FIELD_OFFICER' || user.role === 'FORENSIC_OFFICER' || user.role === 'ADMINISTRATOR');
  }

  static canPerformForensicAnalysis(user: User): boolean {
    return user.status === 'ACTIVE' && (user.role === 'FORENSIC_OFFICER' || user.role === 'INVESTIGATOR' || user.role === 'ADMINISTRATOR');
  }

  static canRequestModification(user: User, _evidence?: EvidenceItem): boolean {
    return user.status === 'ACTIVE';
  }

  static canUpdateEvidenceStatus(user: User): boolean {
    return user.status === 'ACTIVE';
  }

  static canTransferCustody(user: User): boolean {
    return user.status === 'ACTIVE';
  }

  static canReviewModifications(user: User): boolean {
    return user.status === 'ACTIVE' && (user.role === 'HIGHER_OFFICIAL' || user.role === 'ADMINISTRATOR');
  }

  static canManageUsers(user: User): boolean {
    return user.status === 'ACTIVE' && user.role === 'ADMINISTRATOR';
  }
}
