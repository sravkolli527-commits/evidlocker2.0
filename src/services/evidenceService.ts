import {
  EvidenceItem,
  EvidenceStatus,
  EvidenceType,
  CrimeCase,
  ModificationRequest,
  User,
} from '../types';
import {
  loadEvidence,
  saveEvidence,
  loadCases,
  saveCases,
  loadModifications,
  saveModifications,
} from './storageService';
import { computeEvidenceRecordHash } from './cryptoService';
import { AuditService } from './auditService';
import { ApiService } from './apiService';

export class EvidenceService {
  // --- Case Operations ---
  static async fetchCases(): Promise<CrimeCase[]> {
    try {
      const serverCases = await ApiService.getCases();
      if (serverCases && Array.isArray(serverCases) && serverCases.length > 0) {
        saveCases(serverCases);
        return serverCases;
      }
    } catch {
      // Backend offline or starting, fall back to local storage
    }
    return loadCases();
  }

  static getCases(): CrimeCase[] {
    return loadCases();
  }

  static getCaseById(caseId: string): CrimeCase | undefined {
    return loadCases().find(c => c.id === caseId);
  }

  static async createCase(params: {
    title: string;
    crimeLocation: string;
    description: string;
    user: User;
  }): Promise<CrimeCase> {
    const created = await ApiService.createCase({
      title: params.title,
      crimeLocation: params.crimeLocation,
      description: params.description,
      userId: params.user.id,
    });
    if (created) {
      const cases = loadCases();
      cases.unshift(created);
      saveCases(cases);
      await AuditService.fetchAuditLogs();
      return created;
    }
    throw new Error('Server returned empty response when creating case.');
  }

  // --- Evidence Operations ---
  static async fetchEvidenceList(): Promise<EvidenceItem[]> {
    try {
      const serverList = await ApiService.getEvidence();
      if (serverList && Array.isArray(serverList) && serverList.length > 0) {
        saveEvidence(serverList);
        return serverList;
      }
    } catch {
      // Fallback to local
    }
    return loadEvidence();
  }

  static getEvidenceList(): EvidenceItem[] {
    return loadEvidence();
  }

  static getEvidenceById(id: string): EvidenceItem | undefined {
    return loadEvidence().find(e => e.id === id);
  }

  static getEvidenceForCase(caseId: string): EvidenceItem[] {
    return loadEvidence().filter(e => e.caseId === caseId);
  }

  static generateEvidenceId(): string {
    const list = loadEvidence();
    const nextNum = list.length + 1;
    return `EV-2026-${String(nextNum).padStart(4, '0')}`;
  }

  static async registerEvidence(params: {
    caseId: string;
    name: string;
    evidenceType: EvidenceType;
    description: string;
    address: string;
    roomOrSector?: string;
    coordinates?: string;
    storageLocation: string;
    imageUrl?: string;
    fileHash?: string;
    user: User;
    biometricUsed?: boolean;
  }): Promise<EvidenceItem> {
    const registered = await ApiService.registerEvidence({
      caseId: params.caseId,
      name: params.name,
      evidenceType: params.evidenceType,
      description: params.description,
      address: params.address,
      roomOrSector: params.roomOrSector,
      coordinates: params.coordinates,
      storageLocation: params.storageLocation,
      imageUrl: params.imageUrl,
      fileHash: params.fileHash,
      userId: params.user.id,
      biometricUsed: params.biometricUsed,
    });

    if (registered) {
      const evidenceList = loadEvidence();
      evidenceList.unshift(registered);
      saveEvidence(evidenceList);

      const cases = loadCases();
      const targetCase = cases.find(c => c.id === params.caseId);
      if (targetCase) {
        targetCase.evidenceCount = (targetCase.evidenceCount || 0) + 1;
        saveCases(cases);
      }

      await AuditService.fetchAuditLogs();
      return registered;
    }
    throw new Error('Server returned empty response when registering evidence.');
  }

  // --- Modification Request Flow ---
  static async fetchModificationRequests(): Promise<ModificationRequest[]> {
    try {
      const serverMods = await ApiService.getModifications();
      if (serverMods && Array.isArray(serverMods)) {
        saveModifications(serverMods);
        return serverMods;
      }
    } catch {
      // Fallback to local
    }
    return loadModifications();
  }

  static getModificationRequests(): ModificationRequest[] {
    return loadModifications();
  }

  static getPendingModificationCount(): number {
    return loadModifications().filter(m => m.status === 'PENDING').length;
  }

  static async requestModification(params: {
    evidenceId: string;
    fieldToChange: 'evidenceType' | 'name' | 'description' | 'location' | 'storageLocation';
    fieldNameDisplay: string;
    originalValue: string;
    requestedValue: string;
    reason: string;
    user: User;
    biometricUsed?: boolean;
  }): Promise<ModificationRequest> {
    const createdMod = await ApiService.requestModification({
      evidenceId: params.evidenceId,
      fieldToChange: params.fieldToChange,
      fieldNameDisplay: params.fieldNameDisplay,
      originalValue: params.originalValue,
      requestedValue: params.requestedValue,
      reason: params.reason,
      userId: params.user.id,
      biometricUsed: params.biometricUsed,
    });

    if (createdMod) {
      const mods = loadModifications();
      mods.unshift(createdMod);
      saveModifications(mods);
      await AuditService.fetchAuditLogs();
      return createdMod;
    }
    throw new Error('Server returned empty response when submitting modification request.');
  }

  static async reviewModification(params: {
    requestId: string;
    status: 'APPROVED' | 'REJECTED';
    reviewNotes?: string;
    user: User;
    biometricVerified?: boolean;
    authProofToken?: string;
  }): Promise<ModificationRequest> {
    // ENFORCE PRIVILEGED PROTECTION: Never use a simulated biometric result to authorize a real evidence correction or approval
    if (params.biometricVerified) {
      if (!params.authProofToken || params.authProofToken.startsWith('SIMULATED_DEMO_') || params.authProofToken.includes('SIMULATED')) {
        throw new Error(
          'SECURITY VIOLATION: A simulated biometric result cannot be used to authorize a real evidence correction or approval. Genuine device biometrics or Standard Supervisory Review is required.'
        );
      }
    }

    const reviewed = await ApiService.reviewModification({
      id: params.requestId,
      status: params.status,
      reviewNotes: params.reviewNotes,
      userId: params.user.id,
      biometricVerified: params.biometricVerified,
      authProofToken: params.authProofToken,
    });

    if (reviewed) {
      // Sync fresh evidence & modifications from server
      await this.fetchEvidenceList();
      await this.fetchModificationRequests();
      await AuditService.fetchAuditLogs();
      return reviewed;
    }
    throw new Error('Server returned empty response when reviewing modification.');
  }

  // --- Status and Custody Lifecycle ---
  static async updateEvidenceStatus(params: {
    evidenceId: string;
    newStatus: EvidenceStatus;
    notes?: string;
    user: User;
  }): Promise<EvidenceItem> {
    const serverItem = await ApiService.updateEvidenceStatus({
      id: params.evidenceId,
      newStatus: params.newStatus,
      notes: params.notes,
      userId: params.user.id,
    });
    if (serverItem) {
      const list = loadEvidence();
      const idx = list.findIndex(e => e.id === serverItem.id);
      if (idx !== -1) list[idx] = serverItem;
      saveEvidence(list);
      await AuditService.fetchAuditLogs();
      return serverItem;
    }
    throw new Error('Server returned empty response when updating evidence status.');
  }

  static async transferCustody(params: {
    evidenceId: string;
    toCustodian: string;
    newStorageLocation: string;
    purpose: string;
    user: User;
    biometricVerified?: boolean;
  }): Promise<EvidenceItem> {
    const serverItem = await ApiService.transferCustody({
      id: params.evidenceId,
      toCustodian: params.toCustodian,
      newStorageLocation: params.newStorageLocation,
      purpose: params.purpose,
      userId: params.user.id,
      biometricVerified: params.biometricVerified,
    });
    if (serverItem) {
      const list = loadEvidence();
      const idx = list.findIndex(e => e.id === serverItem.id);
      if (idx !== -1) list[idx] = serverItem;
      saveEvidence(list);
      await AuditService.fetchAuditLogs();
      return serverItem;
    }
    throw new Error('Server returned empty response when transferring custody.');
  }

  static async logEvidenceView(evidenceId: string, user: User): Promise<void> {
    const item = this.getEvidenceById(evidenceId);
    if (!item) return;

    await AuditService.logAction({
      action: 'EVIDENCE_VIEWED',
      user,
      evidenceId,
      caseId: item.caseId,
      description: `Digital Evidence Record ${evidenceId} accessed and reviewed by ${user.name} (${user.role}, Badge: ${user.badgeNumber}).`,
    });
  }
}
