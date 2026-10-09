-- ==============================================================================
-- DIGITAL EVIDENCE GUARDIAN - INITIAL SCHEMA MIGRATION
-- Migration: 001_initial_schema.sql
-- Cryptographic Evidence Management, RBAC, and Tamper-Evident Audit Ledger
-- ==============================================================================

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. USERS (Personnel & Role-Based Access Control)
CREATE TABLE IF NOT EXISTS public.users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    badge_number TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('FIELD_OFFICER', 'INVESTIGATOR', 'HIGHER_OFFICIAL', 'ADMINISTRATOR')),
    email TEXT NOT NULL UNIQUE,
    department TEXT NOT NULL,
    avatar_url TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
    fingerprint_enrolled BOOLEAN NOT NULL DEFAULT false,
    biometric_key_id TEXT,
    fingerprint_hash TEXT,
    webauthn_credential_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_users_role ON public.users(role);
CREATE INDEX IF NOT EXISTS idx_users_badge ON public.users(badge_number);

-- 3. CRIME CASES
CREATE TABLE IF NOT EXISTS public.cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    crime_location TEXT NOT NULL,
    opened_date TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'UNDER_INVESTIGATION', 'TRIAL_PENDING', 'CLOSED')),
    lead_investigator_id TEXT REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL,
    lead_investigator_name TEXT NOT NULL,
    lead_investigator_badge TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    evidence_count INTEGER NOT NULL DEFAULT 0,
    is_demo BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cases_status ON public.cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_opened_date ON public.cases(opened_date DESC);
CREATE INDEX IF NOT EXISTS idx_cases_lead_investigator ON public.cases(lead_investigator_id);

-- 4. EVIDENCE ITEMS
CREATE TABLE IF NOT EXISTS public.evidence (
    id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES public.cases(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    name TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    description TEXT NOT NULL,
    collection_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    collection_address TEXT NOT NULL,
    room_or_sector TEXT,
    coordinates TEXT,
    collecting_officer_id TEXT REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL,
    collecting_officer_name TEXT NOT NULL,
    collecting_officer_badge TEXT NOT NULL,
    collecting_officer_department TEXT NOT NULL,
    current_custodian TEXT NOT NULL,
    current_status TEXT NOT NULL DEFAULT 'REGISTERED' CHECK (
        current_status IN (
            'COLLECTED',
            'REGISTERED',
            'STORED',
            'TRANSFERRED',
            'FORENSIC ANALYSIS',
            'VERIFIED',
            'SUBMITTED TO COURT'
        )
    ),
    storage_location TEXT NOT NULL,
    image_url TEXT,
    storage_path TEXT,
    file_hash TEXT,
    record_hash TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    qr_payload TEXT NOT NULL,
    is_demo BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON public.evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_status ON public.evidence(current_status);
CREATE INDEX IF NOT EXISTS idx_evidence_record_hash ON public.evidence(record_hash);
CREATE INDEX IF NOT EXISTS idx_evidence_collection_timestamp ON public.evidence(collection_timestamp DESC);

-- 5. MODIFICATION REQUESTS (Dual-Control Governance)
CREATE TABLE IF NOT EXISTS public.modification_requests (
    id TEXT PRIMARY KEY,
    evidence_id TEXT NOT NULL REFERENCES public.evidence(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    case_id TEXT NOT NULL REFERENCES public.cases(id) ON UPDATE CASCADE ON DELETE RESTRICT,
    requested_by_id TEXT REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL,
    requested_by_name TEXT NOT NULL,
    requested_by_badge TEXT NOT NULL,
    requested_by_role TEXT NOT NULL,
    request_timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    field_to_change TEXT NOT NULL CHECK (field_to_change IN ('evidenceType', 'name', 'description', 'location', 'storageLocation')),
    field_name_display TEXT NOT NULL,
    original_value TEXT NOT NULL,
    requested_value TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED')),
    reviewed_by_id TEXT REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL,
    reviewed_by_name TEXT,
    reviewed_by_badge TEXT,
    reviewed_by_role TEXT,
    review_timestamp TIMESTAMPTZ,
    review_notes TEXT,
    biometric_verification_used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_mod_requests_status ON public.modification_requests(status);
CREATE INDEX IF NOT EXISTS idx_mod_requests_evidence_id ON public.modification_requests(evidence_id);
CREATE INDEX IF NOT EXISTS idx_mod_requests_case_id ON public.modification_requests(case_id);

-- 6. AUDIT LOGS (Cryptographically Chained Append-Only Ledger)
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    action TEXT NOT NULL,
    evidence_id TEXT,
    case_id TEXT,
    user_id TEXT NOT NULL,
    user_name TEXT NOT NULL,
    user_role TEXT NOT NULL,
    badge_number TEXT NOT NULL,
    description TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    previous_hash TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON public.audit_logs(timestamp ASC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_case_id ON public.audit_logs(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_evidence_id ON public.audit_logs(evidence_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON public.audit_logs(user_id);

-- 7. APPEND-ONLY ENFORCEMENT ON AUDIT LOGS (Database-level Tamper Prevention)
CREATE OR REPLACE FUNCTION public.prevent_audit_modification()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'SECURITY PROTOCOL VIOLATION: Audit log records are append-only and mathematically immutable. Updates or deletions are strictly prohibited.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_prevent_audit_update ON public.audit_logs;
CREATE TRIGGER trg_prevent_audit_update
BEFORE UPDATE OR DELETE ON public.audit_logs
FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_modification();

-- 8. ROW LEVEL SECURITY (RLS) POLICIES
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.modification_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;

-- Service role has full administrative access (used by server backend)
DROP POLICY IF EXISTS "Service role full access on users" ON public.users;
CREATE POLICY "Service role full access on users" ON public.users
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on cases" ON public.cases;
CREATE POLICY "Service role full access on cases" ON public.cases
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on evidence" ON public.evidence;
CREATE POLICY "Service role full access on evidence" ON public.evidence
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on modification_requests" ON public.modification_requests;
CREATE POLICY "Service role full access on modification_requests" ON public.modification_requests
    FOR ALL TO service_role USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "Service role full access on audit_logs" ON public.audit_logs;
CREATE POLICY "Service role full access on audit_logs" ON public.audit_logs
    FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Authenticated law enforcement read policies
DROP POLICY IF EXISTS "Authenticated users can read personnel" ON public.users;
CREATE POLICY "Authenticated users can read personnel" ON public.users
    FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Authenticated users can read cases" ON public.cases;
CREATE POLICY "Authenticated users can read cases" ON public.cases
    FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Authenticated users can read evidence" ON public.evidence;
CREATE POLICY "Authenticated users can read evidence" ON public.evidence
    FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Authenticated users can read modification requests" ON public.modification_requests;
CREATE POLICY "Authenticated users can read modification requests" ON public.modification_requests
    FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "Authenticated users can read audit trail" ON public.audit_logs;
CREATE POLICY "Authenticated users can read audit trail" ON public.audit_logs
    FOR SELECT TO authenticated USING (true);

-- 9. SUPABASE STORAGE BUCKET CONFIGURATION (evidence-images)
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES (
    'evidence-images',
    'evidence-images',
    false, -- Private bucket: access via signed URLs or service-role
    20971520, -- 20 MB limit
    ARRAY['image/jpeg', 'image/png', 'image/webp', 'image/gif']
)
ON CONFLICT (id) DO UPDATE SET
    public = false,
    file_size_limit = 20971520,
    allowed_mime_types = ARRAY['image/jpeg', 'image/png', 'image/webp', 'image/gif'];

-- Storage bucket access policies
DROP POLICY IF EXISTS "Service role full storage access" ON storage.objects;
CREATE POLICY "Service role full storage access" ON storage.objects
    FOR ALL TO service_role USING (bucket_id = 'evidence-images') WITH CHECK (bucket_id = 'evidence-images');

DROP POLICY IF EXISTS "Authenticated users can read evidence files" ON storage.objects;
CREATE POLICY "Authenticated users can read evidence files" ON storage.objects
    FOR SELECT TO authenticated USING (bucket_id = 'evidence-images');

-- 10. INITIAL SEED DATA (Law Enforcement Baseline)
INSERT INTO public.users (id, name, badge_number, role, email, department, status, fingerprint_enrolled, biometric_key_id, fingerprint_hash)
VALUES
    ('usr-officer-ravi', 'Inspector Vikram Rathore', 'FO-8841', 'FIELD_OFFICER', 'vikram.rathore@forensics.gov.in', 'Crime Scene First Response Unit', 'ACTIVE', true, 'bio-key-ravi-8841', 'a7c92b84f091de467812bc89fa01438910e54cd3b78912ef093412567890abcd'),
    ('usr-det-sarah', 'Det. Ananya Sharma', 'INV-4029', 'INVESTIGATOR', 'ananya.sharma@forensics.gov.in', 'Major Crimes & Forensics Division', 'ACTIVE', true, 'bio-key-sarah-4029', 'bc8912de45fa0192837465ab10928374650192837465fa0192837465bcde8901'),
    ('usr-insp-marcus', 'Superintendent Rajesh Verma', 'HO-1002', 'HIGHER_OFFICIAL', 'rajesh.verma@forensics.gov.in', 'Judicial Liaison & Internal Affairs', 'ACTIVE', true, 'bio-key-marcus-1002', '99018237465fa0192837465bcde8901a7c92b84f091de467812bc89fa0143891'),
    ('usr-admin-elena', 'Director Priya Deshmukh', 'ADM-0001', 'ADMINISTRATOR', 'priya.deshmukh@cybersec.gov.in', 'Department of Digital Security & Forensics', 'ACTIVE', true, 'bio-key-elena-0001', '34567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.cases (id, title, crime_location, opened_date, status, lead_investigator_id, lead_investigator_name, lead_investigator_badge, description, evidence_count)
VALUES
    ('CASE-2026-001', 'Downtown Vault Security Breach & Burglary', '742 Grand Avenue, Downtown Metro Financial District', '2026-10-05T08:15:00.000Z', 'UNDER_INVESTIGATION', 'usr-det-sarah', 'Det. Ananya Sharma', 'INV-4029', 'Forced entry via secondary vault service shaft. Safe deposit boxes targeted with mechanical and electronic intrusion apparatus.', 2),
    ('CASE-2026-002', 'Pier 14 Maritime Warehouse Contraband Interception', 'Warehouse B, Terminal 3, Metro Seaport', '2026-10-06T14:30:00.000Z', 'OPEN', 'usr-det-sarah', 'Det. Ananya Sharma', 'INV-4029', 'Suspicious shipping container flagged during customs thermal imaging. Unregistered firearms and telecommunication jammers recovered.', 1),
    ('CASE-2026-003', 'Apex Financial Cryptographic Ransomware Attack', 'Server Room 4B, Apex Tower, Tech Corridor', '2026-10-07T03:40:00.000Z', 'UNDER_INVESTIGATION', 'usr-det-sarah', 'Det. Ananya Sharma', 'INV-4029', 'Core clearing database encrypted by state-sponsored malware variant. Air-gapped backup server drives seized for digital forensics.', 1)
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.evidence (id, case_id, name, evidence_type, description, collection_timestamp, collection_address, room_or_sector, coordinates, collecting_officer_id, collecting_officer_name, collecting_officer_badge, collecting_officer_department, current_custodian, current_status, storage_location, image_url, file_hash, record_hash, version, qr_payload)
VALUES
    ('EV-2026-0001', 'CASE-2026-001', '36-inch Forged Alloy Prying Tool (Crowbar)', 'Metal Object / Weapon', 'Heavy duty steel crowbar with red oxidized paint scratches. Found adjacent to the north security door frame with visible paint transfer from door lock mechanism.', '2026-10-05T09:12:44.000Z', '742 Grand Avenue, Floor -1, Service Hallway', 'Vault Access Corridor North', '37.7749° N, 122.4194° W', 'usr-officer-ravi', 'Inspector Vikram Rathore', 'FO-8841', 'Crime Scene First Response Unit', 'Central Secure Evidence Locker Room 2, Bay C-14', 'STORED', 'Central Vault #2 - Bay C14', 'https://images.unsplash.com/photo-1581783898377-1c85bf937427?auto=format&fit=crop&w=800&q=80', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', '8f7a93e2b104928bcf6270451a998b3fca40134bc57564d39e2482315b9cf412', 1, 'DEG:EV-2026-0001:CASE-2026-001:VERIFIED-AUTH'),
    ('EV-2026-0002', 'CASE-2026-001', 'Encrypted Samsung 990 Pro 2TB NVMe SSD', 'Digital Media / Storage', 'Solid state drive recovered plugged into rogue hardware bypass TAP device attached to the security DVR switch.', '2026-10-05T10:45:12.000Z', '742 Grand Avenue, Security Surveillance Room 102', 'Rack Server 04, Port 22 Bypass', '37.7751° N, 122.4196° W', 'usr-officer-ravi', 'Inspector Vikram Rathore', 'FO-8841', 'Crime Scene First Response Unit', 'Cyber Forensics Unit - Hardware Lab 3', 'FORENSIC ANALYSIS', 'Forensics Lab 3 - Faraday Enclosure #7', 'https://images.unsplash.com/photo-1597872200969-2b65d56bd16b?auto=format&fit=crop&w=800&q=80', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', '3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1', 1, 'DEG:EV-2026-0002:CASE-2026-001:VERIFIED-AUTH'),
    ('EV-2026-0003', 'CASE-2026-002', 'Glock 19 Gen5 9mm Semiautomatic Firearm', 'Firearm & Ballistics', 'Handgun with defaced serial number, fitted with threaded barrel. Magazine contained 14 rounds of 9mm Luger ball ammunition.', '2026-10-06T15:20:00.000Z', 'Terminal 3, Pier 14, Warehouse B Office', 'Supervisor Desk Lower Locked Drawer', '37.7983° N, 122.3789° W', 'usr-officer-ravi', 'Inspector Vikram Rathore', 'FO-8841', 'Crime Scene First Response Unit', 'Ballistics & Firearms Analysis Section', 'REGISTERED', 'Firearms Armory Evidence Safe #12', 'https://images.unsplash.com/photo-1595590424283-b8f17842773f?auto=format&fit=crop&w=800&q=80', '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', '7d5668e27c1a851167732a32c695b7a5e01b1b463281ab7911b6441113ffef6c', 1, 'DEG:EV-2026-0003:CASE-2026-002:VERIFIED-AUTH'),
    ('EV-2026-0004', 'CASE-2026-003', 'Forensic Memory Dump USB Key (SanDisk 128GB)', 'Digital Media / Storage', 'Volatile RAM image extracted from compromised Domain Controller prior to cold shutdown. Contains decrypted malware payload traces in memory space.', '2026-10-07T04:15:30.000Z', 'Apex Tower, 1200 Silicon Expressway, Server Room 4B', 'Rack Bay 12, Terminal A', '37.7833° N, 122.4167° W', 'usr-det-sarah', 'Det. Ananya Sharma', 'INV-4029', 'Major Crimes & Forensics Division', 'State Forensic Lab - Evidence Examiner Dr. Patel', 'VERIFIED', 'High-Security Cyber Safe #01', 'https://images.unsplash.com/photo-1618005182384-a83a8bd57fbe?auto=format&fit=crop&w=800&q=80', '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a', '9a2245b78d23414986c7104b9015c9d64f027c4b693245d826f4203da8e9e992', 1, 'DEG:EV-2026-0004:CASE-2026-003:VERIFIED-AUTH')
ON CONFLICT (id) DO NOTHING;

INSERT INTO public.audit_logs (id, timestamp, action, case_id, evidence_id, user_id, user_name, user_role, badge_number, description, previous_hash, hash)
VALUES
    ('AUD-0001', '2026-10-05T08:15:00.000Z', 'CASE_CREATED', 'CASE-2026-001', NULL, 'usr-det-sarah', 'Det. Ananya Sharma', 'INVESTIGATOR', 'INV-4029', 'Case CASE-2026-001 "Downtown Vault Security Breach & Burglary" formally opened and assigned.', 'GENESIS_BLOCK_0000000000000000000000000000000000000000000000000000000000000000', '6a09e667f3bcc908a8e3d09a5b3a4a123f8b9d0e12a45b67c89d0e12f3456789')
ON CONFLICT (id) DO NOTHING;
