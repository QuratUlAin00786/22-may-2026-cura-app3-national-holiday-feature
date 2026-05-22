import {
  scryptSync,
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from "node:crypto";

/** Matches @encryption-sdk/ AveroxEnvelope format (ChaCha20-Poly1305) */
interface PatientEnvelope {
  v: string;
  alg: string;
  iv: string;
  tag: string;
  ct: string;
  aad?: string;
  kid?: string;
}

export class PatientCryptoError extends Error {
  constructor(
    public code: string,
    message: string,
    public details?: unknown,
  ) {
    super(message);
    this.name = "PatientCryptoError";
  }
}

export class BadInputError extends PatientCryptoError {
  constructor(message: string) {
    super("BAD_INPUT", message);
    this.name = "BadInputError";
  }
}

export class InvalidTagError extends PatientCryptoError {
  constructor(message = "Authentication tag verification failed") {
    super("INVALID_TAG", message);
    this.name = "InvalidTagError";
  }
}

/** Domain-separated AAD for whole-patient payload authentication */
const PATIENT_RECORD_AAD = "cura-emr:patient-record:v1";

/** Wrapper key for encrypted jsonb column values */
const ENCRYPTED_JSONB_FIELD_KEY = "__encryptedField";

/** Application salt for deriving a 32-byte key from ENCRYPTION_KEY */
const KEY_DERIVATION_SALT = "cura-emr-patient-encryption-v1";

const CHACHA_KEY_SIZE = 32;
const CHACHA_NONCE_SIZE = 12;
const CHACHA_TAG_SIZE = 16;

/** Text columns on patients that store per-field encrypted envelopes */
const PATIENT_ENCRYPTED_TEXT_FIELDS = [
  "firstName",
  "lastName",
  "relation",
  "dateOfBirth",
  "genderAtBirth",
  "email",
  "phone",
  "nhsNumber",
] as const;

/** Jsonb columns on patients that store { __encryptedField: "<envelope>" } */
const PATIENT_ENCRYPTED_JSONB_FIELDS = [
  "address",
  "insuranceInfo",
  "emergencyContact",
  "communicationPreferences",
] as const;

type PatientTextField = (typeof PATIENT_ENCRYPTED_TEXT_FIELDS)[number];
type PatientJsonbField = (typeof PATIENT_ENCRYPTED_JSONB_FIELDS)[number];

const RAW_ROW_FIELD_ALIASES: Record<string, string> = {
  firstName: "first_name",
  lastName: "last_name",
  dateOfBirth: "date_of_birth",
  genderAtBirth: "gender_at_birth",
  nhsNumber: "nhs_number",
  insuranceInfo: "insurance_info",
  emergencyContact: "emergency_contact",
  communicationPreferences: "communication_preferences",
};

let encryptionKey: Buffer | null = null;

/** True when ENCRYPTION_KEY is set (required before creating encrypted patient rows). */
export function isPatientEncryptionConfigured(): boolean {
  return Boolean(process.env.ENCRYPTION_KEY?.trim());
}

/** Strip empty address parts before jsonb column encryption. */
export function normalizePatientAddressForStorage(
  address: unknown,
): Record<string, string> {
  if (!address || typeof address !== "object" || Array.isArray(address)) {
    return {};
  }
  const keys = ["street", "city", "state", "postcode", "country", "building"] as const;
  const result: Record<string, string> = {};
  for (const key of keys) {
    const value = (address as Record<string, unknown>)[key];
    if (value != null && String(value).trim() !== "") {
      result[key] = String(value).trim();
    }
  }
  return result;
}

/** Ensures preparePatientForStorage produced required per-column envelopes. */
export function assertEncryptedPatientInsertRow(insertData: Record<string, unknown>): void {
  if (!isEncryptedScalarField(insertData.email)) {
    throw new BadInputError("Patient email was not encrypted for storage");
  }
  if (!isEncryptedScalarField(insertData.firstName)) {
    throw new BadInputError("Patient firstName was not encrypted for storage");
  }
  if (!isEncryptedScalarField(insertData.lastName)) {
    throw new BadInputError("Patient lastName was not encrypted for storage");
  }
  const medicalHistory = insertData.medicalHistory as Record<string, unknown> | undefined;
  const payload = medicalHistory?.[ENCRYPTED_PATIENT_PAYLOAD_KEY];
  if (typeof payload !== "string" || payload.length === 0) {
    throw new BadInputError("Patient encrypted payload is missing from medicalHistory");
  }
}

function deriveKeyFromEnv(): Buffer {
  const raw = process.env.ENCRYPTION_KEY;
  if (!raw || raw.trim().length === 0) {
    throw new PatientCryptoError(
      "MISSING_ENCRYPTION_KEY",
      "ENCRYPTION_KEY environment variable is required for patient data encryption",
    );
  }

  const trimmed = raw.trim();

  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, "hex");
  }

  try {
    const decoded = Buffer.from(trimmed, "base64");
    if (decoded.length === CHACHA_KEY_SIZE) {
      return decoded;
    }
  } catch {
    /* fall through to scrypt */
  }

  return scryptSync(trimmed, KEY_DERIVATION_SALT, CHACHA_KEY_SIZE);
}

function getEncryptionKey(): Buffer {
  if (!encryptionKey) {
    encryptionKey = deriveKeyFromEnv();
  }
  return encryptionKey;
}

export function fieldAad(fieldName: string): string {
  return `cura-emr:patient-field:${fieldName}:v1`;
}

/** ChaCha20-Poly1305 AEAD — same envelope layout as @encryption-sdk/ */
function encryptChaCha20Poly1305(plaintext: string, aad: string): PatientEnvelope {
  const key = getEncryptionKey();
  const plaintextBuffer = Buffer.from(plaintext, "utf8");
  const aadBuffer = Buffer.from(aad, "utf8");
  const nonce = randomBytes(CHACHA_NONCE_SIZE);

  const cipher = createCipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: CHACHA_TAG_SIZE,
  });
  cipher.setAAD(aadBuffer, { plaintextLength: plaintextBuffer.length });

  let ciphertext = cipher.update(plaintextBuffer);
  ciphertext = Buffer.concat([ciphertext, cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    v: "2.0",
    alg: "ChaCha20-Poly1305",
    iv: nonce.toString("base64url"),
    tag: tag.toString("base64url"),
    ct: ciphertext.toString("base64url"),
    aad: aadBuffer.toString("base64url"),
  };
}

function decryptChaCha20Poly1305(envelope: PatientEnvelope, aad: string): Buffer {
  const key = getEncryptionKey();

  if (envelope.alg !== "ChaCha20-Poly1305") {
    throw new BadInputError(`Expected ChaCha20-Poly1305 but got: ${envelope.alg}`);
  }

  const aadBuffer = Buffer.from(aad, "utf8");
  const nonce = Buffer.from(envelope.iv, "base64url");
  const tag = Buffer.from(envelope.tag, "base64url");
  const ciphertext = Buffer.from(envelope.ct, "base64url");

  if (nonce.length !== CHACHA_NONCE_SIZE) {
    throw new PatientCryptoError("INVALID_NONCE", "Nonce must be exactly 12 bytes");
  }
  if (tag.length !== CHACHA_TAG_SIZE) {
    throw new PatientCryptoError("INVALID_TAG", "Tag must be exactly 16 bytes");
  }

  try {
    const decipher = createDecipheriv("chacha20-poly1305", key, nonce, {
      authTagLength: CHACHA_TAG_SIZE,
    });
    decipher.setAuthTag(tag);
    decipher.setAAD(aadBuffer, { plaintextLength: ciphertext.length });

    let plaintext = decipher.update(ciphertext);
    plaintext = Buffer.concat([plaintext, decipher.final()]);
    return plaintext;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (
      message.includes("unable to authenticate") ||
      message.includes("Unsupported state") ||
      message.includes("auth tag")
    ) {
      throw new InvalidTagError("Authentication failed - data may have been tampered with");
    }
    if (error instanceof PatientCryptoError) {
      throw error;
    }
    throw new PatientCryptoError(
      "DECRYPTION_FAILED",
      `ChaCha20-Poly1305 decryption failed: ${message}`,
      error,
    );
  }
}

function parseEnvelope(encryptedData: string): PatientEnvelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(encryptedData);
  } catch {
    throw new BadInputError("Encrypted patient data is not valid JSON");
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    !("v" in parsed) ||
    !("alg" in parsed) ||
    !("iv" in parsed) ||
    !("tag" in parsed) ||
    !("ct" in parsed)
  ) {
    throw new BadInputError("Encrypted patient data has an invalid envelope structure");
  }

  return parsed as PatientEnvelope;
}

function isEncryptedEnvelopeShape(o: unknown): o is PatientEnvelope {
  if (!o || typeof o !== "object" || Array.isArray(o)) return false;
  const parsed = o as PatientEnvelope;
  return (
    parsed.v === "2.0" &&
    parsed.alg === "ChaCha20-Poly1305" &&
    typeof parsed.ct === "string" &&
    typeof parsed.iv === "string" &&
    typeof parsed.tag === "string"
  );
}

/** True when a text column holds a ChaCha20-Poly1305 envelope (JSON string or parsed object). */
export function isEncryptedScalarField(value: unknown): boolean {
  if (typeof value === "string") {
    const t = value.trim();
    if (!t.startsWith("{")) {
      return false;
    }
    try {
      return isEncryptedEnvelopeShape(JSON.parse(t));
    } catch {
      return false;
    }
  }
  return isEncryptedEnvelopeShape(value);
}

/**
 * Normalize DB/driver values to a single JSON string for parseEnvelope/decrypt.
 * Some drivers return json/jsonb columns as objects instead of strings.
 */
export function patientEnvelopeJsonFromUnknown(stored: unknown): string | null {
  if (typeof stored === "string") {
    const t = stored.trim();
    return isEncryptedScalarField(t) ? t : null;
  }
  if (isEncryptedScalarField(stored)) {
    return JSON.stringify(stored);
  }
  return null;
}

function isEmptyObject(value: unknown): boolean {
  return (
    value != null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value as object).length === 0
  );
}

/** Encrypts a scalar patient column value (stored as envelope JSON string in text columns). */
export function encryptPatientField(fieldName: string, plaintext: string): string {
  const normalized = plaintext.trim();
  if (!normalized) {
    throw new BadInputError(`Field "${fieldName}" must be non-empty to encrypt`);
  }
  return JSON.stringify(encryptChaCha20Poly1305(normalized, fieldAad(fieldName)));
}

/**
 * Decrypts a scalar patient column envelope (JSON string or envelope object).
 * Tries canonical field AAD first, then the AAD embedded in the envelope (must match what was used at encrypt time).
 */
export function decryptPatientField(fieldName: string, encryptedValue: unknown): string {
  const json =
    typeof encryptedValue === "string" && isEncryptedScalarField(encryptedValue.trim())
      ? encryptedValue.trim()
      : patientEnvelopeJsonFromUnknown(encryptedValue);
  if (!json) {
    throw new BadInputError(`Field "${fieldName}" is not in encrypted envelope format`);
  }
  const envelope = parseEnvelope(json);
  const canonicalAad = fieldAad(fieldName);
  let embeddedAad: string | null = null;
  if (typeof envelope.aad === "string" && envelope.aad.length > 0) {
    try {
      embeddedAad = Buffer.from(envelope.aad, "base64url").toString("utf8");
    } catch {
      embeddedAad = null;
    }
  }
  const aadCandidates =
    embeddedAad != null && embeddedAad !== canonicalAad
      ? [canonicalAad, embeddedAad]
      : [canonicalAad];

  let lastError: unknown;
  for (const aad of aadCandidates) {
    try {
      return decryptChaCha20Poly1305(envelope, aad).toString("utf8");
    } catch (e) {
      lastError = e;
    }
  }
  if (lastError instanceof Error) {
    throw lastError;
  }
  throw new PatientCryptoError(
    "DECRYPTION_FAILED",
    `Failed to decrypt patient field "${fieldName}"`,
    lastError,
  );
}

export function encryptPatientEmail(email: string): string {
  return encryptPatientField("email", email);
}

export function decryptPatientEmail(encryptedEmail: string): string {
  return decryptPatientField("email", encryptedEmail);
}

function encryptPatientTextColumn(
  fieldName: PatientTextField,
  value: unknown,
  required = false,
): string | null {
  if (value == null || String(value).trim() === "") {
    if (required) {
      throw new BadInputError(`Field "${fieldName}" is required`);
    }
    return null;
  }
  return encryptPatientField(fieldName, String(value));
}

function encryptPatientJsonbColumn(
  fieldName: PatientJsonbField,
  value: unknown,
): Record<string, string> {
  if (value == null || isEmptyObject(value)) {
    return {};
  }
  const serialized = JSON.stringify(value);
  if (serialized === "{}" || serialized === "null") {
    return {};
  }
  return {
    [ENCRYPTED_JSONB_FIELD_KEY]: encryptPatientField(fieldName, serialized),
  };
}

function getRawColumnValue(rawPatient: Record<string, unknown>, fieldName: string): unknown {
  if (fieldName in rawPatient) {
    return rawPatient[fieldName];
  }
  const snake = RAW_ROW_FIELD_ALIASES[fieldName];
  if (snake && snake in rawPatient) {
    return rawPatient[snake];
  }
  return undefined;
}

function decryptPatientTextColumn(
  fieldName: PatientTextField,
  rawPatient: Record<string, unknown>,
  fallback: unknown,
): unknown {
  const stored = getRawColumnValue(rawPatient, fieldName);
  const envJson = patientEnvelopeJsonFromUnknown(stored);
  if (envJson) {
    return decryptPatientField(fieldName, envJson);
  }
  if (stored === PLACEHOLDER_FIRST_NAME || stored === PLACEHOLDER_LAST_NAME) {
    return fallback;
  }
  if (stored != null && String(stored).trim() !== "" && !patientEnvelopeJsonFromUnknown(stored)) {
    return stored;
  }
  return fallback;
}

function decryptPatientJsonbColumn(
  fieldName: PatientJsonbField,
  rawPatient: Record<string, unknown>,
  fallback: unknown,
): unknown {
  const stored = getRawColumnValue(rawPatient, fieldName);
  if (stored && typeof stored === "object" && !Array.isArray(stored)) {
    const record = stored as Record<string, unknown>;
    const encrypted = record[ENCRYPTED_JSONB_FIELD_KEY];
    const encJson = patientEnvelopeJsonFromUnknown(encrypted);
    if (encJson) {
      try {
        return JSON.parse(decryptPatientField(fieldName, encJson));
      } catch {
        throw new BadInputError(`Decrypted "${fieldName}" is not valid JSON`);
      }
    }
    if (!(ENCRYPTED_PATIENT_PAYLOAD_KEY in record)) {
      return stored;
    }
  }
  return fallback;
}

/**
 * Encrypts a complete patient object as a single authenticated payload.
 * @returns JSON string containing the SDK envelope (v, alg, iv, tag, ct, aad)
 */
export function encryptPatientData(patient: object): string {
  if (patient === null || typeof patient !== "object") {
    throw new BadInputError("Patient data must be a non-null object");
  }

  const serialized = JSON.stringify(patient);
  const envelope = encryptChaCha20Poly1305(serialized, PATIENT_RECORD_AAD);
  return JSON.stringify(envelope);
}

/**
 * Decrypts a patient payload produced by encryptPatientData.
 * @returns The restored patient object
 */
export function decryptPatientData(encryptedData: string): object {
  if (!encryptedData || typeof encryptedData !== "string") {
    throw new BadInputError("Encrypted patient data must be a non-empty string");
  }

  const envelope = parseEnvelope(encryptedData);
  let plaintext: Buffer;

  try {
    plaintext = decryptChaCha20Poly1305(envelope, PATIENT_RECORD_AAD);
  } catch (error) {
    if (error instanceof InvalidTagError) {
      throw error;
    }
    if (error instanceof PatientCryptoError) {
      throw error;
    }
    throw new PatientCryptoError(
      "DECRYPTION_FAILED",
      "Failed to decrypt patient data",
      error,
    );
  }

  try {
    return JSON.parse(plaintext.toString("utf8")) as object;
  } catch {
    throw new BadInputError("Decrypted patient data is not valid JSON");
  }
}

/** medicalHistory key used to store the encrypted patient payload (no schema change) */
export const ENCRYPTED_PATIENT_PAYLOAD_KEY = "__encryptedPatientPayload";

/** Legacy placeholder values (older rows — PHI was blob-only in medical_history) */
export const PLACEHOLDER_FIRST_NAME = "[encrypted]";
export const PLACEHOLDER_LAST_NAME = "[encrypted]";

/** True when row has a blob but PHI columns were not stored as per-field envelopes (legacy). */
export function needsPatientColumnBackfill(rawPatient: Record<string, unknown>): boolean {
  if (!isEncryptedPatientStorageRow(rawPatient)) {
    return false;
  }
  const firstName = getRawColumnValue(rawPatient, "firstName");
  const lastName = getRawColumnValue(rawPatient, "lastName");
  if (
    firstName === PLACEHOLDER_FIRST_NAME ||
    lastName === PLACEHOLDER_LAST_NAME
  ) {
    return true;
  }
  for (const field of PATIENT_ENCRYPTED_TEXT_FIELDS) {
    const stored = getRawColumnValue(rawPatient, field);
    if (stored == null || String(stored).trim() === "") {
      return true;
    }
    if (!patientEnvelopeJsonFromUnknown(stored)) {
      return true;
    }
  }
  for (const field of PATIENT_ENCRYPTED_JSONB_FIELDS) {
    const stored = getRawColumnValue(rawPatient, field);
    if (stored == null) {
      continue;
    }
    if (isEmptyObject(stored)) {
      continue;
    }
    const record = stored as Record<string, unknown>;
    const enc = record[ENCRYPTED_JSONB_FIELD_KEY];
    if (!patientEnvelopeJsonFromUnknown(enc)) {
      return true;
    }
  }
  return false;
}

/**
 * Re-encrypts every PHI column from the blob in medical_history (fixes legacy rows).
 */
export function rebuildPatientStorageRowFromBlob(
  rawPatient: Record<string, unknown>,
): Record<string, unknown> {
  if (!isEncryptedPatientStorageRow(rawPatient)) {
    throw new BadInputError("Patient row has no encrypted payload in medical_history");
  }
  const decrypted = decryptPatientData(extractEncryptedPayload(rawPatient)) as Record<
    string,
    unknown
  >;
  return preparePatientForStorage({
    ...decrypted,
    organizationId: rawPatient.organizationId ?? decrypted.organizationId,
    userId: rawPatient.userId ?? decrypted.userId,
    patientId: rawPatient.patientId ?? decrypted.patientId,
    riskLevel: rawPatient.riskLevel ?? decrypted.riskLevel ?? "low",
    isActive: rawPatient.isActive !== false,
    isInsured: rawPatient.isInsured === true,
    createdBy: rawPatient.createdBy ?? decrypted.createdBy,
  });
}

function getMedicalHistoryObject(rawPatient: Record<string, unknown>): Record<string, unknown> | null {
  const medicalHistory = rawPatient.medicalHistory ?? rawPatient.medical_history;
  if (!medicalHistory) return null;
  if (typeof medicalHistory === "object" && medicalHistory !== null) {
    return medicalHistory as Record<string, unknown>;
  }
  if (typeof medicalHistory === "string") {
    try {
      const parsed = JSON.parse(medicalHistory);
      if (parsed && typeof parsed === "object") {
        return parsed as Record<string, unknown>;
      }
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * Decrypt a raw patients table row for display/API use.
 * Handles full blob, per-column envelopes, and legacy plaintext rows.
 */
export function normalizePatientFromDatabaseRow(
  rawPatient: unknown,
): Record<string, unknown> | null {
  if (!rawPatient || typeof rawPatient !== "object") {
    return null;
  }
  const row = rawPatient as Record<string, unknown>;
  const decrypted = decryptPatientFromStorageRow(row);
  if (decrypted) {
    return decrypted;
  }
  const perColumn = mergePerColumnDecryptedPatientFields(row);
  if (perColumn) {
    return perColumn;
  }
  return row;
}

/** True when the DB row holds an encrypted patient blob in medicalHistory */
export function isEncryptedPatientStorageRow(rawPatient: unknown): boolean {
  if (!rawPatient || typeof rawPatient !== "object") return false;
  const medicalHistory = getMedicalHistoryObject(rawPatient as Record<string, unknown>);
  const payload = medicalHistory?.[ENCRYPTED_PATIENT_PAYLOAD_KEY];
  return typeof payload === "string" && payload.length > 0;
}

function extractEncryptedPayload(rawPatient: Record<string, unknown>): string {
  const medicalHistory = getMedicalHistoryObject(rawPatient);
  const payload = medicalHistory?.[ENCRYPTED_PATIENT_PAYLOAD_KEY];
  if (typeof payload !== "string" || payload.length === 0) {
    throw new BadInputError("Encrypted patient payload is missing from storage row");
  }
  return payload;
}

/**
 * Builds a DB row: each PHI column holds its own encrypted value; full record also in medicalHistory.
 */
export function preparePatientForStorage(patient: Record<string, unknown>): Record<string, unknown> {
  if (isEncryptedPatientStorageRow(patient)) {
    throw new BadInputError("Patient record is already encrypted");
  }

  const email = patient.email != null ? String(patient.email).trim() : "";
  if (!email) {
    throw new BadInputError("Patient email is required for encrypted storage");
  }

  const encryptedPayload = encryptPatientData({ ...patient, email });

  return {
    organizationId: patient.organizationId,
    userId: patient.userId ?? null,
    patientId: patient.patientId,
    firstName: encryptPatientTextColumn("firstName", patient.firstName, true),
    lastName: encryptPatientTextColumn("lastName", patient.lastName, true),
    relation: encryptPatientTextColumn("relation", patient.relation),
    dateOfBirth: encryptPatientTextColumn("dateOfBirth", patient.dateOfBirth),
    genderAtBirth: encryptPatientTextColumn("genderAtBirth", patient.genderAtBirth),
    email: encryptPatientField("email", email),
    phone: encryptPatientTextColumn("phone", patient.phone),
    nhsNumber: encryptPatientTextColumn("nhsNumber", patient.nhsNumber),
    address: encryptPatientJsonbColumn("address", patient.address),
    insuranceInfo: encryptPatientJsonbColumn("insuranceInfo", patient.insuranceInfo),
    emergencyContact: encryptPatientJsonbColumn("emergencyContact", patient.emergencyContact),
    medicalHistory: { [ENCRYPTED_PATIENT_PAYLOAD_KEY]: encryptedPayload },
    riskLevel: patient.riskLevel ?? "low",
    flags: Array.isArray(patient.flags) ? (patient.flags as unknown[]) : [],
    communicationPreferences: encryptPatientJsonbColumn(
      "communicationPreferences",
      patient.communicationPreferences,
    ),
    isActive: patient.isActive !== false,
    isInsured: patient.isInsured === true,
    createdBy: patient.createdBy ?? null,
  };
}

/**
 * Decrypts a storage row. Returns null for legacy plaintext rows (backward compatible).
 */
export function decryptPatientFromStorageRow(
  rawPatient: Record<string, unknown>,
): Record<string, unknown> | null {
  if (!isEncryptedPatientStorageRow(rawPatient)) {
    return null;
  }

  const decrypted = decryptPatientData(extractEncryptedPayload(rawPatient)) as Record<string, unknown>;

  const result: Record<string, unknown> = {
    ...decrypted,
    id: rawPatient.id ?? decrypted.id,
    organizationId: rawPatient.organizationId ?? decrypted.organizationId,
    userId: rawPatient.userId ?? decrypted.userId,
    isActive:
      rawPatient.isActive !== undefined ? rawPatient.isActive : decrypted.isActive,
    isInsured:
      rawPatient.isInsured !== undefined ? rawPatient.isInsured : decrypted.isInsured,
    createdAt: rawPatient.createdAt ?? decrypted.createdAt,
    updatedAt: rawPatient.updatedAt ?? decrypted.updatedAt,
    createdBy: rawPatient.createdBy ?? decrypted.createdBy,
  };

  for (const field of PATIENT_ENCRYPTED_TEXT_FIELDS) {
    result[field] = decryptPatientTextColumn(field, rawPatient, decrypted[field]);
  }

  for (const field of PATIENT_ENCRYPTED_JSONB_FIELDS) {
    result[field] = decryptPatientJsonbColumn(field, rawPatient, decrypted[field]);
  }

  return result;
}

/**
 * When the row has no full medicalHistory blob but PHI text/jsonb columns hold envelopes
 * (per-column encryption only), decrypt those fields so API/email paths see plaintext.
 */
export function mergePerColumnDecryptedPatientFields(
  rawPatient: Record<string, unknown>,
): Record<string, unknown> | null {
  let changed = false;
  const merged: Record<string, unknown> = { ...rawPatient };

  for (const field of PATIENT_ENCRYPTED_TEXT_FIELDS) {
    const stored = getRawColumnValue(rawPatient, field);
    const envJson = patientEnvelopeJsonFromUnknown(stored);
    if (envJson) {
      try {
        merged[field] = decryptPatientField(field, envJson);
        changed = true;
      } catch {
        /* leave ciphertext */
      }
    }
  }

  for (const field of PATIENT_ENCRYPTED_JSONB_FIELDS) {
    try {
      const prev = getRawColumnValue(merged, field);
      const next = decryptPatientJsonbColumn(field, rawPatient, prev);
      if (JSON.stringify(next ?? null) !== JSON.stringify(prev ?? null)) {
        merged[field] = next;
        changed = true;
      }
    } catch {
      /* skip */
    }
  }

  return changed ? merged : null;
}

/** In-memory search for listings/dropdowns after decryption */
export function patientMatchesSearchQuery(
  patient: Record<string, unknown>,
  query: string,
): boolean {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return true;

  const fullName = `${patient.firstName ?? ""} ${patient.lastName ?? ""}`.trim().toLowerCase();
  const searchable = [
    fullName,
    patient.patientId,
    patient.email,
    patient.phone,
    patient.nhsNumber,
  ]
    .filter((value) => value != null && String(value).length > 0)
    .map((value) => String(value).toLowerCase());

  return searchable.some((value) => value.includes(normalizedQuery));
}
