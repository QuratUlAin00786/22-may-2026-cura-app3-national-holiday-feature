import {
  AveroxCrypto,
  getSDKMetadata,
  getSupportedAlgorithms,
  BadInputError,
  InvalidTagError,
  AveroxCryptoError,
  type EnvelopeWithKMS,
} from "@averox/curaemrencryption-crypto-sdk";

export { BadInputError, InvalidTagError, AveroxCryptoError };
export { AveroxCryptoError as PatientCryptoError };

/** Domain-separated AAD for whole-patient payload authentication */
const PATIENT_RECORD_AAD = "cura-emr:patient-record:v1";

/** Wrapper key for encrypted jsonb column values */
const ENCRYPTED_JSONB_FIELD_KEY = "__encryptedField";

/** medicalHistory key used to store the encrypted patient payload */
export const ENCRYPTED_PATIENT_PAYLOAD_KEY = "__encryptedPatientPayload";

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

let averoxCrypto: AveroxCrypto | null = null;

function getAveroxCrypto(): AveroxCrypto {
  if (!averoxCrypto) {
    averoxCrypto = new AveroxCrypto();
  }
  return averoxCrypto;
}

/** True when SDK vault metadata is present. */
export function isPatientEncryptionConfigured(): boolean {
  try {
    const meta = getSDKMetadata() as {
      vaultApiEndpoint?: string;
      vaultKekName?: string;
      envelopeEncryptionEnabled?: boolean;
      metadata?: { tenant?: string };
    };
    return Boolean(
      meta.vaultApiEndpoint &&
        meta.vaultKekName &&
        meta.metadata?.tenant &&
        meta.envelopeEncryptionEnabled !== false,
    );
  } catch {
    return false;
  }
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

export function fieldAad(fieldName: string): string {
  return `cura-emr:patient-field:${fieldName}:v1`;
}

function sdkSupportedAlgorithms(): Set<string> {
  return new Set(getSupportedAlgorithms().map((alg) => alg.toUpperCase()));
}

function isSdkEnvelope(o: unknown): o is EnvelopeWithKMS {
  if (!o || typeof o !== "object" || Array.isArray(o)) return false;
  const envelope = o as EnvelopeWithKMS;
  const algorithms = sdkSupportedAlgorithms();
  return (
    envelope.v === "2.0" &&
    typeof envelope.alg === "string" &&
    algorithms.has(envelope.alg.toUpperCase()) &&
    typeof envelope.ct === "string" &&
    typeof envelope.iv === "string" &&
    typeof envelope.tag === "string" &&
    typeof envelope.encryptedDEK === "string" &&
    envelope.encryptedDEK.length > 0
  );
}

function parseEnvelope(encryptedData: string): EnvelopeWithKMS {
  let parsed: unknown;
  try {
    parsed = JSON.parse(encryptedData);
  } catch {
    throw new BadInputError("Encrypted patient data is not valid JSON");
  }

  if (!isSdkEnvelope(parsed)) {
    throw new BadInputError("Encrypted patient data has an invalid SDK envelope structure");
  }

  return parsed;
}

/** True when a text column holds an SDK envelope (JSON string or parsed object). */
export function isEncryptedScalarField(value: unknown): boolean {
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed.startsWith("{")) {
      return false;
    }
    try {
      return isSdkEnvelope(JSON.parse(trimmed));
    } catch {
      return false;
    }
  }
  return isSdkEnvelope(value);
}

/** Normalize DB/driver values to envelope JSON for decrypt. */
export function patientEnvelopeJsonFromUnknown(stored: unknown): string | null {
  if (typeof stored === "string") {
    const trimmed = stored.trim();
    return isEncryptedScalarField(trimmed) ? trimmed : null;
  }
  if (isSdkEnvelope(stored)) {
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

async function encryptEnvelope(plaintext: string, aad: string): Promise<EnvelopeWithKMS> {
  if (!isPatientEncryptionConfigured()) {
    throw new AveroxCryptoError(
      "SDK_NOT_CONFIGURED",
      "Encryption SDK is not configured. Vault metadata is missing from the SDK package.",
    );
  }
  return getAveroxCrypto().encrypt(plaintext, aad);
}

async function decryptEnvelope(envelope: EnvelopeWithKMS, aad: string): Promise<Buffer> {
  return getAveroxCrypto().decrypt(envelope, aad);
}

/** Encrypts a scalar patient column value (stored as envelope JSON string). */
export async function encryptPatientField(fieldName: string, plaintext: string): Promise<string> {
  const normalized = plaintext.trim();
  if (!normalized) {
    throw new BadInputError(`Field "${fieldName}" must be non-empty to encrypt`);
  }
  const envelope = await encryptEnvelope(normalized, fieldAad(fieldName));
  return JSON.stringify(envelope);
}

/** Decrypts a scalar patient column envelope. */
export async function decryptPatientField(
  fieldName: string,
  encryptedValue: unknown,
): Promise<string> {
  const json =
    typeof encryptedValue === "string" && isEncryptedScalarField(encryptedValue.trim())
      ? encryptedValue.trim()
      : patientEnvelopeJsonFromUnknown(encryptedValue);
  if (!json) {
    throw new BadInputError(`Field "${fieldName}" is not in encrypted envelope format`);
  }

  const envelope = parseEnvelope(json);
  const plaintext = await decryptEnvelope(envelope, fieldAad(fieldName));
  return plaintext.toString("utf8");
}

export async function encryptPatientEmail(email: string): Promise<string> {
  return encryptPatientField("email", email);
}

export async function decryptPatientEmail(encryptedEmail: string): Promise<string> {
  return decryptPatientField("email", encryptedEmail);
}

async function encryptPatientTextColumn(
  fieldName: PatientTextField,
  value: unknown,
  required = false,
): Promise<string | null> {
  if (value == null || String(value).trim() === "") {
    if (required) {
      throw new BadInputError(`Field "${fieldName}" is required`);
    }
    return null;
  }
  return encryptPatientField(fieldName, String(value));
}

async function encryptPatientJsonbColumn(
  fieldName: PatientJsonbField,
  value: unknown,
): Promise<Record<string, string>> {
  if (value == null || isEmptyObject(value)) {
    return {};
  }
  const serialized = JSON.stringify(value);
  if (serialized === "{}" || serialized === "null") {
    return {};
  }
  return {
    [ENCRYPTED_JSONB_FIELD_KEY]: await encryptPatientField(fieldName, serialized),
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

async function decryptPatientTextColumn(
  fieldName: PatientTextField,
  rawPatient: Record<string, unknown>,
): Promise<unknown> {
  const stored = getRawColumnValue(rawPatient, fieldName);
  const envJson = patientEnvelopeJsonFromUnknown(stored);
  if (!envJson) {
    throw new BadInputError(`Field "${fieldName}" is not encrypted`);
  }
  return decryptPatientField(fieldName, envJson);
}

async function decryptPatientJsonbColumn(
  fieldName: PatientJsonbField,
  rawPatient: Record<string, unknown>,
): Promise<unknown> {
  const stored = getRawColumnValue(rawPatient, fieldName);
  if (stored == null || isEmptyObject(stored)) {
    return {};
  }
  if (typeof stored !== "object" || Array.isArray(stored)) {
    throw new BadInputError(`Field "${fieldName}" has invalid encrypted jsonb shape`);
  }
  const encrypted = (stored as Record<string, unknown>)[ENCRYPTED_JSONB_FIELD_KEY];
  const encJson = patientEnvelopeJsonFromUnknown(encrypted);
  if (!encJson) {
    throw new BadInputError(`Field "${fieldName}" is not encrypted`);
  }
  try {
    return JSON.parse(await decryptPatientField(fieldName, encJson));
  } catch (error) {
    if (error instanceof BadInputError) {
      throw error;
    }
    throw new BadInputError(`Decrypted "${fieldName}" is not valid JSON`);
  }
}

/** Encrypts a complete patient object as a single authenticated SDK envelope payload. */
export async function encryptPatientData(patient: object): Promise<string> {
  if (patient === null || typeof patient !== "object") {
    throw new BadInputError("Patient data must be a non-null object");
  }
  const envelope = await encryptEnvelope(JSON.stringify(patient), PATIENT_RECORD_AAD);
  return JSON.stringify(envelope);
}

/** Decrypts a patient payload produced by encryptPatientData. */
export async function decryptPatientData(encryptedData: string): Promise<object> {
  if (!encryptedData || typeof encryptedData !== "string") {
    throw new BadInputError("Encrypted patient data must be a non-empty string");
  }
  const envelope = parseEnvelope(encryptedData);
  const plaintext = await decryptEnvelope(envelope, PATIENT_RECORD_AAD);
  try {
    return JSON.parse(plaintext.toString("utf8")) as object;
  } catch {
    throw new BadInputError("Decrypted patient data is not valid JSON");
  }
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

/** Decrypt a raw patients table row for display/API use. */
export async function normalizePatientFromDatabaseRow(
  rawPatient: unknown,
): Promise<Record<string, unknown>> {
  if (!rawPatient || typeof rawPatient !== "object") {
    throw new BadInputError("Patient row must be a non-null object");
  }
  return decryptPatientFromStorageRow(rawPatient as Record<string, unknown>);
}

/**
 * Builds a DB row: each PHI column holds its own SDK envelope; full record also in medicalHistory.
 */
export async function preparePatientForStorage(
  patient: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (isEncryptedPatientStorageRow(patient)) {
    throw new BadInputError("Patient record is already encrypted");
  }

  const email = patient.email != null ? String(patient.email).trim() : "";
  if (!email) {
    throw new BadInputError("Patient email is required for encrypted storage");
  }

  const encryptedPayload = await encryptPatientData({ ...patient, email });

  const [
    firstName,
    lastName,
    relation,
    dateOfBirth,
    genderAtBirth,
    encryptedEmail,
    phone,
    nhsNumber,
    address,
    insuranceInfo,
    emergencyContact,
    communicationPreferences,
  ] = await Promise.all([
    encryptPatientTextColumn("firstName", patient.firstName, true),
    encryptPatientTextColumn("lastName", patient.lastName, true),
    encryptPatientTextColumn("relation", patient.relation),
    encryptPatientTextColumn("dateOfBirth", patient.dateOfBirth),
    encryptPatientTextColumn("genderAtBirth", patient.genderAtBirth),
    encryptPatientField("email", email),
    encryptPatientTextColumn("phone", patient.phone),
    encryptPatientTextColumn("nhsNumber", patient.nhsNumber),
    encryptPatientJsonbColumn("address", patient.address),
    encryptPatientJsonbColumn("insuranceInfo", patient.insuranceInfo),
    encryptPatientJsonbColumn("emergencyContact", patient.emergencyContact),
    encryptPatientJsonbColumn("communicationPreferences", patient.communicationPreferences),
  ]);

  return {
    organizationId: patient.organizationId,
    userId: patient.userId ?? null,
    patientId: patient.patientId,
    firstName,
    lastName,
    relation,
    dateOfBirth,
    genderAtBirth,
    email: encryptedEmail,
    phone,
    nhsNumber,
    address,
    insuranceInfo,
    emergencyContact,
    medicalHistory: { [ENCRYPTED_PATIENT_PAYLOAD_KEY]: encryptedPayload },
    riskLevel: patient.riskLevel ?? "low",
    flags: Array.isArray(patient.flags) ? (patient.flags as unknown[]) : [],
    communicationPreferences,
    isActive: patient.isActive !== false,
    isInsured: patient.isInsured === true,
    createdBy: patient.createdBy ?? null,
  };
}

/** Decrypts an encrypted storage row via the SDK. */
export async function decryptPatientFromStorageRow(
  rawPatient: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!isEncryptedPatientStorageRow(rawPatient)) {
    throw new BadInputError("Patient row is not encrypted");
  }

  const decrypted = (await decryptPatientData(extractEncryptedPayload(rawPatient))) as Record<
    string,
    unknown
  >;

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
    result[field] = await decryptPatientTextColumn(field, rawPatient);
  }

  for (const field of PATIENT_ENCRYPTED_JSONB_FIELDS) {
    result[field] = await decryptPatientJsonbColumn(field, rawPatient);
  }

  return result;
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
