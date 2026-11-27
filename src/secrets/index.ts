/**
 * Secret detection & redaction building blocks. Redaction entry points live in
 * utils/redact (redact, redactDeep, redactObject); detection in ./detect.
 */
export { DETECTORS, jwtPayload, type Confidence, type Detector } from './detectors';
export { detectSecrets, detectSecretConfidence, type SecretHit } from './detect';
export { scanLine, shouldRedact, detectionConfidence, type SecretSpan } from './scan';
export { isPlaceholder, isSecretKey, entropy } from './placeholder';
export { privateKeyBlocks, redactBlocks } from './multiline';
export { findGitleaks, runGitleaks, parseGitleaksReport, gitleaksToFindings, gitleaksFindings } from './gitleaks';
