import type zh from "./zh";

export default {
  "certificates.title": "Local TLS certificates",
  "certificates.scope":
    "Read identities actually loaded by this process. Expand or refresh to update; no certificate files are read, remote endpoints probed, or certificates issued or rotated.",
  "certificates.validityOnly":
    "Being within validity does not prove trust, name coverage, revocation status or service reachability.",
  "certificates.refresh": "Refresh certificate status",
  "certificates.unsupported":
    "This server version does not provide certificate status. Other node functions remain available.",
  "certificates.interrupted":
    "The read was interrupted. Refresh before reviewing the status.",
  "certificates.observed": "Observed at",
  "certificates.clockUnknown": "Clock unavailable; current validity is unknown",
  "certificates.dateRange": "Date outside display range",
  "certificates.validFrom": "Valid from",
  "certificates.validUntil": "Valid until",
  "certificates.copy": "Copy SHA-256",
  "certificates.copied": "Copied",
  "certificates.role.management": "Management HTTPS",
  "certificates.role.node": "Node mTLS",
  "certificates.role.proxy": "Proxy listener",
  "certificates.source.manual": "Manual configuration",
  "certificates.source.acme": "ACME",
  "certificates.condition.disabled": "No TLS identity configured",
  "certificates.condition.pending": "No normal certificate published yet",
  "certificates.condition.unavailable":
    "Certificate metadata unavailable; TLS state is unknown",
  "certificates.condition.loaded": "Loaded",
  "certificates.condition.time_unknown": "Current validity unknown",
  "certificates.condition.not_yet_valid": "Not yet valid",
  "certificates.condition.expired": "Expired",
  "certificates.condition.expiring": "Expires within seven days",
  "certificates.condition.within_validity": "Within validity",
} satisfies Record<keyof typeof zh, string>;
