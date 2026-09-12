import "@typespec/json-schema";

using TypeSpec.JsonSchema;

namespace SharedAuth.Iam;

@id("CapabilityStatus")
enum CapabilityStatus {
  implemented: "implemented",
  partial: "partial",
  planned: "planned",
  blocked: "blocked",
}

@id("CapabilityCategory")
enum CapabilityCategory {
  coreAuth: "core_auth",
  multiFactor: "multi_factor",
  passkeys: "passkeys",
  organizations: "organizations",
  enterpriseSso: "enterprise_sso",
  directoryProvisioning: "directory_provisioning",
  lifecycle: "lifecycle",
  policyRiskAudit: "policy_risk_audit",
  brandingLocalization: "branding_localization",
}

@id("CapabilityEvidence")
model CapabilityEvidence {
  feature: string;
  category: CapabilityCategory;
  status: CapabilityStatus;
  sourceRepository: string;
  sourceRevision: string;
  tests: string[];
}

@id("CapabilityCatalog")
model CapabilityCatalog {
  version: string;
  capabilities: CapabilityEvidence[];
}
