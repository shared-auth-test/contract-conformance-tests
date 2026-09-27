// Shared Auth network identity, broker, and downstream federation contract.
// This TypeSpec source and authored.schema.json are independent peer authorities.
// JSON Schema emitted from this file is comparison evidence only.
import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace SharedAuth.NetworkFederation;

@id("FederationRole")
enum FederationRole {
  upstreamRp: "upstream_rp",
  identityBroker: "identity_broker",
  networkIdp: "network_idp",
  publicIdp: "public_idp",
}

@id("DownstreamSubjectType")
enum DownstreamSubjectType {
  pairwise: "pairwise",
  publicSubject: "public",
}

@id("ApplicationEnrollmentPolicy")
enum ApplicationEnrollmentPolicy {
  jit: "jit",
  invitation: "invitation",
  consent: "consent",
}

@id("ApplicationAccountStatus")
enum ApplicationAccountStatus {
  active: "active",
  suspended: "suspended",
  revoked: "revoked",
}

@id("UpstreamIdentityEvidence")
model UpstreamIdentityEvidence {
  provider_id: string;
  issuer: string;
  provider_tenant: string;
  provider_subject: string;
  assurance: string;
  authenticated_at: string;
  verified_email?: string;
}

@id("BrokeredPrincipalLink")
model BrokeredPrincipalLink {
  principal_id: string;
  provider_id: string;
  issuer: string;
  provider_tenant: string;
  provider_subject: string;
  linked_at: string;
  link_proof: string;
}

@id("ApplicationAccountContract")
model ApplicationAccountContract {
  application_id: string;
  application_account_id: string;
  principal_id: string;
  status: ApplicationAccountStatus;
  enrollment_policy: ApplicationEnrollmentPolicy;
}

// A subject sector is registration metadata, not a signing key and not a secret.
// Multiple clients may intentionally share one sector and therefore one pairwise
// subject for the same principal. Pairwise subjects are persisted identity-plane
// authority data, so JWT signing-key rotation cannot silently change `sub`.
@id("SubjectSectorContract")
model SubjectSectorContract {
  sector_id: string;
  sector_identifier: string;
  client_ids: string[];
  subject_version: string;
  active: boolean;
}

// Internal identity-plane mapping. principal_id is intentionally absent from
// the downstream assertion even though the server uses it to resolve this row.
@id("ApplicationPairwiseSubject")
model ApplicationPairwiseSubject {
  sector_id: string;
  application_id: string;
  application_account_id: string;
  subject: string;
  subject_version: string;
}

@id("DownstreamIdentityAssertion")
model DownstreamIdentityAssertion {
  issuer: string;
  client_id: string;
  audience: string;
  subject: string;
  subject_type: DownstreamSubjectType;
  session_id: string;
  scopes: string[];
  acr?: string;
  amr: string[];
}

@id("NetworkSsoHandoff")
model NetworkSsoHandoff {
  source_session_id: string;
  target_application_id: string;
  target_client_id: string;
  subject_sector_id: string;
  authorization_code_id: string;
  credential_prompted: boolean;
  downstream: DownstreamIdentityAssertion;
}

@id("FederationCapabilityContract")
model FederationCapabilityContract {
  roles: FederationRole[];
  pairwise_subjects_default: boolean;
  email_linking_allowed: boolean;
  raw_upstream_tokens_exposed_downstream: boolean;
  child_origins_share_sso_cookie: boolean;
  network_sso: boolean;
  public_oidc_provider: boolean;
}
