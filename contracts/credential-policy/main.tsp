import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace SharedAuthCredentialPolicy;

@id("CredentialPolicyV1")
model CredentialPolicyV1 {
  @minValue(1)
  @maxValue(1)
  version: integer;

  @minLength(1)
  @maxLength(128)
  issuer: string;

  @minLength(1)
  @maxLength(128)
  audience: string;

  @minValue(60)
  @maxValue(86400)
  session_ttl_seconds: integer;

  passkey_required: boolean;
}
