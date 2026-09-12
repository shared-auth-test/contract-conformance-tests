// Independently authored TypeSpec peer authority. Generated JSON Schema is evidence only.
import "@typespec/json-schema";
using TypeSpec.JsonSchema;

namespace ExternalPeer;

@id("ExternalPeerContract")
model ExternalPeerContract {
  repository: string;
  enabled: boolean;
  owner?: string;
}
