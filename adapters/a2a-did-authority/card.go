package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

const claimsURI = "https://inspection.invalid/received-document"

// This ASCII/integer fixture uses standard JSON plus standard Ed25519 directly,
// independently of ADK signing helpers and the subject's JCS implementation.
func signedCard(target string) []byte {
	card := map[string]any{"name": "authority fixture", "description": "", "version": "1", "supportedInterfaces": []any{map[string]any{"url": target, "protocolBinding": "https://sage-x-project.github.io/sage-spec/a2a/0.10.0/binding", "protocolVersion": "1.0"}}, "capabilities": map[string]any{"streaming": false, "extensions": []any{map[string]any{"uri": "https://sage-x-project.github.io/sage-spec/a2a/0.10.0/extension", "required": true, "params": map[string]any{"sageVersion": "0.10.0", "did": serverDID, "recordVersion": "17", "issued": epoch, "expires": epoch + 5}}}}, "defaultInputModes": []string{"application/json"}, "defaultOutputModes": []string{"application/json"}, "skills": []any{map[string]any{"id": "inspection", "name": "inspection", "description": "", "tags": []string{"inspection"}}}}
	// Optional informational document. No peer key or negative mode enters this CLI.
	pub := signingKey(serverDID).Public().(ed25519.PublicKey)
	document := map[string]any{"@context": []string{"https://www.w3.org/ns/did/v1"}, "id": serverDID, "verificationMethod": []any{map[string]any{"id": serverDID + "#sign", "type": "JsonWebKey", "controller": serverDID, "publicKeyJwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}}}}
	capabilities := card["capabilities"].(map[string]any)
	capabilities["extensions"] = append(capabilities["extensions"].([]any), map[string]any{"uri": claimsURI, "params": map[string]any{"didDocument": document}})
	payload := must(json.Marshal(card))
	header := must(json.Marshal(map[string]string{"alg": "Ed25519", "kid": serverDID + "#sign", "typ": "sage-a2a-card+jws"}))
	enc := base64.RawURLEncoding.EncodeToString
	protected := enc(header)
	signature := ed25519.Sign(signingKey(serverDID), []byte(protected+"."+enc(payload)))
	card["signatures"] = []any{map[string]string{"protected": protected, "signature": enc(signature)}}
	return must(json.Marshal(card))
}
