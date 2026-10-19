// This fixed normal card uses standard JSON and Ed25519 for an owned fixture.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
)

func signedCard(target string) []byte {
	card := map[string]any{"name": "inspection fixture", "description": "", "version": "1", "supportedInterfaces": []any{map[string]any{"url": target, "protocolBinding": "https://sage-x-project.github.io/sage-spec/a2a/0.10.0/binding", "protocolVersion": "1.0"}}, "capabilities": map[string]any{"streaming": false, "extensions": []any{map[string]any{"uri": "https://sage-x-project.github.io/sage-spec/a2a/0.10.0/extension", "required": true, "params": map[string]any{"sageVersion": "0.10.0", "did": serverDID, "recordVersion": "17", "issued": epoch, "expires": epoch + 5}}}}, "defaultInputModes": []string{"application/json"}, "defaultOutputModes": []string{"application/json"}, "skills": []any{map[string]any{"id": "inspection", "name": "inspection", "description": "", "tags": []string{"inspection"}}}}
	payload := must(json.Marshal(card))
	header := must(json.Marshal(map[string]string{"alg": "Ed25519", "kid": serverDID + "#sign", "typ": "sage-a2a-card+jws"}))
	enc := base64.RawURLEncoding.EncodeToString
	protected := enc(header)
	signature := ed25519.Sign(signingKey(serverDID), []byte(protected+"."+enc(payload)))
	card["signatures"] = []any{map[string]string{"protected": protected, "signature": enc(signature)}}
	return must(json.Marshal(card))
}
