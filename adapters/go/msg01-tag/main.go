// Observe an independently signed HTTP request using the pinned Go core.
// This adapter only checks the RFC 9421 base and Ed25519 signature.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"

	core "github.com/sage-x-project/sage/pkg/agent/core/rfc9421"
)

type request struct {
	RequestHex   string `json:"request_hex"`
	PublicKeyHex string `json:"public_key_hex"`
}

type response struct {
	BaseHex        string `json:"base_hex"`
	SignatureValid bool   `json:"signature_valid"`
}

func run(input io.Reader, output io.Writer) error {
	var item request
	decoder := json.NewDecoder(io.LimitReader(input, 16_385))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&item); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	wire, err := hex.DecodeString(item.RequestHex)
	if err != nil {
		return err
	}
	public, err := hex.DecodeString(item.PublicKeyHex)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return io.ErrUnexpectedEOF
	}
	message, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil {
		return err
	}
	defer func() { _ = message.Body.Close() }()
	params, err := core.ParseSignatureInput(message.Header.Get("Signature-Input"))
	if err != nil || params["sig1"] == nil {
		return io.ErrUnexpectedEOF
	}
	base, err := core.NewCanonicalizer().BuildSignatureBase(message, "sig1", params["sig1"])
	if err != nil {
		return err
	}
	signatures, err := core.ParseSignature(message.Header.Get("Signature"))
	if err != nil || len(signatures["sig1"]) != ed25519.SignatureSize {
		return io.ErrUnexpectedEOF
	}
	return json.NewEncoder(output).Encode(response{
		BaseHex: hex.EncodeToString([]byte(base)),
		SignatureValid: ed25519.Verify(ed25519.PublicKey(public),
			[]byte(base), signatures["sig1"]),
	})
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		os.Exit(2)
	}
}
