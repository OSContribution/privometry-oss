// Package signing signs and verifies Privometry's DSSE envelopes: policy bundles,
// entitlements, license files, risk feeds, adapter sets and key sets.
//
// A signature is Ed25519 over the DSSE pre-authentication encoding (PAE) of
// the payload type and the exact payload bytes. An envelope verifies when at
// least one signature comes from a key in the trusted key set that has the
// expected role and is inside its validity window.
package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/cn-solutions/privometry/privometry-oss/internal/contract"
)

// Errors returned by Verify. Callers may match them with errors.Is.
var (
	ErrPayloadType      = errors.New("signing: unexpected payload type")
	ErrNoValidSignature = errors.New("signing: no valid signature from a trusted key")
	ErrRollback         = errors.New("signing: key set version is not newer")
	ErrMalformed        = errors.New("signing: malformed envelope")
)

// Envelope is a DSSE envelope (specs/common/v1/dsse.schema.json).
type Envelope = contract.Envelope

// Signature is one DSSE signature.
type Signature = contract.EnvelopeSignature

// Key is a trusted public key for one role.
type Key struct {
	KeyID     string
	Role      string
	Public    ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time // zero means no end
}

// KeySet is a privometry.keyset/v1 document.
type KeySet struct {
	Version int
	Keys    []Key
}

// PAE is the DSSE v1 pre-authentication encoding.
func PAE(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

// KeyID formats <role>:<name>:<first 16 hex of SHA-256 of the public key>.
func KeyID(role, name string, pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return role + ":" + name + ":" + hex.EncodeToString(sum[:8])
}

// Sign returns an envelope with one signature.
func Sign(payloadType string, payload []byte, keyID string, priv ed25519.PrivateKey) Envelope {
	return Envelope{
		PayloadType: payloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, PAE(payloadType, payload)))}},
	}
}

// ParseKeySet decodes a privometry.keyset/v1 document and checks that each key ID
// matches its role and public key.
func ParseKeySet(raw []byte) (*KeySet, error) {
	var doc contract.KeySet
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("signing: key set: %w", err)
	}
	if doc.Schema != contract.KeySetSchema {
		return nil, fmt.Errorf("signing: key set schema is %q", doc.Schema)
	}
	ks := &KeySet{Version: int(doc.Version)}
	for _, k := range doc.Keys {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("signing: key %s: bad public key", k.KeyID)
		}
		role := string(k.Role)
		parts := strings.Split(k.KeyID, ":")
		if len(parts) != 3 || parts[0] != role || KeyID(role, parts[1], pub) != k.KeyID {
			return nil, fmt.Errorf("signing: key %s: key ID does not match role and public key", k.KeyID)
		}
		key := Key{KeyID: k.KeyID, Role: role, Public: pub, NotBefore: k.NotBefore.Time}
		if k.NotAfter != nil {
			key.NotAfter = k.NotAfter.Time
		}
		ks.Keys = append(ks.Keys, key)
	}
	return ks, nil
}

// Verify checks an envelope and returns its payload. The payload type must
// equal payloadType, and at least one signature must come from a key in ks
// with the given role that is valid at now.
func Verify(raw []byte, ks *KeySet, role, payloadType string, now time.Time) ([]byte, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if env.PayloadType != payloadType {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrPayloadType, env.PayloadType, payloadType)
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	msg := PAE(env.PayloadType, payload)
	for _, s := range env.Signatures {
		sig, err := base64.StdEncoding.Strict().DecodeString(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		for _, k := range ks.Keys {
			if k.KeyID != s.KeyID || k.Role != role || now.Before(k.NotBefore) || (!k.NotAfter.IsZero() && now.After(k.NotAfter)) {
				continue
			}
			if ed25519.Verify(k.Public, msg, sig) {
				return payload, nil
			}
		}
	}
	return nil, ErrNoValidSignature
}

// PayloadTypeKeySet is the DSSE payload type of a signed key set.
const PayloadTypeKeySet = "application/vnd.privometry.keyset+json"

// VerifyKeySetUpdate verifies a key set signed by a root key of current and
// returns it. The new version must be higher than current's.
func VerifyKeySetUpdate(raw []byte, current *KeySet, now time.Time) (*KeySet, error) {
	payload, err := Verify(raw, current, "root", PayloadTypeKeySet, now)
	if err != nil {
		return nil, err
	}
	next, err := ParseKeySet(payload)
	if err != nil {
		return nil, err
	}
	if next.Version <= current.Version {
		return nil, fmt.Errorf("%w: %d after %d", ErrRollback, next.Version, current.Version)
	}
	return next, nil
}
