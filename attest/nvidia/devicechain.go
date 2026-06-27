// NVIDIA GPU device-identity certificate chain verification.
//
// The public key that signs the SPDM MEASUREMENTS response is the GPU's
// attestation key. By itself a valid SPDM signature only proves "some key
// signed these measurements". To prove the key belongs to a genuine NVIDIA
// GPU we verify the GPU's certificate chain to an operator-pinned NVIDIA
// device-identity root CA:
//
//	leaf (GPU attestation cert, ECDSA P-384)
//	  -> NVIDIA GPU attestation intermediate(s)
//	    -> NVIDIA device-identity root CA   <-- operator pins this
//
// The root is supplied by the operator (WithNVTrustDeviceRoots), never
// taken from the evidence — exactly as AMD's ARK is pinned for SEV-SNP and
// the RIM signing key is pinned for the RIM. There is no insecure mode: an
// empty root pool means the local SPDM path is refused.
//
// Clean-room: standard X.509 path validation against an operator pool. No
// NVIDIA root certificate is vendored; production wiring loads NVIDIA's
// published device-identity root PEM into the pool at startup.
package nvidia

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Errors returned by chain verification.
var (
	ErrChainEmpty       = errors.New("nvidia/chain: empty certificate chain")
	ErrChainBadPEM      = errors.New("nvidia/chain: certificate is not valid PEM/DER")
	ErrChainNoRoots     = errors.New("nvidia/chain: no device-identity roots configured")
	ErrChainUntrusted   = errors.New("nvidia/chain: leaf does not chain to a pinned root")
	ErrChainLeafKeyType = errors.New("nvidia/chain: leaf public key type unsupported")
)

// ParseCertChainPEM decodes a leaf-first list of PEM certificate blocks
// into parsed certificates. Each element may itself contain multiple
// concatenated PEM blocks (the typical NVIDIA evidence packs the whole
// chain in one string); all blocks are flattened, preserving order.
func ParseCertChainPEM(pems []string) ([]*x509.Certificate, error) {
	if len(pems) == 0 {
		return nil, ErrChainEmpty
	}
	var certs []*x509.Certificate
	for _, p := range pems {
		rest := []byte(p)
		for {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrChainBadPEM, err)
			}
			certs = append(certs, c)
		}
	}
	if len(certs) == 0 {
		return nil, ErrChainEmpty
	}
	return certs, nil
}

// VerifyDeviceChain validates a leaf-first certificate chain to the pinned
// device-identity roots and returns the verified leaf. chain[0] is the GPU
// attestation leaf; chain[1:] are intermediates. The root is NOT expected
// in the chain — it is supplied via roots and pinned by the operator.
//
// ExtKeyUsageAny is used because NVIDIA GPU attestation leaves do not
// carry a TLS-server EKU; path, validity window, and signatures are still
// fully checked against the pinned root.
func VerifyDeviceChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, ErrChainEmpty
	}
	if roots == nil {
		return nil, ErrChainNoRoots
	}
	// CertPool offers no public emptiness check; the operator-supplied pool
	// is assumed non-empty when non-nil. An empty pool simply fails the
	// Verify below with ErrChainUntrusted, which is the correct refusal.

	intermediates := x509.NewCertPool()
	for _, ic := range chain[1:] {
		intermediates.AddCert(ic)
	}
	leaf := chain[0]
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChainUntrusted, err)
	}
	return leaf, nil
}

// LeafSPDMKey returns the leaf's public key in the form the SPDM verifier
// consumes, rejecting key types no NVIDIA GPU attestation key uses.
func LeafSPDMKey(leaf *x509.Certificate) (crypto.PublicKey, error) {
	switch leaf.PublicKey.(type) {
	case interface{ Equal(crypto.PublicKey) bool }:
		// *ecdsa.PublicKey and *rsa.PublicKey both satisfy this; the SPDM
		// verifier does the final algo<->key-type binding.
		return leaf.PublicKey, nil
	default:
		return nil, fmt.Errorf("%w: %T", ErrChainLeafKeyType, leaf.PublicKey)
	}
}
