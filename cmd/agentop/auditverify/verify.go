// Package auditverify checks signed OCSF audit records the way an
// independent auditor would: from the exported bytes and the signing
// authority's public key alone, trusting nothing cortex says about them.
//
// The record contract is AID-EMIT-1 (serialization 2, JCS): a record's
// fingerprint is SHA-256 over the RFC 8785 canonical form of the record with
// the attestation's `fingerprint` and `signatures` and the record's
// `unmapped.signature_b64` and `unmapped.signature_key_id` removed. The DSSE
// signature is ECDSA P-256 over the pre-authentication encoding of those
// same bytes. Each record links to its predecessor's fingerprint through
// `prev_event`, and carries a dense `stream_seq` per (epoch, stream).
//
// Verification lives in agentop rather than in cortex on purpose: a cortex
// that reported its own records as verified would be vouching for itself.
package auditverify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// dssePayloadType is the DSSE payload type the sink signs under.
const dssePayloadType = "application/vnd.ocsf.event+json"

// SignatureState is what a record's signature check found.
type SignatureState string

const (
	// SignatureValid: the signature verifies over the record's canonical
	// bytes under the key its key id names.
	SignatureValid SignatureState = "valid"
	// SignatureInvalid: the signature does not verify, so the record or its
	// signature was changed after signing.
	SignatureInvalid SignatureState = "invalid"
	// SignatureUnsigned: the record carries no signature (chained only).
	SignatureUnsigned SignatureState = "unsigned"
	// SignatureUnknownKey: the record names a key id the verifier was not
	// given, so the signature cannot be checked.
	SignatureUnknownKey SignatureState = "unknown-key"
)

// LinkState is what a record's link to its predecessor shows.
type LinkState string

const (
	// LinkGenesis: the first record of its chain; it has no predecessor.
	LinkGenesis LinkState = "genesis"
	// LinkIntact: the predecessor is present and its recomputed fingerprint
	// matches the link.
	LinkIntact LinkState = "intact"
	// LinkBroken: the predecessor is present but its recomputed fingerprint
	// does not match, so the predecessor was changed.
	LinkBroken LinkState = "broken"
	// LinkMissing: the predecessor is not among the records, so it was lost
	// or deleted. A stream gap usually accounts for it.
	LinkMissing LinkState = "missing"
	// LinkUnchained: the record has no attestation at all.
	LinkUnchained LinkState = "unchained"
)

// Stamp is a record's position in the engine's audit stream.
type Stamp struct {
	Epoch     uint64
	StreamID  string
	StreamSeq uint64
}

// Result is the verdict for one record.
type Result struct {
	// Index is the record's position in the input.
	Index int
	// UID is the record's metadata.uid, when it parsed.
	UID string
	// Err is set when the record is not a JSON object or lacks the fields
	// verification needs; the other fields are then zero.
	Err error
	// Fingerprint is the fingerprint recomputed from the record's bytes: what an independent
	// copy, such as a ledger receipt, is compared against.
	Fingerprint string
	// FingerprintOK: the stored fingerprint equals the recomputed one.
	FingerprintOK bool
	Signature     SignatureState
	Link          LinkState
	// Stamp is nil when the record carries no stream stamp.
	Stamp *Stamp
}

// Tampered reports whether the record itself fails a check: its content no
// longer matches its fingerprint or signature, or its predecessor was
// changed. A missing predecessor is loss, reported through Gaps, not
// tampering, and a record with no attestation has nothing to fail.
func (r Result) Tampered() bool {
	if r.Err != nil || r.Link == LinkUnchained {
		return false
	}
	return !r.FingerprintOK || r.Signature == SignatureInvalid || r.Link == LinkBroken
}

// Gap is a run of stream positions with no record: records that existed and
// did not arrive, or were deleted.
type Gap struct {
	Epoch    uint64
	StreamID string
	// From and To are the first and last missing stream_seq, inclusive.
	From, To uint64
}

// Report is the verdict for a set of records.
type Report struct {
	Results []Result
	Gaps    []Gap
}

// Keys maps a signing key id to its public key.
type Keys map[string]*ecdsa.PublicKey

// ParsePublicKeyPEM reads a PEM-encoded P-256 public key (SPKI).
func ParsePublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, want an ECDSA public key", key)
	}
	return ec, nil
}

// Verify checks every record and the streams they form. Records may be in
// any order: the sink can write two concurrent records in the opposite order
// from their chain positions, so links are resolved by uid and gaps by
// stream_seq, never by arrival.
func Verify(records [][]byte, keys Keys) Report {
	type parsed struct {
		doc  map[string]any
		fp   string
		prev string // predecessor uid, "" for genesis
		link string // predecessor fingerprint the record claims
	}
	report := Report{Results: make([]Result, len(records))}
	docs := make([]*parsed, len(records))
	recomputed := map[string]string{} // uid -> recomputed fingerprint

	for i, raw := range records {
		res := &report.Results[i]
		res.Index = i
		doc, err := decode(raw)
		if err != nil {
			res.Err = fmt.Errorf("not a JSON object: %w", err)
			continue
		}
		res.UID = str(dig(doc, "metadata", "uid"))
		res.Stamp = stampOf(doc)

		att, _ := first(doc["attestation_list"]).(map[string]any)
		if att == nil {
			res.Link = LinkUnchained
			res.Signature = SignatureUnsigned
			continue
		}
		canonical, err := signingInput(doc)
		if err != nil {
			res.Err = err
			continue
		}
		sum := sha256.Sum256(canonical)
		fp := hex.EncodeToString(sum[:])
		res.Fingerprint = fp
		res.FingerprintOK = fp == str(dig(att, "fingerprint", "value"))
		res.Signature = checkSignature(doc, canonical, keys)
		if res.UID != "" {
			recomputed[res.UID] = fp
		}
		p := &parsed{doc: doc, fp: fp}
		if prev, ok := att["prev_event"].(map[string]any); ok {
			p.prev = str(prev["uid"])
			p.link = str(dig(prev, "fingerprint", "value"))
		}
		docs[i] = p
	}

	for i, p := range docs {
		if p == nil {
			continue
		}
		res := &report.Results[i]
		switch fp, seen := recomputed[p.prev]; {
		case p.prev == "":
			res.Link = LinkGenesis
		case !seen:
			res.Link = LinkMissing
		case fp == p.link:
			res.Link = LinkIntact
		default:
			res.Link = LinkBroken
		}
	}

	report.Gaps = gaps(report.Results)
	return report
}

// decode parses one record with its numbers kept as written, so the
// canonical form and the stream stamp see the emitted digits.
func decode(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, errors.New("null")
	}
	return doc, nil
}

// signingInput is the record's canonical form with the four post-hash
// members removed, as AID-EMIT-1 section 4 defines it. It works on a copy:
// doc keeps its signature fields for checkSignature.
func signingInput(doc map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonicalize(&buf, covered(doc)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// covered is doc without the four post-hash members: what the fingerprint and signature cover,
// and what a ledger receipt stores. It works on a copy; doc is not changed.
func covered(doc map[string]any) map[string]any {
	cp := cloneMap(doc)
	if att, ok := first(cp["attestation_list"]).(map[string]any); ok {
		att = cloneMap(att)
		delete(att, "fingerprint")
		delete(att, "signatures")
		cp["attestation_list"] = append([]any{att}, cp["attestation_list"].([]any)[1:]...)
	}
	if un, ok := cp["unmapped"].(map[string]any); ok {
		un = cloneMap(un)
		delete(un, "signature_b64")
		delete(un, "signature_key_id")
		if len(un) == 0 {
			delete(cp, "unmapped")
		} else {
			cp["unmapped"] = un
		}
	}
	return cp
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func checkSignature(doc map[string]any, canonical []byte, keys Keys) SignatureState {
	sigB64 := str(dig(doc, "unmapped", "signature_b64"))
	if sigB64 == "" {
		return SignatureUnsigned
	}
	key := keys[str(dig(doc, "unmapped", "signature_key_id"))]
	if key == nil {
		return SignatureUnknownKey
	}
	der, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return SignatureInvalid
	}
	digest := sha256.Sum256(pae(canonical))
	if !ecdsa.VerifyASN1(key, digest[:], der) {
		return SignatureInvalid
	}
	return SignatureValid
}

// pae is the DSSE pre-authentication encoding over dssePayloadType.
func pae(payload []byte) []byte {
	out := []byte("DSSEv1 " + strconv.Itoa(len(dssePayloadType)) + " " + dssePayloadType + " " +
		strconv.Itoa(len(payload)) + " ")
	return append(out, payload...)
}

// gaps finds the missing stream_seq values per (epoch, stream). A stream
// whose lowest sequence is above 0 is missing its head too.
func gaps(results []Result) []Gap {
	type key struct {
		epoch  uint64
		stream string
	}
	seen := map[key][]uint64{}
	for _, r := range results {
		if r.Stamp != nil {
			k := key{r.Stamp.Epoch, r.Stamp.StreamID}
			seen[k] = append(seen[k], r.Stamp.StreamSeq)
		}
	}
	var out []Gap
	for k, seqs := range seen {
		sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
		next := uint64(0)
		for _, s := range seqs {
			if s > next {
				out = append(out, Gap{Epoch: k.epoch, StreamID: k.stream, From: next, To: s - 1})
			}
			if s+1 > next {
				next = s + 1
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Epoch != out[j].Epoch {
			return out[i].Epoch < out[j].Epoch
		}
		if out[i].StreamID != out[j].StreamID {
			return out[i].StreamID < out[j].StreamID
		}
		return out[i].From < out[j].From
	})
	return out
}

func stampOf(doc map[string]any) *Stamp {
	s, ok := dig(doc, "unmapped", "aid.stream").(map[string]any)
	if !ok {
		return nil
	}
	epoch, err1 := strconv.ParseUint(numStr(s["epoch"]), 10, 64)
	seq, err2 := strconv.ParseUint(numStr(s["stream_seq"]), 10, 64)
	if err1 != nil || err2 != nil {
		return nil
	}
	return &Stamp{Epoch: epoch, StreamID: str(s["stream_id"]), StreamSeq: seq}
}

func dig(v any, path ...string) any {
	for _, p := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[p]
	}
	return v
}

func first(v any) any {
	if l, ok := v.([]any); ok && len(l) > 0 {
		return l[0]
	}
	return nil
}

func numStr(v any) string {
	n, _ := v.(json.Number)
	return string(n)
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
