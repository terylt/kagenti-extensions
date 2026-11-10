package auditverify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
)

// Change is one field whose value differs between two copies of a record.
type Change struct {
	// Path names the field, dot-separated, with array indexes in brackets:
	// "action", "unmapped.aid.decision.steps[0].action".
	Path string
	// Was is the field in the reference copy and Now in the copy under
	// question, each as canonical JSON; "" when the field is absent there.
	Was, Now string
}

// Changes lists every field that differs between a reference copy of a
// record, such as the content a ledger receipted, and the record under
// question, such as what cortex serves now. Both are compared on what the
// signature covers, so the signature material, which a ledger does not keep,
// never shows as a change. Changes are sorted by path.
func Changes(reference, record []byte) ([]Change, error) {
	ref, err := decode(reference)
	if err != nil {
		return nil, fmt.Errorf("reference copy: %w", err)
	}
	got, err := decode(record)
	if err != nil {
		return nil, fmt.Errorf("record: %w", err)
	}
	var out []Change
	if err := walk("", covered(ref), covered(got), &out); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func walk(path string, was, now any, out *[]Change) error {
	if wm, ok := was.(map[string]any); ok {
		if nm, ok := now.(map[string]any); ok {
			keys := map[string]bool{}
			for k := range wm {
				keys[k] = true
			}
			for k := range nm {
				keys[k] = true
			}
			for k := range keys {
				if err := walk(join(path, k), wm[k], nm[k], out); err != nil {
					return err
				}
			}
			return nil
		}
	}
	if wa, ok := was.([]any); ok {
		if na, ok := now.([]any); ok && len(wa) == len(na) {
			for i := range wa {
				if err := walk(path+"["+strconv.Itoa(i)+"]", wa[i], na[i], out); err != nil {
					return err
				}
			}
			return nil
		}
	}
	w, err := render(was)
	if err != nil {
		return err
	}
	n, err := render(now)
	if err != nil {
		return err
	}
	if w != n {
		*out = append(*out, Change{Path: path, Was: w, Now: n})
	}
	return nil
}

// render is v's canonical JSON, or "" for an absent field.
func render(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	var buf bytes.Buffer
	if err := canonicalize(&buf, v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// Fingerprint is the AID-EMIT-1 fingerprint of a record or of a ledger's
// copy of one: SHA-256 over the canonical form of its covered fields, in hex.
// A ledger copy already holds only the covered fields; a full record has its
// signature material removed first, so both give the same value.
func Fingerprint(record []byte) (string, error) {
	doc, err := decode(record)
	if err != nil {
		return "", err
	}
	canonical, err := signingInput(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// PrevFingerprint is the fingerprint a record says its predecessor had (its
// attestation's prev_event), or "" for a record that names none.
func PrevFingerprint(record []byte) string {
	doc, err := decode(record)
	if err != nil {
		return ""
	}
	att, _ := first(doc["attestation_list"]).(map[string]any)
	return str(dig(att, "prev_event", "fingerprint", "value"))
}
