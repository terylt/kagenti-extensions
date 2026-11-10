package auditverify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// canonicalize writes v, decoded with json.Decoder.UseNumber, in the form
// the sink hashes: RFC 8785 (JCS) except that an integer is written exactly
// as given. That is what the sink's canonicalizer does, and it matters for
// the nanosecond epoch, which a double cannot hold: rendering every number
// through a double, as a strict JCS library does, would change its digits
// and report an honest record as tampered.
//
//   - Object keys sort by UTF-16 code units.
//   - An integer that fits in 64 bits is written as given; any other number
//     takes the ES6 Number.prototype.toString form.
//   - Strings escape only `"`, `\` and control characters, with the short
//     forms for \b \t \n \f \r and lowercase \u00xx for the rest, as the
//     sink's JSON encoder does. Go's encoder escapes more (`<`, `>`, `&`,
//     U+2028, U+2029), so it is not used here.
func canonicalize(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		buf.WriteString(strconv.FormatBool(t))
	case string:
		writeString(buf, t)
	case json.Number:
		s, err := canonicalNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case []any:
		buf.WriteByte('[')
		for i, el := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalize(buf, el); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := canonicalize(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("unexpected JSON value %T", v)
	}
	return nil
}

// canonicalNumber renders a JSON number literal. A literal with no fraction
// or exponent that fits in an int64 or uint64 is an integer and is written
// as given (normalized, so -0 is 0); anything else is a double in ES6 form.
func canonicalNumber(lit string) (string, error) {
	if !strings.ContainsAny(lit, ".eE") {
		if i, err := strconv.ParseInt(lit, 10, 64); err == nil {
			return strconv.FormatInt(i, 10), nil
		}
		if u, err := strconv.ParseUint(lit, 10, 64); err == nil {
			return strconv.FormatUint(u, 10), nil
		}
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("number %q: %w", lit, err)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("number %q has no JSON form", lit)
	}
	return es6Number(f), nil
}

// es6Number is ECMA-262 Number::toString(x) for a finite double: the
// shortest digits that round-trip, laid out by the decimal exponent.
func es6Number(x float64) string {
	if x == 0 {
		return "0" // and -0
	}
	if x < 0 {
		return "-" + es6Number(-x)
	}
	// 'e' with precision -1 gives the shortest round-trip digits:
	// d.ddddde±xx. s is the digits, n the position of the decimal point.
	mant, expPart, _ := strings.Cut(strconv.FormatFloat(x, 'e', -1, 64), "e")
	s := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expPart)
	k, n := len(s), exp+1
	switch {
	case k <= n && n <= 21:
		return s + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return s[:n] + "." + s[n:]
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + s
	}
	e := n - 1
	sign := "+"
	if e < 0 {
		sign, e = "-", -e
	}
	if k == 1 {
		return s + "e" + sign + strconv.Itoa(e)
	}
	return s[:1] + "." + s[1:] + "e" + sign + strconv.Itoa(e)
}

func writeString(buf *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\t':
			buf.WriteString(`\t`)
		case '\n':
			buf.WriteString(`\n`)
		case '\f':
			buf.WriteString(`\f`)
		case '\r':
			buf.WriteString(`\r`)
		default:
			if c < 0x20 {
				buf.WriteString(`\u00`)
				buf.WriteByte(hex[c>>4])
				buf.WriteByte(hex[c&0xf])
			} else {
				buf.WriteByte(c)
			}
		}
	}
	buf.WriteByte('"')
}

// utf16Less orders strings by UTF-16 code units (RFC 8785 section 3.2.3).
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}
