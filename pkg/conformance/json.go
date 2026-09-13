package conformance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// strictJSON checks lossless JSON syntax before encoding/json can replace text or
// discard duplicate names. It is not a JCS serializer or a protocol schema check.
func strictJSON(b []byte) (any, error) {
	if len(b) > MaxJSONBytes || !utf8.Valid(b) {
		return nil, fmt.Errorf("JSON size or UTF-8 invalid")
	}
	// Validate escaped UTF-16 in each string before Go's decoder replaces surrogates.
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		i++
		for ; i < len(b) && b[i] != '"'; i++ {
			if b[i] != '\\' {
				continue
			}
			i++
			if i >= len(b) {
				break
			}
			if b[i] != 'u' {
				continue
			}
			if i+4 >= len(b) {
				return nil, fmt.Errorf("short Unicode escape")
			}
			n, e := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
			if e != nil {
				return nil, e
			}
			i += 4
			if n >= 0xd800 && n <= 0xdbff {
				if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
					return nil, fmt.Errorf("unpaired surrogate")
				}
				m, e := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
				if e != nil || m < 0xdc00 || m > 0xdfff {
					return nil, fmt.Errorf("unpaired surrogate")
				}
				i += 6
			} else if n >= 0xdc00 && n <= 0xdfff {
				return nil, fmt.Errorf("unpaired surrogate")
			}
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	members := 0
	var value func(int) (any, error)
	value = func(depth int) (any, error) {
		t, e := d.Token()
		if e != nil {
			return nil, e
		}
		switch x := t.(type) {
		case json.Delim:
			if depth > 64 {
				return nil, fmt.Errorf("JSON nesting exceeds64")
			}
			switch x {
			case '{':
				m := map[string]any{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return nil, e
					}
					key, ok := k.(string)
					if !ok {
						return nil, fmt.Errorf("invalid member")
					}
					if _, ok = m[key]; ok {
						return nil, fmt.Errorf("duplicate member %q", key)
					}
					members++
					if members > 16384 {
						return nil, fmt.Errorf("too many members")
					}
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					m[key] = v
				}
				end, e := d.Token()
				if e != nil || end != json.Delim('}') {
					return nil, fmt.Errorf("unclosed object")
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					v, e := value(depth + 1)
					if e != nil {
						return nil, e
					}
					a = append(a, v)
				}
				end, e := d.Token()
				if e != nil || end != json.Delim(']') {
					return nil, fmt.Errorf("unclosed array")
				}
				return a, nil
			}
			return nil, fmt.Errorf("unexpected delimiter")
		case json.Number:
			n, e := strconv.ParseFloat(string(x), 64)
			if e != nil || math.IsInf(n, 0) || math.IsNaN(n) {
				return nil, fmt.Errorf("nonfinite number")
			}
			if n == 0 && len(x) > 0 && x[0] == '-' {
				return nil, fmt.Errorf("negative zero")
			}
			return x, nil
		default:
			return t, nil
		}
	}
	v, e := value(1)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return v, nil
}

func decode(b []byte, out any) error {
	v, e := strictJSON(b)
	if e != nil {
		return e
	}
	if e = shape(v, reflect.TypeOf(out).Elem()); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// encoding/json matches struct fields case-insensitively; reject that relaxation
// and require every declared schema member before decoding into zero values.
func shape(v any, t reflect.Type) error {
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if v == nil {
			return fmt.Errorf("null member")
		}
		return shape(v, t.Elem())
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("expected object")
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")[0]
			if tag != "-" && tag != "" {
				fields[tag] = f.Type
			}
		}
		for key := range m {
			if _, ok := fields[key]; !ok {
				return fmt.Errorf("unknown member %q", key)
			}
		}
		for key, typ := range fields {
			x, ok := m[key]
			if !ok {
				return fmt.Errorf("missing member %q", key)
			}
			if e := shape(x, typ); e != nil {
				return fmt.Errorf("%s: %w", key, e)
			}
		}
	case reflect.Slice:
		a, ok := v.([]any)
		if !ok {
			return fmt.Errorf("expected array")
		}
		for _, x := range a {
			if e := shape(x, t.Elem()); e != nil {
				return e
			}
		}
	default:
		if v == nil {
			return fmt.Errorf("null member")
		}
	}
	return nil
}
