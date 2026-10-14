package driver

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

type credentials struct {
	mu     sync.Mutex
	values map[string]string
	next   uint64
}

const maxCredentialLine = 64 << 10
const maxCredentialBytes = 1 << 20

func loadCredentials(input io.Reader) (*credentials, error) {
	c := &credentials{values: map[string]string{}}
	if input == nil {
		return nil, failure("driver", "driver_failed")
	}
	if closer, ok := input.(io.Closer); ok {
		defer closer.Close()
	}
	r := bufio.NewReader(io.LimitReader(input, maxCredentialBytes+1))
	total := 0
	for {
		line, err := readLineLimit(r, maxCredentialLine)
		if errors.Is(err, io.EOF) {
			return c, nil
		}
		total += len(line) + 1
		var item struct {
			Ref   string `json:"ref"`
			Value string `json:"value"`
		}
		if err != nil || total > maxCredentialBytes || validateJSON(line) != nil || decode(line, &item, "ref", "value") != nil || !validReference(item.Ref) || item.Value == "" {
			c.erase()
			return nil, failure("driver", "protocol_violation")
		}
		if _, exists := c.values[item.Ref]; exists {
			c.erase()
			return nil, failure("driver", "protocol_violation")
		}
		c.values[item.Ref] = item.Value
	}
}

func (c *credentials) erase() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.values)
}

func (c *credentials) resolve(ref string) (string, *Error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.values[ref]
	if !ok {
		return "", failure("driver", "invalid_reference")
	}
	return value, nil
}

func (c *credentials) reference(value string) *string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.referenceLocked(value)
}

func (c *credentials) referenceLocked(value string) *string {
	if value == "" {
		return nil
	}
	// Choose a stable name when two supplied references have equal values.
	name := ""
	for ref, known := range c.values {
		if known == value && (name == "" || ref < name) {
			name = ref
		}
	}
	if name == "" {
		for {
			c.next++
			name = fmt.Sprintf("d:credential:%d", c.next)
			if _, exists := c.values[name]; !exists {
				break
			}
		}
		c.values[name] = value
	}
	return new(name)
}

func (c *credentials) containsSecret(data []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var patterns []string
	for _, secret := range c.values {
		patterns = append(patterns, secret, base64.StdEncoding.EncodeToString([]byte(secret)), base64.RawStdEncoding.EncodeToString([]byte(secret)), base64.URLEncoding.EncodeToString([]byte(secret)), base64.RawURLEncoding.EncodeToString([]byte(secret)), hex.EncodeToString([]byte(secret)), strings.ToUpper(hex.EncodeToString([]byte(secret))))
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if value, ok := token.(string); ok {
			for _, pattern := range patterns {
				if strings.Contains(value, pattern) {
					return true
				}
			}
		}
	}
	return false
}

func (c *credentials) output(value any, requested map[string]string) (map[string]any, map[string]string, *Error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, nil, failure("driver", "driver_failed")
	}
	var output map[string]any
	if json.Unmarshal(data, &output) != nil || output == nil {
		return nil, nil, failure("driver", "driver_failed")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Validate the complete registration before changing the reference table.
	pending := map[string]string{}
	for field, ref := range requested {
		secret, ok := output[field].(string)
		if !ok || secret == "" || !validReference(ref) {
			return nil, nil, failure("driver", "invalid_args")
		}
		if _, exists := c.values[ref]; exists {
			return nil, nil, failure("driver", "invalid_reference")
		}
		if _, exists := pending[ref]; exists {
			return nil, nil, failure("driver", "invalid_reference")
		}
		pending[ref] = secret
	}
	for ref, secret := range pending {
		c.values[ref] = secret
	}
	refs := map[string]string{}
	for field, ref := range requested {
		refs[field] = ref
		delete(output, field)
	}
	for _, field := range []string{"access_token", "refresh_token"} {
		secret, ok := output[field].(string)
		if !ok {
			continue
		}
		if ref := c.referenceLocked(secret); ref != nil {
			refs[field] = *ref
		}
		delete(output, field)
	}
	var scrub func(any) any
	scrub = func(v any) any {
		switch v := v.(type) {
		case map[string]any:
			for key, child := range v {
				if key == "access_token" || key == "refresh_token" || key == "password" || key == "credential" {
					delete(v, key)
				} else {
					v[key] = scrub(child)
				}
			}
		case []any:
			for i := range v {
				v[i] = scrub(v[i])
			}
		case string:
			for _, secret := range c.values {
				if strings.Contains(v, secret) {
					return "[redacted]"
				}
			}
		}
		return v
	}
	scrub(output)
	return output, refs, nil
}
