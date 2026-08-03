package e2e

import (
	"encoding/json"
	"errors"
)

func jsonMarshal(v any) ([]byte, error)   { return json.Marshal(v) }
func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func errorsAs(err error, target any) bool { return errors.As(err, target) }
