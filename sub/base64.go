package sub

import (
	"encoding/base64"

	"github.com/qsilasu/xproxy/node"
)

func parseBase64(input []byte) (*node.Subscription, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(string(input))
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(string(input))
		if err != nil {
			return nil, err
		}
	}
	return parseRaw(decoded)
}

func generateBase64(sub *node.Subscription) ([]byte, error) {
	raw, err := generateRaw(sub)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	return []byte(encoded), nil
}
