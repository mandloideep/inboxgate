package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

type envelopeClassification struct {
	Code    int
	Message string
	ID      any
	Method  string
	Name    string
}

type structuralError uint8

const (
	structuralOK structuralError = iota
	structuralParse
	structuralInvalid
)

type structuralState struct {
	nodes int
}

func classifyEnvelope(data []byte) envelopeClassification {
	if !utf8.Valid(data) {
		return classifiedError(-32700)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	state := structuralState{}
	value, kind := decodeJSONValue(decoder, &state, 1)
	if kind == structuralParse {
		return classifiedError(-32700)
	}
	if kind == structuralInvalid {
		return classifiedError(-32600)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return classifiedError(-32700)
	}
	root, ok := value.(map[string]any)
	if !ok {
		return classifiedError(-32600)
	}
	classification := envelopeClassification{}
	if id, found := root["id"]; found {
		classification.ID = id
	}
	method, _ := root["method"].(string)
	classification.Method = method
	if !exactKeys(root, "jsonrpc", "id", "method", "params") || root["jsonrpc"] != "2.0" || classification.ID == nil || method == "" {
		return classification.withError(-32600)
	}
	switch classification.ID.(type) {
	case string, json.Number:
	default:
		return classification.withError(-32600)
	}
	params, ok := root["params"].(map[string]any)
	if !ok {
		return classification.withError(-32602)
	}
	if method == "initialize" {
		return classification.withError(-32601)
	}
	if method == "notifications/initialized" {
		return classification.withError(-32600)
	}
	if method == "tools/call" {
		if !exactKeys(params, "name", "arguments", "_meta") {
			return classification.withError(-32602)
		}
		name, ok := params["name"].(string)
		if !ok || name == "" {
			return classification.withError(-32602)
		}
		classification.Name = name
		arguments, ok := params["arguments"].(map[string]any)
		if !ok || len(arguments) != 0 {
			return classification.withError(-32602)
		}
	} else if !exactKeys(params, "_meta") {
		return classification.withError(-32602)
	}
	if !validRequestMeta(params["_meta"]) {
		return classification.withError(-32602)
	}
	switch method {
	case "server/discover", "tools/list":
		return classification
	case "tools/call":
		if classification.Name != systemCapabilitiesTool {
			return classification.withError(-32601)
		}
		return classification
	default:
		return classification.withError(-32601)
	}
}

func (classification envelopeClassification) withError(code int) envelopeClassification {
	classification.Code = code
	classification.Message = jsonRPCMessage(code)
	return classification
}

func classifiedError(code int) envelopeClassification {
	return envelopeClassification{Code: code, Message: jsonRPCMessage(code)}
}

func validRequestMeta(value any) bool {
	meta, ok := value.(map[string]any)
	if !ok || !exactKeys(meta,
		"io.modelcontextprotocol/protocolVersion",
		"io.modelcontextprotocol/clientCapabilities",
		"io.modelcontextprotocol/clientInfo",
	) && !exactKeys(meta,
		"io.modelcontextprotocol/protocolVersion",
		"io.modelcontextprotocol/clientCapabilities",
	) {
		return false
	}
	if meta["io.modelcontextprotocol/protocolVersion"] != ProtocolVersion {
		return false
	}
	capabilities, ok := meta["io.modelcontextprotocol/clientCapabilities"].(map[string]any)
	if !ok || len(capabilities) != 0 {
		return false
	}
	if raw, found := meta["io.modelcontextprotocol/clientInfo"]; found {
		client, ok := raw.(map[string]any)
		if !ok || !exactKeys(client, "name", "version") {
			return false
		}
		name, nameOK := client["name"].(string)
		version, versionOK := client["version"].(string)
		if !nameOK || !versionOK || name == "" || version == "" || len(name) > 128 || len(version) > 128 {
			return false
		}
	}
	return true
}

func exactKeys(value map[string]any, required ...string) bool {
	if len(value) != len(required) {
		return false
	}
	for _, key := range required {
		if _, found := value[key]; !found {
			return false
		}
	}
	return true
}

func decodeJSONValue(decoder *json.Decoder, state *structuralState, depth int) (any, structuralError) {
	token, err := decoder.Token()
	if err != nil {
		return nil, structuralParse
	}
	state.nodes++
	if state.nodes > MaximumJSONNodes {
		return nil, structuralInvalid
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return token, structuralOK
	}
	if depth > MaximumJSONDepth {
		return nil, structuralInvalid
	}
	switch delimiter {
	case '{':
		result := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, structuralParse
			}
			key, ok := keyToken.(string)
			if !ok || !utf8.ValidString(key) || bytes.IndexByte([]byte(key), 0) >= 0 {
				return nil, structuralInvalid
			}
			state.nodes++
			if state.nodes > MaximumJSONNodes {
				return nil, structuralInvalid
			}
			if _, duplicate := result[key]; duplicate {
				return nil, structuralInvalid
			}
			value, kind := decodeJSONValue(decoder, state, depth+1)
			if kind != structuralOK {
				return nil, kind
			}
			result[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, structuralParse
		}
		return result, structuralOK
	case '[':
		result := []any{}
		for decoder.More() {
			value, kind := decodeJSONValue(decoder, state, depth+1)
			if kind != structuralOK {
				return nil, kind
			}
			result = append(result, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, structuralParse
		}
		return result, structuralOK
	default:
		return nil, structuralParse
	}
}

func jsonRPCMessage(code int) string {
	switch code {
	case -32700:
		return "parse error"
	case -32600:
		return "invalid request"
	case -32601:
		return "method not found"
	case -32602:
		return "invalid params"
	case -32603:
		return "internal error"
	case -32020:
		return "protocol or routing mismatch"
	default:
		return "internal error"
	}
}
