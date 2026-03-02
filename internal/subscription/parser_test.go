package subscription

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestParseGeneralSubscription_SingboxJSON_Basic(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "shadowsocks", "tag": "ss-us", "server": "1.2.3.4", "server_port": 443},
			{"type": "vmess", "tag": "vmess-jp", "server": "5.6.7.8", "server_port": 443},
			{"type": "direct", "tag": "direct"},
			{"type": "block", "tag": "block"},
			{"type": "selector", "tag": "proxy", "outbounds": ["ss-us", "vmess-jp"]}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}

	// Only shadowsocks and vmess are supported; direct/block/selector are not.
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}

	if nodes[0].Tag != "ss-us" {
		t.Fatalf("expected tag ss-us, got %s", nodes[0].Tag)
	}
	if nodes[1].Tag != "vmess-jp" {
		t.Fatalf("expected tag vmess-jp, got %s", nodes[1].Tag)
	}
}

func TestParseGeneralSubscription_SingboxJSON_AllSupportedTypes(t *testing.T) {
	types := []string{
		"socks", "http", "shadowsocks", "vmess", "trojan", "wireguard",
		"hysteria", "vless", "shadowtls", "tuic", "hysteria2", "anytls",
		"tor", "ssh", "naive",
	}

	// Build JSON with all supported types.
	outbounds := "["
	for i, tp := range types {
		if i > 0 {
			outbounds += ","
		}
		outbounds += `{"type":"` + tp + `","tag":"node-` + tp + `"}`
	}
	outbounds += "]"

	data := []byte(`{"outbounds":` + outbounds + `}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != len(types) {
		t.Fatalf("expected %d nodes, got %d", len(types), len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_UnsupportedTypesFiltered(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "direct", "tag": "direct"},
			{"type": "block", "tag": "block"},
			{"type": "selector", "tag": "sel"},
			{"type": "urltest", "tag": "urltest"},
			{"type": "dns", "tag": "dns"}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_EmptyOutbounds(t *testing.T) {
	data := []byte(`{"outbounds": []}`)
	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_MalformedJSON(t *testing.T) {
	_, err := ParseGeneralSubscription([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestParseGeneralSubscription_SingboxJSON_MalformedOutboundSkipped(t *testing.T) {
	// A bare number is not a valid JSON object for an outbound — should be skipped.
	data := []byte(`{"outbounds": [123]}`)
	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatalf("malformed individual outbound should be skipped, not fatal: %v", err)
	}
	if len(nodes) != 0 {
		t.Fatalf("expected 0 nodes after skipping bad entry, got %d", len(nodes))
	}
}

func TestParseGeneralSubscription_SingboxJSON_MixedGoodAndBadOutbounds(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "shadowsocks", "tag": "good-node", "server": "1.2.3.4", "server_port": 443},
			123,
			"bad-string",
			{"type": "vmess", "tag": "also-good", "server": "5.6.7.8", "server_port": 443}
		]
	}`)
	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatalf("should skip bad entries, not fail: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 valid nodes, got %d", len(nodes))
	}
	if nodes[0].Tag != "good-node" || nodes[1].Tag != "also-good" {
		t.Fatalf("unexpected tags: %s, %s", nodes[0].Tag, nodes[1].Tag)
	}
}

func TestParseGeneralSubscription_SingboxJSON_RawOptionsPreservesFullJSON(t *testing.T) {
	data := []byte(`{
		"outbounds": [
			{"type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "server_port": 443, "method": "aes-256-gcm"}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}

	// RawOptions should contain the full original JSON.
	raw := string(nodes[0].RawOptions)
	if len(raw) == 0 {
		t.Fatal("RawOptions should not be empty")
	}
	// Should contain method field.
	if !strings.Contains(raw, "aes-256-gcm") {
		t.Fatalf("RawOptions missing method: %s", raw)
	}
}

func TestParseGeneralSubscription_ClashJSON(t *testing.T) {
	data := []byte(`{
		"proxies": [
			{
				"name": "ss-test",
				"type": "ss",
				"server": "1.1.1.1",
				"port": 8388,
				"cipher": "aes-128-gcm",
				"password": "pass"
			},
			{
				"name": "ignored-http",
				"type": "http",
				"server": "2.2.2.2",
				"port": 8080
			}
		]
	}`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}

	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "shadowsocks" {
		t.Fatalf("expected type shadowsocks, got %v", got)
	}
	if got := obj["tag"]; got != "ss-test" {
		t.Fatalf("expected tag ss-test, got %v", got)
	}
}

func TestParseGeneralSubscription_ClashYAML(t *testing.T) {
	data := []byte(`
proxies:
  - name: vmess-yaml
    type: vmess
    server: 3.3.3.3
    port: 443
    uuid: 26a1d547-b031-4139-9fc5-6671e1d0408a
    cipher: auto
    tls: true
    servername: example.com
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}

	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "vmess" {
		t.Fatalf("expected type vmess, got %v", got)
	}
	if got := obj["tag"]; got != "vmess-yaml" {
		t.Fatalf("expected tag vmess-yaml, got %v", got)
	}
}

func TestParseGeneralSubscription_URILines(t *testing.T) {
	data := []byte(`
trojan://password@example.com:443?allowInsecure=1&type=ws&sni=example.com#Trojan%20Node
vless://26a1d547-b031-4139-9fc5-6671e1d0408a@example.com:443?type=tcp&security=tls&sni=example.com#VLESS%20Node
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)
	if first["type"] != "trojan" || second["type"] != "vless" {
		t.Fatalf("unexpected node types: %v, %v", first["type"], second["type"])
	}
}

func TestParseGeneralSubscription_ProxyURILines(t *testing.T) {
	data := []byte(`
http://user-http:pass-http@1.2.3.4:8080#HTTP%20Node
https://user-https:pass-https@example.com:8443?sni=tls.example.com&allowInsecure=1#HTTPS%20Node
socks5://user-s5:pass-s5@5.6.7.8:1081#SOCKS5%20Node
socks5h://user-s5h:pass-s5h@proxy.example.net:1082#SOCKS5H%20Node
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 4 {
		t.Fatalf("expected 4 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)
	third := parseNodeRaw(t, nodes[2].RawOptions)
	fourth := parseNodeRaw(t, nodes[3].RawOptions)

	if got := first["type"]; got != "http" {
		t.Fatalf("expected first type http, got %v", got)
	}
	if got := first["username"]; got != "user-http" {
		t.Fatalf("expected first username user-http, got %v", got)
	}
	if got := first["password"]; got != "pass-http" {
		t.Fatalf("expected first password pass-http, got %v", got)
	}
	if got := first["tag"]; got != "HTTP Node" {
		t.Fatalf("expected first tag HTTP Node, got %v", got)
	}

	if got := second["type"]; got != "http" {
		t.Fatalf("expected second type http, got %v", got)
	}
	tls, ok := second["tls"].(map[string]any)
	if !ok {
		t.Fatalf("expected second tls object, got %T", second["tls"])
	}
	if got := tls["enabled"]; got != true {
		t.Fatalf("expected second tls.enabled true, got %v", got)
	}
	if got := tls["server_name"]; got != "tls.example.com" {
		t.Fatalf("expected second tls.server_name tls.example.com, got %v", got)
	}
	if got := tls["insecure"]; got != true {
		t.Fatalf("expected second tls.insecure true, got %v", got)
	}
	if got := second["tag"]; got != "HTTPS Node" {
		t.Fatalf("expected second tag HTTPS Node, got %v", got)
	}

	if got := third["type"]; got != "socks" {
		t.Fatalf("expected third type socks, got %v", got)
	}
	if got := third["server"]; got != "5.6.7.8" {
		t.Fatalf("expected third server 5.6.7.8, got %v", got)
	}
	if got := third["server_port"]; got != float64(1081) {
		t.Fatalf("expected third server_port 1081, got %v", got)
	}
	if got := third["username"]; got != "user-s5" {
		t.Fatalf("expected third username user-s5, got %v", got)
	}
	if got := third["password"]; got != "pass-s5" {
		t.Fatalf("expected third password pass-s5, got %v", got)
	}

	if got := fourth["type"]; got != "socks" {
		t.Fatalf("expected fourth type socks, got %v", got)
	}
	if got := fourth["server"]; got != "proxy.example.net" {
		t.Fatalf("expected fourth server proxy.example.net, got %v", got)
	}
	if got := fourth["server_port"]; got != float64(1082) {
		t.Fatalf("expected fourth server_port 1082, got %v", got)
	}
	if got := fourth["username"]; got != "user-s5h" {
		t.Fatalf("expected fourth username user-s5h, got %v", got)
	}
	if got := fourth["password"]; got != "pass-s5h" {
		t.Fatalf("expected fourth password pass-s5h, got %v", got)
	}
}

func TestParseGeneralSubscription_ProxyURILinesRejectNonProxyURLs(t *testing.T) {
	tests := []string{
		"https://api.example.com",
		"https://api.example.com/subscription/token",
		"http://api.example.com:8080/path/to/resource",
		"socks5://proxy.example.com:1080/path",
		"socks5://proxy.example.com:1080?token=abc",
		"https://proxy.example.com:8443?token=abc",
	}

	for _, input := range tests {
		nodes, err := ParseGeneralSubscription([]byte(input))
		if err != nil {
			t.Fatalf("input %q should not return error, got %v", input, err)
		}
		if len(nodes) != 0 {
			t.Fatalf("input %q should not be parsed as proxy node, got %d", input, len(nodes))
		}
	}
}

func TestParseGeneralSubscription_PlainHTTPProxyLines(t *testing.T) {
	data := []byte(`
1.2.3.4:8080
5.6.7.8:3128:user-a:pass-a
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)

	if first["type"] != "http" {
		t.Fatalf("expected first type http, got %v", first["type"])
	}
	if first["server"] != "1.2.3.4" {
		t.Fatalf("expected first server 1.2.3.4, got %v", first["server"])
	}
	if first["server_port"] != float64(8080) {
		t.Fatalf("expected first server_port 8080, got %v", first["server_port"])
	}
	if _, ok := first["username"]; ok {
		t.Fatalf("expected first proxy without username, got %v", first["username"])
	}
	if _, ok := first["password"]; ok {
		t.Fatalf("expected first proxy without password, got %v", first["password"])
	}

	if second["type"] != "http" {
		t.Fatalf("expected second type http, got %v", second["type"])
	}
	if second["server"] != "5.6.7.8" {
		t.Fatalf("expected second server 5.6.7.8, got %v", second["server"])
	}
	if second["server_port"] != float64(3128) {
		t.Fatalf("expected second server_port 3128, got %v", second["server_port"])
	}
	if second["username"] != "user-a" {
		t.Fatalf("expected second username user-a, got %v", second["username"])
	}
	if second["password"] != "pass-a" {
		t.Fatalf("expected second password pass-a, got %v", second["password"])
	}
}

func TestParseGeneralSubscription_PlainHTTPProxyLinesIPv6(t *testing.T) {
	data := []byte(`
[2001:db8::1]:8080
2001:db8::2:3128:user-v6:pass-v6
`)

	nodes, err := ParseGeneralSubscription(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes, got %d", len(nodes))
	}

	first := parseNodeRaw(t, nodes[0].RawOptions)
	second := parseNodeRaw(t, nodes[1].RawOptions)

	if first["type"] != "http" {
		t.Fatalf("expected first type http, got %v", first["type"])
	}
	if first["server"] != "2001:db8::1" {
		t.Fatalf("expected first server 2001:db8::1, got %v", first["server"])
	}
	if first["server_port"] != float64(8080) {
		t.Fatalf("expected first server_port 8080, got %v", first["server_port"])
	}

	if second["type"] != "http" {
		t.Fatalf("expected second type http, got %v", second["type"])
	}
	if second["server"] != "2001:db8::2" {
		t.Fatalf("expected second server 2001:db8::2, got %v", second["server"])
	}
	if second["server_port"] != float64(3128) {
		t.Fatalf("expected second server_port 3128, got %v", second["server_port"])
	}
	if second["username"] != "user-v6" {
		t.Fatalf("expected second username user-v6, got %v", second["username"])
	}
	if second["password"] != "pass-v6" {
		t.Fatalf("expected second password pass-v6, got %v", second["password"])
	}
}

func TestParseGeneralSubscription_Base64WrappedURIs(t *testing.T) {
	plain := "ss://YWVzLTEyOC1nY206cGFzcw==@1.1.1.1:8388#SS-Node"
	encoded := base64.StdEncoding.EncodeToString([]byte(plain))

	nodes, err := ParseGeneralSubscription([]byte(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("expected 1 parsed node, got %d", len(nodes))
	}

	obj := parseNodeRaw(t, nodes[0].RawOptions)
	if got := obj["type"]; got != "shadowsocks" {
		t.Fatalf("expected type shadowsocks, got %v", got)
	}
	if got := obj["tag"]; got != "SS-Node" {
		t.Fatalf("expected tag SS-Node, got %v", got)
	}
}

func TestParseGeneralSubscription_UnknownFormatReturnsError(t *testing.T) {
	_, err := ParseGeneralSubscription([]byte("this is not a subscription format"))
	if err == nil {
		t.Fatal("expected error for unknown subscription format")
	}
}

func parseNodeRaw(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal node raw failed: %v", err)
	}
	return obj
}
