package agent

import (
	"strings"
	"testing"
)

func TestProxyEnvEmptyIsNil(t *testing.T) {
	// v0.4.68 安全修复：空代理时不再返回 nil。
	// 必须返回「敏感变量清空项」，否则子进程通过 os.Environ() 继承
	// POJUN_PG_DSN / API key —— agent 一条 `env` 就拿到数据库口令。
	env := proxyEnv("", "")
	if env == nil {
		t.Fatal("proxyEnv(\"\", \"\") = nil；空代理时也必须返回敏感变量清空项")
	}
	got := map[string]bool{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && v == "" {
			got[k] = true
		}
	}
	for _, key := range sensitiveEnvKeys {
		if !got[key] {
			t.Errorf("敏感变量 %q 未被清空；env=%v", key, env)
		}
	}
	for _, kv := range env {
		if strings.HasPrefix(kv, "HTTP_PROXY=") && !strings.HasSuffix(kv, "=") {
			t.Errorf("空代理时不应注入 HTTP_PROXY：%q", kv)
		}
	}
}

func TestProxyEnvSetsAllProxyForSocks5(t *testing.T) {
	// Capture-off egress path: a socks5 proxy, no MITM CA. ALL_PROXY must be set
	// (curl reads socks5 only from there), and no CA vars should appear.
	env := proxyEnv("socks5://10.0.0.1:1080", "")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"HTTP_PROXY=", "HTTPS_PROXY=", "ALL_PROXY=", "all_proxy="} {
		if !has(want) {
			t.Errorf("proxyEnv missing %s: %v", want, env)
		}
	}
	if has("SSL_CERT_FILE=") || has("CURL_CA_BUNDLE=") {
		t.Errorf("proxyEnv without CA must not inject CA vars: %v", env)
	}
}

func TestProxyEnvInjectsCAWhenRecording(t *testing.T) {
	env := proxyEnv("http://127.0.0.1:8788", "/data/ca.pem")
	has := func(prefix string) bool {
		for _, e := range env {
			if strings.HasPrefix(e, prefix) {
				return true
			}
		}
		return false
	}
	for _, want := range []string{"SSL_CERT_FILE=", "CURL_CA_BUNDLE=", "REQUESTS_CA_BUNDLE=", "NODE_EXTRA_CA_CERTS="} {
		if !has(want) {
			t.Errorf("proxyEnv with CA missing %s: %v", want, env)
		}
	}
}
