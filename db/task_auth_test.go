package db

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestNormalizeTaskAuth 钉住校验与默认值：只校验启用中的配置；URL 必须
// http/https；方法/请求体格式/字段名有安全默认；用户密码必填。
func TestNormalizeTaskAuth(t *testing.T) {
	ok := &TaskAuthConfig{Enabled: true, LoginURL: "https://t.example.com/login", Username: "u", Password: "p"}
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
	if ok.Method != "POST" || ok.ContentType != "json" || ok.UsernameField != "username" || ok.PasswordField != "password" {
		t.Fatalf("defaults missing: %+v", ok)
	}
	if !ok.HasPassword {
		t.Fatal("HasPassword must be derived")
	}

	bad := []*TaskAuthConfig{
		{Enabled: true, LoginURL: "ftp://t/login", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", Method: "PUT", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", ContentType: "xml", Username: "u", Password: "p"},
		{Enabled: true, LoginURL: "https://t/login", Username: "u"},
		{Enabled: true, LoginURL: "https://t/login", Password: "p"},
	}
	for _, b := range bad {
		if err := b.Normalize(); err == nil {
			t.Fatalf("expected error for %+v", b)
		}
	}
	// 关闭的配置不校验（可存草稿）。
	if err := (&TaskAuthConfig{Enabled: false, LoginURL: "not-a-url"}).Normalize(); err != nil {
		t.Fatal("disabled config must not be validated")
	}
}

// TestTaskAuthSecretsNotSerialized 是安全边界：任何 JSON 序列化（API 响应）
// 都不能出现 password / totp_secret；DB 存取走 DBValue 才带秘密。
func TestTaskAuthSecretsNotSerialized(t *testing.T) {
	a := &TaskAuthConfig{
		Enabled: true, LoginURL: "https://t/login", Username: "alice", Password: "s3cret",
		TOTPSecret: "GEZDGNBV", HasPassword: true, HasTOTP: true,
	}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") || strings.Contains(string(raw), "GEZDGNBV") {
		t.Fatalf("API JSON leaked secrets: %s", raw)
	}

	dbRaw, err := a.DBValue()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dbRaw), "s3cret") || !strings.Contains(string(dbRaw), "GEZDGNBV") {
		t.Fatalf("DBValue must persist secrets: %s", dbRaw)
	}
	back := ParseTaskAuth(dbRaw)
	if back == nil || back.Password != "s3cret" || back.TOTPSecret != "GEZDGNBV" || !back.HasPassword || !back.HasTOTP {
		t.Fatalf("roundtrip failed: %+v", back)
	}
	if ParseTaskAuth([]byte("null")) != nil || ParseTaskAuth(nil) != nil {
		t.Fatal("empty config must parse to nil")
	}
}

// TestTaskAuthPromptBlock 断言 prompt 块**不含**凭据明文。
//
// v0.4.68：旧测试要求块里必须出现密码 "s3cret" —— 那正是把凭据发给第三方
// 模型厂商的通道。现在块只描述接口形态，真实值由
// session_login(use_task_auth=true) 在发请求时从内存取。
func TestTaskAuthPromptBlock(t *testing.T) {
	a := &TaskAuthConfig{Enabled: true, LoginURL: "https://t/login", Method: "POST", ContentType: "json",
		UsernameField: "user", PasswordField: "pass", Username: "alice", Password: "s3cret",
		TOTPSecret: "JBSWY3DPEHPK3PXP", TOTPField: "otp",
		SuccessStatus: 200, SuccessContains: "token"}
	a.HasPassword = true
	a.HasTOTP = true
	block := a.PromptBlock()

	// 结构性信息必须保留（worker 要知道怎么登录）。
	for _, want := range []string{"https://t/login", "user", "pass", "otp", "use_task_auth"} {
		if !strings.Contains(block, want) {
			t.Fatalf("prompt block missing %q:\n%s", want, block)
		}
	}
	// 凭据明文一律不得出现。
	for _, secret := range []string{"s3cret", "JBSWY3DPEHPK3PXP", "alice"} {
		if strings.Contains(block, secret) {
			t.Fatalf("prompt block 泄露了凭据 %q：\n%s", secret, block)
		}
	}
	if (&TaskAuthConfig{}).PromptBlock() != "" {
		t.Fatal("disabled config must render empty block")
	}
}
