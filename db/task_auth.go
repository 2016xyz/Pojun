package db

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// TaskAuthConfig 是任务的「目标登录凭据」配置（v0.4.8，借鉴 Shannon 的
// authentication 模型）：worker 拿到它先登录、再在会话内测试；创建后可
// 触发一次登录自检，凭据不可用时在开扫前就知道，而不是让 worker 盲探。
//
// 安全边界：Password / TOTPSecret 标记 json:"-"——任何 API 响应都不会回传
// 秘密；DB 存取走 DBValue（显式带秘密）。HasPassword/HasTOTP 是只读派生标记，
// 让前端知道"配过密码"而不暴露内容。
type TaskAuthConfig struct {
	Enabled         bool              `json:"enabled"`
	LoginURL        string            `json:"login_url"`
	Method          string            `json:"method"`       // POST|GET
	ContentType     string            `json:"content_type"` // json|form
	UsernameField   string            `json:"username_field,omitempty"`
	PasswordField   string            `json:"password_field,omitempty"`
	TOTPField       string            `json:"totp_field,omitempty"` // 动态码表单字段名（默认 totp）
	Username        string            `json:"username,omitempty"`
	Password        string            `json:"-"`
	HasPassword     bool              `json:"has_password,omitempty"`
	TOTPSecret      string            `json:"-"`
	HasTOTP         bool              `json:"has_totp,omitempty"`
	ExtraFields     map[string]string `json:"extra_fields,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	SuccessStatus   int               `json:"success_status,omitempty"`   // 0=不校验状态码
	SuccessContains string            `json:"success_contains,omitempty"` // 响应体包含即视为成功
}

// TOTPCodeNow 按当前时间生成 6 位动态码（RFC 6238，30 秒步长，HMAC-SHA1）。
//
// v0.4.68：TOTP 密钥不再以明文写进 system prompt。session_login(use_task_auth=true)
// 在**发请求的那一刻**现算动态码，密钥始终留在服务端内存里。
func (a *TaskAuthConfig) TOTPCodeNow() (string, error) {
	secret := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(a.TOTPSecret), " ", ""))
	if secret == "" {
		return "", fmt.Errorf("未配置 TOTP 密钥")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		// 兼容带 "=" 填充的写法
		key, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return "", fmt.Errorf("TOTP 密钥不是合法 Base32: %w", err)
		}
	}
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(ctr[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%06d", code%1000000), nil
}

// authWire 是 DB 存储形态：TaskAuthConfig 的 json:"-" 面向 API，DB 必须显式
// 带上 password / totp_secret 两个秘密字段。
type authWire struct {
	TaskAuthConfig
	Password   string `json:"password,omitempty"`
	TOTPSecret string `json:"totp_secret,omitempty"`
}

// DBValue 序列化含秘密字段的 JSON（写 tasks.auth_config）。
func (a *TaskAuthConfig) DBValue() ([]byte, error) {
	if a == nil {
		return nil, nil
	}
	return json.Marshal(authWire{TaskAuthConfig: *a, Password: a.Password, TOTPSecret: a.TOTPSecret})
}

// ParseTaskAuth 解析 DB 里的 auth_config；空/nil 返回 nil。解析成功时派生
// HasPassword/HasTOTP 供前端展示。
func ParseTaskAuth(raw []byte) *TaskAuthConfig {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" {
		return nil
	}
	var w authWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil
	}
	a := w.TaskAuthConfig
	a.Password = w.Password
	a.TOTPSecret = w.TOTPSecret
	a.HasPassword = a.Password != ""
	a.HasTOTP = a.TOTPSecret != ""
	return &a
}

// Normalize 校验并补默认值。只校验启用中的配置：关闭的配置保留原样（便于
// 用户先存草稿再启用）。
func (a *TaskAuthConfig) Normalize() error {
	if a == nil || !a.Enabled {
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(a.LoginURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("登录地址必须是完整的 http/https URL")
	}
	a.LoginURL = strings.TrimSpace(a.LoginURL)
	a.Method = strings.ToUpper(strings.TrimSpace(a.Method))
	if a.Method == "" {
		a.Method = "POST"
	}
	if a.Method != "POST" && a.Method != "GET" {
		return fmt.Errorf("登录方法只支持 POST / GET")
	}
	a.ContentType = strings.ToLower(strings.TrimSpace(a.ContentType))
	if a.ContentType == "" {
		a.ContentType = "json"
	}
	if a.ContentType != "json" && a.ContentType != "form" {
		return fmt.Errorf("登录请求体只支持 json / form")
	}
	if strings.TrimSpace(a.UsernameField) == "" {
		a.UsernameField = "username"
	}
	if strings.TrimSpace(a.PasswordField) == "" {
		a.PasswordField = "password"
	}
	if strings.TrimSpace(a.Username) == "" || a.Password == "" {
		return fmt.Errorf("启用登录配置时用户名与密码都必须填写")
	}
	if a.SuccessStatus != 0 && (a.SuccessStatus < 100 || a.SuccessStatus > 599) {
		return fmt.Errorf("成功状态码需在 100–599 之间（0 表示不校验）")
	}
	a.HasPassword = a.Password != ""
	a.HasTOTP = strings.TrimSpace(a.TOTPSecret) != ""
	return nil
}

// PromptBlock 渲染成注入 worker system prompt 的文本块。
//
// v0.4.68 安全修复：**不再输出密码与 TOTP 密钥的明文**。
//
// 旧实现一边在注释里写「不打印密码明文」，一边把 a.Password 与 a.TOTPSecret
// 原样拼进 system prompt。而 system prompt 会随 worker 的每一次 LLM 调用发给
// 第三方模型厂商（OpenAI/Anthropic/自建中转），并落进 llm_records 与
// transcripts/*.jsonl——凭据因此在三个地方各留一份明文。
//
// 现在只描述「登录接口长什么样」与「凭据已配置」，真实值由
// session_login(use_task_auth=true) 在发请求时从内存取（含 TOTP 现算）。
func (a *TaskAuthConfig) PromptBlock() string {
	if a == nil || !a.Enabled {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n━━ 目标登录凭据（任务级配置）━━\n")
	b.WriteString("目标站点已配置登录凭据。**凭据值不在此处给出**——登录时调用：\n")
	b.WriteString("  session_login(session=\"<会话名>\", url=\"" + a.LoginURL + "\", use_task_auth=true)\n")
	b.WriteString("工具会从服务端配置里直接取用户名/密码，并按当前时间现算 TOTP 动态码；\n")
	b.WriteString("登录成功后用同一 session 名调 http_request 复用登录态。\n")
	b.WriteString("不要用 Bash/curl 手工拼登录请求（那样需要明文密码，平台不会提供）。\n")
	b.WriteString("登录地址：" + a.LoginURL + "\n")
	b.WriteString("请求方法：" + a.Method + "，请求体格式：" + a.ContentType + "\n")
	b.WriteString("用户名字段：" + a.UsernameField + "（值已配置）\n")
	b.WriteString("密码字段：" + a.PasswordField + "（值已配置）\n")
	if a.HasTOTP {
		field := a.TOTPField
		if field == "" {
			field = "totp"
		}
		b.WriteString("动态码字段：" + field + "（TOTP 密钥已配置，工具自动现算）\n")
	}
	if len(a.ExtraFields) > 0 {
		keys := make([]string, 0, len(a.ExtraFields))
		for k := range a.ExtraFields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("附加表单字段：" + strings.Join(keys, "，") + "（值已配置，工具自动填入）\n")
	}
	if len(a.Headers) > 0 {
		b.WriteString("附加请求头已配置（工具自动带上）\n")
	}
	if a.SuccessStatus > 0 {
		b.WriteString(fmt.Sprintf("成功判定：响应状态码 %d", a.SuccessStatus))
		if a.SuccessContains != "" {
			b.WriteString(fmt.Sprintf("，且响应体包含 %q", a.SuccessContains))
		}
		b.WriteString("\n")
	} else if a.SuccessContains != "" {
		b.WriteString(fmt.Sprintf("成功判定：响应体包含 %q\n", a.SuccessContains))
	}
	b.WriteString("登录成功后从响应头/响应体提取会话凭证（Set-Cookie/token），后续请求携带它。登录失败时如实记录失败原因，不要猜测其他凭据。")
	return b.String()
}
