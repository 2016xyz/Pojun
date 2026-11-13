package listener

import (
	"strings"
	"testing"
)

// 回连接收器默认只绑本机，不对外网开放。
//
// 回归背景（v0.4.68）：原实现 net.Listen("tcp", ":port") 绑的是 0.0.0.0——
// 宿主机只要有公网网卡，一个 reverse shell 接收器就在无提示的情况下对全网
// 开放了，而它接收任意来源的连接。
func TestBindAddrDefaultsToLoopback(t *testing.T) {
	t.Setenv(BindAddrEnv, "")
	if got := bindAddr(); got != "127.0.0.1" {
		t.Fatalf("默认绑定地址 = %q，应为 127.0.0.1（对外回连需显式 %s=0.0.0.0）", got, BindAddrEnv)
	}
}

func TestBindAddrEnvOverride(t *testing.T) {
	for _, want := range []string{"0.0.0.0", "10.1.2.3", "::"} {
		t.Setenv(BindAddrEnv, want)
		if got := bindAddr(); got != want {
			t.Errorf("bindAddr() = %q，应为覆盖值 %q", got, want)
		}
	}
	// 空白值视作未设置，回落到安全默认。
	t.Setenv(BindAddrEnv, "   ")
	if got := bindAddr(); got != "127.0.0.1" {
		t.Errorf("空白覆盖值应回落到 127.0.0.1，实际 %q", got)
	}
}

// Start 实际使用的绑定地址必须跟随 bindAddr()。
func TestStartBindsLoopbackByDefault(t *testing.T) {
	t.Setenv(BindAddrEnv, "")
	m := NewManager()
	l, err := m.Start("bindtest", 18445)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop("bindtest")
	addr := l.ln.Addr().String()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("默认绑定了 %q，应为 127.0.0.1:<port>", addr)
	}
}
