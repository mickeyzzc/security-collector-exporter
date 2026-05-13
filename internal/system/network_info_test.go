package system

import "testing"

func TestParseHexIP(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"zero_address", "00000000", "*"},
		{"localhost", "0100007F", "127.0.0.1"},
		{"192_168_1_1", "0101A8C0", "192.168.1.1"},
		{"10_10_10_5", "050A0A0A", "10.10.10.5"},
		{"short_input", "01", "1.0.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHexIP(tt.input)
			if got != tt.expect {
				t.Errorf("parseHexIP(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestParseHexIP_IPv6(t *testing.T) {
	got := parseHexIP("00000000000000000000000000000000")
	if got != "::" {
		t.Errorf("全零 IPv6 应返回 '::'，得到 '%s'", got)
	}

	got = parseHexIP("00112233445566778899AABBCCDDEEFF")
	if got != "IPv6:00112233" {
		t.Errorf("IPv6 简化格式不正确，得到 '%s'", got)
	}
}

func TestParseHexPort(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"port_22", "0016", "22"},
		{"port_80", "0050", "80"},
		{"port_8080", "1F90", "8080"},
		{"port_53", "0035", "53"},
		{"port_0", "0000", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHexPort(tt.input)
			if got != tt.expect {
				t.Errorf("parseHexPort(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestParseHexPort_Invalid(t *testing.T) {
	got := parseHexPort("ZZZZ")
	if got != "" {
		t.Errorf("无效输入应返回空字符串，得到 '%s'", got)
	}
}

func TestParseTCPState(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"ESTABLISHED", "01", "ESTABLISHED"},
		{"SYN_SENT", "02", "SYN_SENT"},
		{"SYN_RECV", "03", "SYN_RECV"},
		{"FIN_WAIT1", "04", "FIN_WAIT1"},
		{"FIN_WAIT2", "05", "FIN_WAIT2"},
		{"TIME_WAIT", "06", "TIME_WAIT"},
		{"CLOSE", "07", "CLOSE"},
		{"CLOSE_WAIT", "08", "CLOSE_WAIT"},
		{"LAST_ACK", "09", "LAST_ACK"},
		{"LISTEN", "0A", "LISTEN"},
		{"CLOSING", "0B", "CLOSING"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTCPState(tt.input)
			if got != tt.expect {
				t.Errorf("parseTCPState(%q) = %q, want %q", tt.input, got, tt.expect)
			}
		})
	}
}

func TestParseTCPState_Unknown(t *testing.T) {
	got := parseTCPState("FF")
	if got != "UNKNOWN_255" {
		t.Errorf("未知状态应返回 'UNKNOWN_255'，得到 '%s'", got)
	}

	got = parseTCPState("ZZ")
	if got != "unknown" {
		t.Errorf("无效输入应返回 'unknown'，得到 '%s'", got)
	}
}

func TestContainsState(t *testing.T) {
	states := []string{"LISTEN", "ESTABLISHED"}

	if !containsState(states, "LISTEN") {
		t.Error("应包含 LISTEN")
	}
	if !containsState(states, "ESTABLISHED") {
		t.Error("应包含 ESTABLISHED")
	}
	if containsState(states, "CLOSED") {
		t.Error("不应包含 CLOSED")
	}
	if containsState(states, "TIME_WAIT") {
		t.Error("不应包含 TIME_WAIT")
	}
}

func TestContainsState_Empty(t *testing.T) {
	if containsState([]string{}, "LISTEN") {
		t.Error("空切片不应包含任何状态")
	}
}

func TestParseHexByte(t *testing.T) {
	tests := []struct {
		input  string
		expect int
	}{
		{"00", 0},
		{"7F", 127},
		{"FF", 255},
		{"C0", 192},
		{"A8", 168},
	}

	for _, tt := range tests {
		got := parseHexByte(tt.input)
		if got != tt.expect {
			t.Errorf("parseHexByte(%q) = %d, want %d", tt.input, got, tt.expect)
		}
	}
}

func TestParseHexByte_Invalid(t *testing.T) {
	got := parseHexByte("ZZ")
	if got != 0 {
		t.Errorf("无效输入应返回 0，得到 %d", got)
	}
}
