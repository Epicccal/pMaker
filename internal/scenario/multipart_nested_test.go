package scenario

import (
	"strings"
	"testing"
)

// TestValidateMultipartPart_NestedMutualExclusion 验证 body/body_hex/nested 三选一互斥。
func TestValidateMultipartPart_NestedMutualExclusion(t *testing.T) {
	tests := []struct {
		name    string
		part    MultipartPart
		wantErr bool
		errMsg  string
	}{
		{
			name:    "body only - valid",
			part:    MultipartPart{Body: "test"},
			wantErr: false,
		},
		{
			name:    "body_hex only - valid",
			part:    MultipartPart{BodyHex: "0x41"},
			wantErr: false,
		},
		{
			name: "nested only - valid",
			part: MultipartPart{
				Nested: &MultipartBody{
					Parts: []MultipartPart{{Body: "inner"}},
				},
			},
			wantErr: false,
		},
		{
			name: "body + nested - invalid",
			part: MultipartPart{
				Body: "test",
				Nested: &MultipartBody{
					Parts: []MultipartPart{{Body: "inner"}},
				},
			},
			wantErr: true,
			errMsg:  "body/body_hex 与 nested 不可同设",
		},
		{
			name: "body_hex + nested - invalid",
			part: MultipartPart{
				BodyHex: "0x41",
				Nested: &MultipartBody{
					Parts: []MultipartPart{{Body: "inner"}},
				},
			},
			wantErr: true,
			errMsg:  "body/body_hex 与 nested 不可同设",
		},
		{
			name:    "all empty - invalid",
			part:    MultipartPart{},
			wantErr: true,
			errMsg:  "至少一个",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMultipartPart(0, &tt.part)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateMultipart_NestedRecursion 验证递归校验 nested multipart。
func TestValidateMultipart_NestedRecursion(t *testing.T) {
	tests := []struct {
		name    string
		mp      *MultipartBody
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid nested - one level",
			mp: &MultipartBody{
				Boundary: "outer",
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "inner",
							Parts:    []MultipartPart{{Body: "test"}},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid nested - two levels",
			mp: &MultipartBody{
				Boundary: "outer",
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "middle",
							Parts: []MultipartPart{
								{
									Nested: &MultipartBody{
										Boundary: "inner",
										Parts:    []MultipartPart{{Body: "deep"}},
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid nested - empty parts",
			mp: &MultipartBody{
				Boundary: "outer",
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "inner",
							Parts:    []MultipartPart{}, // empty
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "至少需要 1 个 part",
		},
		{
			name: "invalid nested - bad body_hex",
			mp: &MultipartBody{
				Boundary: "outer",
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "inner",
							Parts: []MultipartPart{
								{BodyHex: "notHex"}, // invalid hex
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "0x 前缀",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMultipart(tt.mp)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestValidateBoundaryConflict 验证父子 boundary 冲突检测。
func TestValidateBoundaryConflict(t *testing.T) {
	tests := []struct {
		name    string
		mp      *MultipartBody
		wantErr bool
		errMsg  string
	}{
		{
			name: "no conflict - different boundaries",
			mp: &MultipartBody{
				Boundary: "outer",
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "inner",
							Parts:    []MultipartPart{{Body: "test"}},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "conflict - same boundary",
			mp: &MultipartBody{
				Boundary: "same",
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "same", // conflict!
							Parts:    []MultipartPart{{Body: "test"}},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "在多个层级重复使用",
		},
		{
			name: "conflict - three levels with repeat",
			mp: &MultipartBody{
				Boundary: "b1",
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "b2",
							Parts: []MultipartPart{
								{
									Nested: &MultipartBody{
										Boundary: "b1", // conflicts with root
										Parts:    []MultipartPart{{Body: "test"}},
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "在多个层级重复使用",
		},
		{
			name: "no conflict - default boundary differs from nested",
			mp: &MultipartBody{
				// Boundary empty -> uses default "----=_pMaker_0001"
				Parts: []MultipartPart{
					{
						Nested: &MultipartBody{
							Boundary: "custom",
							Parts:    []MultipartPart{{Body: "test"}},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBoundaryConflict(tt.mp)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestApplyTransferEncoding 验证独立编码函数。
func TestApplyTransferEncoding(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		encoding string
		wantLen  int // just check length change for base64
	}{
		{
			name:     "none - passthrough",
			data:     []byte("test"),
			encoding: "none",
			wantLen:  4,
		},
		{
			name:     "7bit - passthrough",
			data:     []byte("test"),
			encoding: "7bit",
			wantLen:  4,
		},
		{
			name:     "base64 - encodes",
			data:     []byte("test"),
			encoding: "base64",
			wantLen:  8, // base64("test") = "dGVzdA=="
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ApplyTransferEncoding(tt.data, tt.encoding)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if len(result) != tt.wantLen {
				t.Errorf("expected length %d, got %d", tt.wantLen, len(result))
			}
		})
	}
}
