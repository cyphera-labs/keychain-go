package keychain

import (
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

// --- MemoryProvider tests ---

func TestMemoryProvider_Resolve(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")
	p := NewMemoryProvider([]KeyRecord{
		{Ref: "test-key", Version: 1, Status: StatusActive, Algorithm: "aes256", Material: material, CreatedAt: time.Now()},
	})

	rec, err := p.Resolve("test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Ref != "test-key" {
		t.Errorf("expected ref 'test-key', got '%s'", rec.Ref)
	}
	if rec.Version != 1 {
		t.Errorf("expected version 1, got %d", rec.Version)
	}
	if rec.Status != StatusActive {
		t.Errorf("expected status active, got '%s'", rec.Status)
	}
	if string(rec.Material) != string(material) {
		t.Errorf("material mismatch")
	}
}

func TestMemoryProvider_Resolve_NotFound(t *testing.T) {
	p := NewMemoryProvider(nil)
	_, err := p.Resolve("missing")
	if err == nil {
		t.Fatal("expected error for missing key")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestMemoryProvider_Resolve_NoActive(t *testing.T) {
	p := NewMemoryProvider([]KeyRecord{
		{Ref: "dep-key", Version: 1, Status: StatusDeprecated, Material: []byte("x"), CreatedAt: time.Now()},
	})
	_, err := p.Resolve("dep-key")
	if err == nil {
		t.Fatal("expected error for no active key")
	}
	if !errors.Is(err, ErrNoActiveKey) {
		t.Errorf("expected ErrNoActiveKey, got: %v", err)
	}
}

func TestMemoryProvider_ResolveVersion(t *testing.T) {
	p := NewMemoryProvider([]KeyRecord{
		{Ref: "ver-key", Version: 1, Status: StatusDeprecated, Material: []byte("old"), CreatedAt: time.Now()},
		{Ref: "ver-key", Version: 2, Status: StatusActive, Material: []byte("new"), CreatedAt: time.Now()},
	})

	// Resolve should return latest active (v2)
	rec, err := p.Resolve("ver-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Version != 2 {
		t.Errorf("expected version 2, got %d", rec.Version)
	}

	// ResolveVersion should return v1 (deprecated but not disabled)
	rec, err = p.ResolveVersion("ver-key", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Version != 1 {
		t.Errorf("expected version 1, got %d", rec.Version)
	}
}

func TestMemoryProvider_ResolveVersion_Disabled(t *testing.T) {
	p := NewMemoryProvider([]KeyRecord{
		{Ref: "dis-key", Version: 1, Status: StatusDisabled, Material: []byte("x"), CreatedAt: time.Now()},
	})
	_, err := p.ResolveVersion("dis-key", 1)
	if err == nil {
		t.Fatal("expected error for disabled key")
	}
	if !errors.Is(err, ErrKeyDisabled) {
		t.Errorf("expected ErrKeyDisabled, got: %v", err)
	}
}

func TestMemoryProvider_ResolveVersion_NotFound(t *testing.T) {
	p := NewMemoryProvider([]KeyRecord{
		{Ref: "ver-key", Version: 1, Status: StatusActive, Material: []byte("x"), CreatedAt: time.Now()},
	})
	_, err := p.ResolveVersion("ver-key", 99)
	if err == nil {
		t.Fatal("expected error for missing version")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got: %v", err)
	}
}

// --- EnvProvider tests ---

func TestEnvProvider_Resolve(t *testing.T) {
	material := []byte("abcdef0123456789abcdef0123456789")
	hexVal := hex.EncodeToString(material)

	os.Setenv("CYPHERA_TEST_KEY", hexVal)
	defer os.Unsetenv("CYPHERA_TEST_KEY")

	p := NewEnvProvider("CYPHERA")
	rec, err := p.Resolve("test-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.Ref != "test-key" {
		t.Errorf("expected ref 'test-key', got '%s'", rec.Ref)
	}
	if rec.Version != 1 {
		t.Errorf("expected version 1, got %d", rec.Version)
	}
	if rec.Status != StatusActive {
		t.Errorf("expected status active, got '%s'", rec.Status)
	}
	if string(rec.Material) != string(material) {
		t.Errorf("material mismatch: got %x, want %x", rec.Material, material)
	}
}

func TestEnvProvider_Resolve_NotSet(t *testing.T) {
	os.Unsetenv("CYPHERA_NOEXIST")
	p := NewEnvProvider("CYPHERA")
	_, err := p.Resolve("noexist")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got: %v", err)
	}
}

func TestEnvProvider_Resolve_NoPrefix(t *testing.T) {
	material := []byte("00112233445566778899aabbccddeeff")
	hexVal := hex.EncodeToString(material)

	os.Setenv("MY_KEY", hexVal)
	defer os.Unsetenv("MY_KEY")

	p := NewEnvProvider("")
	rec, err := p.Resolve("my-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(rec.Material) != string(material) {
		t.Errorf("material mismatch")
	}
}
