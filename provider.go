// Package keychain provides pluggable key resolution for Cyphera SDKs.
package keychain

import (
	"errors"
	"time"
)

// Status represents the lifecycle state of a key version.
type Status string

const (
	StatusActive     Status = "active"
	StatusDeprecated Status = "deprecated"
	StatusDisabled   Status = "disabled"
)

// KeyRecord holds resolved key material and metadata.
type KeyRecord struct {
	Ref       string
	Version   int
	Status    Status
	Algorithm string
	Material  []byte
	Tweak     []byte
	Metadata  map[string]string
	CreatedAt time.Time
}

// KeyProvider resolves key references to key material.
type KeyProvider interface {
	Resolve(ref string) (KeyRecord, error)
	ResolveVersion(ref string, version int) (KeyRecord, error)
}

var (
	ErrKeyNotFound  = errors.New("key not found")
	ErrKeyDisabled  = errors.New("key is disabled")
	ErrNoActiveKey  = errors.New("no active key version")
)
