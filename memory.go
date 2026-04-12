package keychain

import "fmt"

// MemoryProvider stores keys in memory. For dev/test only.
type MemoryProvider struct {
	records map[string][]KeyRecord
}

// NewMemoryProvider creates a provider from a list of key records.
func NewMemoryProvider(records []KeyRecord) *MemoryProvider {
	m := &MemoryProvider{records: make(map[string][]KeyRecord)}
	for _, r := range records {
		m.records[r.Ref] = append(m.records[r.Ref], r)
	}
	return m
}

func (p *MemoryProvider) Resolve(ref string) (KeyRecord, error) {
	versions, ok := p.records[ref]
	if !ok {
		return KeyRecord{}, fmt.Errorf("%w: %s", ErrKeyNotFound, ref)
	}
	for i := len(versions) - 1; i >= 0; i-- {
		if versions[i].Status == StatusActive {
			return versions[i], nil
		}
	}
	return KeyRecord{}, fmt.Errorf("%w: %s", ErrNoActiveKey, ref)
}

func (p *MemoryProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	versions, ok := p.records[ref]
	if !ok {
		return KeyRecord{}, fmt.Errorf("%w: %s", ErrKeyNotFound, ref)
	}
	for _, r := range versions {
		if r.Version == version {
			if r.Status == StatusDisabled {
				return KeyRecord{}, fmt.Errorf("%w: %s v%d", ErrKeyDisabled, ref, version)
			}
			return r, nil
		}
	}
	return KeyRecord{}, fmt.Errorf("%w: %s v%d", ErrKeyNotFound, ref, version)
}
