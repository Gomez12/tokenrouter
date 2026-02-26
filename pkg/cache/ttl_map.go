package cache

import (
	"sync"
	"time"
)

type item[V any] struct {
	Value     V
	ExpiresAt time.Time
}

type Entry[V any] struct {
	Value     V
	ExpiresAt time.Time
}

type TTLMap[K comparable, V any] struct {
	mu    sync.RWMutex
	items map[K]item[V]
}

func NewTTLMap[K comparable, V any]() *TTLMap[K, V] {
	return &TTLMap[K, V]{items: map[K]item[V]{}}
}

func (m *TTLMap[K, V]) Get(key K) (V, time.Time, bool) {
	var zero V
	if m == nil {
		return zero, time.Time{}, false
	}
	m.mu.RLock()
	it, ok := m.items[key]
	m.mu.RUnlock()
	if !ok {
		return zero, time.Time{}, false
	}
	return it.Value, it.ExpiresAt, true
}

func (m *TTLMap[K, V]) GetFresh(key K, now time.Time) (V, bool) {
	var zero V
	v, exp, ok := m.Get(key)
	if !ok {
		return zero, false
	}
	if !exp.IsZero() && !now.Before(exp) {
		return zero, false
	}
	return v, true
}

func (m *TTLMap[K, V]) SetWithTTL(key K, value V, now time.Time, ttl time.Duration) {
	exp := time.Time{}
	if ttl > 0 {
		exp = now.Add(ttl)
	}
	m.SetWithExpiry(key, value, exp)
}

func (m *TTLMap[K, V]) SetWithExpiry(key K, value V, expiresAt time.Time) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.items[key] = item[V]{Value: value, ExpiresAt: expiresAt}
	m.mu.Unlock()
}

func (m *TTLMap[K, V]) Delete(key K) {
	if m == nil {
		return
	}
	m.mu.Lock()
	delete(m.items, key)
	m.mu.Unlock()
}

func (m *TTLMap[K, V]) Entries() map[K]Entry[V] {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[K]Entry[V], len(m.items))
	for k, it := range m.items {
		out[k] = Entry[V]{
			Value:     it.Value,
			ExpiresAt: it.ExpiresAt,
		}
	}
	return out
}
