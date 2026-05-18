package ebpf

import "sort"

// SpaceSaving 实现 Space-Saving 算法，用于维护固定数量的 Top-K 频繁项
// 内存严格有界: capacity 个槽位，不会增长
type SpaceSaving struct {
	capacity int
	counters map[string]*counter
	minKey   string // 当前最小计数的 key（缓存优化）
}

type counter struct {
	key   string
	count uint64
}

// NewSpaceSaving 创建 SpaceSaving 实例
// capacity: 保留的槽位数（推荐 100）
func NewSpaceSaving(capacity int) *SpaceSaving {
	return &SpaceSaving{
		capacity: capacity,
		counters: make(map[string]*counter, capacity),
	}
}

// Increment 递增指定 key 的计数
// 如果 key 已存在，直接递增
// 如果 key 不存在且有空槽，创建新条目
// 如果 key 不存在且无空槽，替换当前最小计数的条目（继承其计数+1）
func (s *SpaceSaving) Increment(key string) {
	if c, ok := s.counters[key]; ok {
		c.count++
		s.minKey = "" // 清除缓存，下次查找时重新计算
		return
	}

	if len(s.counters) < s.capacity {
		s.counters[key] = &counter{key: key, count: 1}
		return
	}

	// 替换最小计数的条目
	minKey := s.findMinKey()
	if minKey == "" {
		return
	}
	old := s.counters[minKey]
	delete(s.counters, minKey)
	old.key = key
	old.count++
	s.counters[key] = old
	s.minKey = ""
}

// TopN 返回前 N 个最频繁的条目（按计数降序）
func (s *SpaceSaving) TopN(n int) []TopNEntry {
	entries := make([]TopNEntry, 0, len(s.counters))
	for _, c := range s.counters {
		entries = append(entries, TopNEntry{Key: c.key, Count: c.count})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Count > entries[j].Count
	})
	if n > len(entries) {
		n = len(entries)
	}
	return entries[:n]
}

// TopNEntry Top-N 条目
type TopNEntry struct {
	Key   string
	Count uint64
}

// findMinKey 查找当前最小计数的 key
func (s *SpaceSaving) findMinKey() string {
	if s.minKey != "" {
		if _, ok := s.counters[s.minKey]; ok {
			return s.minKey
		}
	}
	var minCount = ^uint64(0)
	var found string
	for k, c := range s.counters {
		if c.count < minCount {
			minCount = c.count
			found = k
		}
	}
	s.minKey = found
	return found
}

// Reset 清空所有计数器
func (s *SpaceSaving) Reset() {
	s.counters = make(map[string]*counter, s.capacity)
	s.minKey = ""
}
