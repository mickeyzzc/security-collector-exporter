package ebpf

import (
	"testing"
)

func TestNewSpaceSaving(t *testing.T) {
	ss := NewSpaceSaving(10)
	if ss == nil {
		t.Fatal("NewSpaceSaving() 返回 nil")
	}
	top := ss.TopN(5)
	if len(top) != 0 {
		t.Fatalf("新建后 TopN 应为空, 实际长度: %d", len(top))
	}
}

func TestIncrement_NewKeys(t *testing.T) {
	ss := NewSpaceSaving(10)
	ss.Increment("a")
	ss.Increment("b")
	ss.Increment("c")

	top := ss.TopN(3)
	if len(top) != 3 {
		t.Fatalf("TopN(3) 应返回 3 条, 实际: %d", len(top))
	}
	// 所有新 key 计数均为 1
	for _, e := range top {
		if e.Count != 1 {
			t.Errorf("新 key %q 计数应为 1, 实际: %d", e.Key, e.Count)
		}
	}
}

func TestIncrement_ExistingKey(t *testing.T) {
	ss := NewSpaceSaving(10)
	ss.Increment("a")
	ss.Increment("a")
	ss.Increment("a")

	top := ss.TopN(1)
	if len(top) != 1 {
		t.Fatalf("TopN(1) 应返回 1 条, 实际: %d", len(top))
	}
	if top[0].Key != "a" {
		t.Errorf("Top1 key 应为 'a', 实际: %q", top[0].Key)
	}
	if top[0].Count != 3 {
		t.Errorf("'a' 计数应为 3, 实际: %d", top[0].Count)
	}
}

func TestTopN_Ordering(t *testing.T) {
	ss := NewSpaceSaving(10)
	// c=5, a=3, b=1
	for i := 0; i < 5; i++ {
		ss.Increment("c")
	}
	for i := 0; i < 3; i++ {
		ss.Increment("a")
	}
	ss.Increment("b")

	top := ss.TopN(3)
	if len(top) != 3 {
		t.Fatalf("TopN(3) 应返回 3 条, 实际: %d", len(top))
	}
	if top[0].Key != "c" || top[0].Count != 5 {
		t.Errorf("Top1 应为 c(5), 实际: %q(%d)", top[0].Key, top[0].Count)
	}
	if top[1].Key != "a" || top[1].Count != 3 {
		t.Errorf("Top2 应为 a(3), 实际: %q(%d)", top[1].Key, top[1].Count)
	}
	if top[2].Key != "b" || top[2].Count != 1 {
		t.Errorf("Top3 应为 b(1), 实际: %q(%d)", top[2].Key, top[2].Count)
	}
}

func TestCapacity_Eviction(t *testing.T) {
	ss := NewSpaceSaving(3)
	ss.Increment("a")
	ss.Increment("b")
	ss.Increment("b")
	ss.Increment("c")
	ss.Increment("c")
	ss.Increment("c")

	// 容量已满(3), 'a' 计数最少(1)
	// 插入 'd' 应淘汰 'a'，继承计数 1+1=2
	ss.Increment("d")

	top := ss.TopN(3)
	keys := make(map[string]bool)
	for _, e := range top {
		keys[e.Key] = true
	}
	if keys["a"] {
		t.Error("'a' 应被淘汰")
	}
	if !keys["d"] {
		t.Error("'d' 应存在")
	}
	// 'd' 继承 'a' 的计数(1) +1 = 2
	for _, e := range top {
		if e.Key == "d" && e.Count != 2 {
			t.Errorf("'d' 计数应为 2, 实际: %d", e.Count)
		}
	}
}

func TestCapacity_Bounded(t *testing.T) {
	capacity := 5
	ss := NewSpaceSaving(capacity)

	// 插入远超容量的 key 数量
	for i := 0; i < 100; i++ {
		ss.Increment(string(rune('A' + i%20)))
	}

	if len(ss.counters) > capacity {
		t.Errorf("counters 长度 %d 超过容量 %d", len(ss.counters), capacity)
	}
}

func TestSpaceSaving_Reset(t *testing.T) {
	ss := NewSpaceSaving(10)
	ss.Increment("a")
	ss.Increment("b")
	ss.Increment("c")

	ss.Reset()

	top := ss.TopN(5)
	if len(top) != 0 {
		t.Fatalf("Reset 后 TopN 应为空, 实际长度: %d", len(top))
	}
}

func TestTopN_ExceedsSize(t *testing.T) {
	ss := NewSpaceSaving(3)
	ss.Increment("a")
	ss.Increment("b")

	// 请求比实际条目更多的 Top-N
	top := ss.TopN(10)
	if len(top) != 2 {
		t.Errorf("TopN(10) 只有 2 条数据, 应返回 2 条, 实际: %d", len(top))
	}
}
