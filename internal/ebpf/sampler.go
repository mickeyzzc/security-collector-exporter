package ebpf

import (
	"sync"
	"time"
)

// nowFunc 类型用于时间注入，方便测试
type nowFunc func() time.Time

// AdaptiveSampler 自适应采样控制器
// 根据实际事件速率动态调整采样率，防止高负载下资源争抢
type AdaptiveSampler struct {
	mu          sync.Mutex
	sampleRate  uint64        // 当前采样率（1=全量, 10=每10个取1个）
	targetRPS   int           // 目标事件速率（events/sec）
	eventCount  uint64        // 当前窗口内的事件计数
	windowStart time.Time     // 当前窗口开始时间
	windowSize  time.Duration // 评估窗口大小
	minRate     uint64        // 最低采样率（不能低于此值）
	maxRate     uint64        // 最高采样率
	now         nowFunc       // 时间函数，可注入用于测试
}

// NewAdaptiveSampler 创建自适应采样器
func NewAdaptiveSampler(targetRPS int) *AdaptiveSampler {
	now := time.Now()
	return &AdaptiveSampler{
		sampleRate:  1,
		targetRPS:   targetRPS,
		windowStart: now,
		windowSize:  10 * time.Second,
		minRate:     1,
		maxRate:     10000,
		now:         time.Now,
	}
}

// newAdaptiveSamplerWithNow 创建带自定义时间函数的采样器（测试用）
func newAdaptiveSamplerWithNow(targetRPS int, fn nowFunc) *AdaptiveSampler {
	return &AdaptiveSampler{
		sampleRate:  1,
		targetRPS:   targetRPS,
		windowStart: fn(),
		windowSize:  10 * time.Second,
		minRate:     1,
		maxRate:     10000,
		now:         fn,
	}
}

// Record 记录一个事件，返回 true 表示应该处理，false 表示应丢弃
func (s *AdaptiveSampler) Record(eventCount uint64) bool {
	s.mu.Lock()
	s.eventCount += eventCount
	s.mu.Unlock()
	return true // 采样决策在 Adjust 中完成
}

// Adjust 每 windowSize 调用一次，根据实际速率调整采样率
// 返回当前采样率
func (s *AdaptiveSampler) Adjust() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	elapsed := now.Sub(s.windowStart)
	if elapsed < s.windowSize {
		return s.sampleRate
	}

	// 计算实际 RPS
	actualRPS := int(float64(s.eventCount) / elapsed.Seconds())

	if actualRPS > s.targetRPS*2 {
		// 事件过多，提高采样率（降低精度保资源）
		newRate := s.sampleRate * 2
		if newRate > s.maxRate {
			newRate = s.maxRate
		}
		s.sampleRate = newRate
	} else if actualRPS < s.targetRPS/2 && s.sampleRate > s.minRate {
		// 事件稀少，降低采样率（恢复精度）
		newRate := s.sampleRate / 2
		if newRate < s.minRate {
			newRate = s.minRate
		}
		s.sampleRate = newRate
	}

	// 重置窗口
	s.eventCount = 0
	s.windowStart = now

	return s.sampleRate
}

// SampleRate 返回当前采样率
func (s *AdaptiveSampler) SampleRate() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sampleRate
}

// SetSampleRate 手动设置采样率
func (s *AdaptiveSampler) SetSampleRate(rate uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rate < s.minRate {
		rate = s.minRate
	}
	if rate > s.maxRate {
		rate = s.maxRate
	}
	s.sampleRate = rate
}
