package ebpf

import (
	"testing"
	"time"
)

func TestSampler_Initial(t *testing.T) {
	s := NewAdaptiveSampler(5000)
	if rate := s.SampleRate(); rate != 1 {
		t.Errorf("初始采样率应为 1，实际为 %d", rate)
	}
}

func TestSampler_HighLoad_IncreaseRate(t *testing.T) {
	baseTime := time.Now()
	s := newAdaptiveSamplerWithNow(5000, func() time.Time { return baseTime })

	// 模拟高负载：目标 5000 RPS，2× 即 >10000 RPS
	// 窗口 10s 内产生 200000 个事件 = 20000 RPS
	s.Record(200000)

	// 推进时间超过窗口大小
	baseTime = baseTime.Add(11 * time.Second)

	rate := s.Adjust()
	if rate <= 1 {
		t.Errorf("高负载下采样率应上升，实际为 %d", rate)
	}
	if rate != 2 {
		t.Errorf("首次倍增采样率应为 2，实际为 %d", rate)
	}

	// 再次模拟高负载，采样率应继续倍增
	s.Record(200000)
	baseTime = baseTime.Add(11 * time.Second)

	rate = s.Adjust()
	if rate != 4 {
		t.Errorf("二次倍增采样率应为 4，实际为 %d", rate)
	}
}

func TestSampler_LowLoad_DecreaseRate(t *testing.T) {
	baseTime := time.Now()
	s := newAdaptiveSamplerWithNow(5000, func() time.Time { return baseTime })

	// 先设高采样率
	s.SetSampleRate(8)

	// 模拟低负载：目标 5000 RPS，0.5× 即 <2500 RPS
	// 窗口 10s 内产生 10000 个事件 = 1000 RPS
	s.Record(10000)
	baseTime = baseTime.Add(11 * time.Second)

	rate := s.Adjust()
	if rate >= 8 {
		t.Errorf("低负载下采样率应下降，实际为 %d", rate)
	}
	if rate != 4 {
		t.Errorf("减半后采样率应为 4，实际为 %d", rate)
	}
}

func TestSampler_RateBoundaries(t *testing.T) {
	baseTime := time.Now()
	s := newAdaptiveSamplerWithNow(5000, func() time.Time { return baseTime })

	// 测试上界：采样率不超过 maxRate
	s.SetSampleRate(10000) // = maxRate

	// 极高负载
	s.Record(999999999)
	baseTime = baseTime.Add(11 * time.Second)

	rate := s.Adjust()
	if rate != 10000 {
		t.Errorf("采样率不应超过 maxRate(10000)，实际为 %d", rate)
	}

	// 测试下界：使用新 sampler，采样率从 1 开始，低负载不应再降低
	baseTime2 := time.Now()
	s2 := newAdaptiveSamplerWithNow(5000, func() time.Time { return baseTime2 })
	s2.Record(1)
	baseTime2 = baseTime2.Add(11 * time.Second)

	rate = s2.Adjust()
	if rate != 1 {
		t.Errorf("采样率不应低于 minRate(1)，实际为 %d", rate)
	}
}

func TestSampler_ManualSet(t *testing.T) {
	s := NewAdaptiveSampler(5000)

	// 正常设置
	s.SetSampleRate(50)
	if rate := s.SampleRate(); rate != 50 {
		t.Errorf("手动设置采样率为 50，实际为 %d", rate)
	}

	// 设置低于 minRate，应被限制到 minRate
	s.SetSampleRate(0)
	if rate := s.SampleRate(); rate != 1 {
		t.Errorf("采样率低于 minRate 应为 1，实际为 %d", rate)
	}

	// 设置高于 maxRate，应被限制到 maxRate
	s.SetSampleRate(999999)
	if rate := s.SampleRate(); rate != 10000 {
		t.Errorf("采样率高于 maxRate 应为 10000，实际为 %d", rate)
	}
}

func TestSampler_Adjust_WindowNotElapsed(t *testing.T) {
	baseTime := time.Now()
	s := newAdaptiveSamplerWithNow(5000, func() time.Time { return baseTime })

	// 窗口未结束时调用 Adjust，不应调整
	s.Record(999999)

	rate := s.Adjust()
	if rate != 1 {
		t.Errorf("窗口未结束时采样率不应变化，实际为 %d", rate)
	}
}

func TestSampler_StableLoad_NoChange(t *testing.T) {
	baseTime := time.Now()
	s := newAdaptiveSamplerWithNow(5000, func() time.Time { return baseTime })

	// 模拟稳定负载：5000 RPS（在 0.5×~2× 范围内）
	// 窗口 10s 内产生 50000 个事件 = 5000 RPS
	s.Record(50000)
	baseTime = baseTime.Add(11 * time.Second)

	rate := s.Adjust()
	if rate != 1 {
		t.Errorf("稳定负载下采样率应保持不变，实际为 %d", rate)
	}
}
