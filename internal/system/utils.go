package system

// BoolToFloat64 将bool转换为float64
func BoolToFloat64(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}
