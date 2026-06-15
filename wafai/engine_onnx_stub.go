//go:build !samwaf_onnx

package wafai

import "errors"

// newONNXEngine 默认构建不含 ONNX 运行时（保持主分支零新增 CGO/外部依赖）。
// 需要 ONNX 深度模型增强档时，用 `-tags samwaf_onnx` 编译并提供 engine_onnx.go 实现。
func newONNXEngine(modelBytes []byte, featureVersion string) (InferenceEngine, error) {
	return nil, errors.New("当前构建未启用 ONNX 引擎（需使用 -tags samwaf_onnx 编译）")
}
