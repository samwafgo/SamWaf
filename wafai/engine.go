package wafai

// InferenceEngine 推理引擎抽象。
//
// 一期实现为纯 Go GBDT（engine_gbdt.go，dmitryikh/leaves 加载 LightGBM）。
// 二期可选 ONNX 深度模型增强档（engine_onnx.go，build tag 隔离）。
type InferenceEngine interface {
	// Score 输入特征向量，返回 [0,1] 的攻击概率。
	Score(features []float64) float64
	// FeatureVersion 模型训练时使用的特征版本，用于与 Go 侧特征版本校验。
	FeatureVersion() string
	// Type 引擎类型标识："gbdt" / "onnx"。
	Type() string
}
