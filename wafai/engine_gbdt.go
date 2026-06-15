package wafai

import (
	"bufio"
	"bytes"
	"fmt"

	"github.com/dmitryikh/leaves"
)

// gbdtEngine 基于 dmitryikh/leaves 的纯 Go LightGBM 推理引擎（一期）。
type gbdtEngine struct {
	model          *leaves.Ensemble
	featureVersion string
}

// newGBDTEngine 从 LightGBM 文本模型字节构建引擎。
// loadTransformation=true 让 leaves 加载 sigmoid 变换，PredictSingle 直接输出概率。
func newGBDTEngine(modelBytes []byte, featureVersion string) (*gbdtEngine, error) {
	br := bufio.NewReader(bytes.NewReader(modelBytes))
	model, err := leaves.LGEnsembleFromReader(br, true)
	if err != nil {
		return nil, fmt.Errorf("加载 LightGBM 模型失败: %w", err)
	}
	if nf := model.NFeatures(); nf != FeatureCount {
		return nil, fmt.Errorf("模型特征维度=%d 与引擎=%d 不一致", nf, FeatureCount)
	}
	return &gbdtEngine{model: model, featureVersion: featureVersion}, nil
}

func (e *gbdtEngine) Score(features []float64) float64 {
	// nIterations=0 表示使用全部树
	return e.model.PredictSingle(features, 0)
}

func (e *gbdtEngine) FeatureVersion() string { return e.featureVersion }

func (e *gbdtEngine) Type() string { return "gbdt" }
