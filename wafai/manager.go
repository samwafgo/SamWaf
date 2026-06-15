package wafai

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Detector AI 检测器：持有当前模型，提供线程安全的打分与热加载。
//
// 失败安全：模型未加载/打分 panic 时，Predict 返回非命中结果，绝不影响业务转发。
type Detector struct {
	mu      sync.RWMutex
	current atomic.Pointer[loadedModel]
}

type loadedModel struct {
	engine   InferenceEngine
	manifest Manifest
}

// PredictResult 单次推理结果。
type PredictResult struct {
	Loaded           bool    // 当前是否有可用模型
	Score            float64 // 攻击概率 [0,1]
	Category         string  // 粗粒度类别提示（SQL注入/XSS/.../异常请求），用于日志展示与按规则汇总
	BlockThreshold   float64 // 模型建议的拦截阈值
	ObserveThreshold float64 // 模型建议的观察阈值
	ModelVersion     string
}

// NewDetector 创建空检测器（尚未加载模型）。
func NewDetector() *Detector {
	return &Detector{}
}

// LoadFromFile 从 .swai 文件加载模型并原子热替换。
func (d *Detector) LoadFromFile(swaiPath string) (Manifest, error) {
	pkg, err := loadPackageFile(swaiPath)
	if err != nil {
		return Manifest{}, err
	}
	return d.loadPackage(pkg)
}

// LoadFromBytes 从内存字节加载模型并原子热替换。
func (d *Detector) LoadFromBytes(data []byte) (Manifest, error) {
	pkg, err := loadPackageBytes(data)
	if err != nil {
		return Manifest{}, err
	}
	return d.loadPackage(pkg)
}

func (d *Detector) loadPackage(pkg *loadedPackage) (Manifest, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	var engine InferenceEngine
	var err error
	switch pkg.Manifest.ModelType {
	case "gbdt", "":
		engine, err = newGBDTEngine(pkg.ModelBytes, pkg.Manifest.FeatureVersion)
	case "onnx":
		engine, err = newONNXEngine(pkg.ModelBytes, pkg.Manifest.FeatureVersion)
	default:
		return Manifest{}, fmt.Errorf("不支持的模型类型: %q", pkg.Manifest.ModelType)
	}
	if err != nil {
		return Manifest{}, err
	}

	d.current.Store(&loadedModel{engine: engine, manifest: pkg.Manifest})
	return pkg.Manifest, nil
}

// Unload 卸载当前模型。
func (d *Detector) Unload() {
	d.current.Store(nil)
}

// IsLoaded 当前是否已加载模型。
func (d *Detector) IsLoaded() bool {
	return d.current.Load() != nil
}

// CurrentManifest 返回当前模型 manifest（未加载时第二个返回值为 false）。
func (d *Detector) CurrentManifest() (Manifest, bool) {
	m := d.current.Load()
	if m == nil {
		return Manifest{}, false
	}
	return m.manifest, true
}

// PredictRequest 对一次请求的关键字段打分。失败安全：任何异常返回 Loaded=false。
func (d *Detector) PredictRequest(method, path, query, body, userAgent string) (res PredictResult) {
	lm := d.current.Load()
	if lm == nil {
		return PredictResult{Loaded: false}
	}

	defer func() {
		if r := recover(); r != nil {
			// 推理 panic 时降级为未命中，绝不阻断业务
			res = PredictResult{Loaded: false}
		}
	}()

	features := ExtractFeatures(method, path, query, body, userAgent)
	score := lm.engine.Score(features)
	return PredictResult{
		Loaded:           true,
		Score:            score,
		Category:         CategoryHint(features),
		BlockThreshold:   lm.manifest.BlockThreshold,
		ObserveThreshold: lm.manifest.ObserveThreshold,
		ModelVersion:     lm.manifest.ModelVersion,
	}
}
