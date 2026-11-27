package wafssl

import (
	"SamWaf/common/zlog"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/spec"
	"SamWaf/service/waf_service"
	"context"
	"errors"
	"sync"
)

var (
	errSSLOrderWorkerUnavailable = errors.New("证书任务执行器暂不可用，请稍后重试")
	errSSLOrderQueueFull         = errors.New("证书任务队列已满，请稍后重试")
	errSSLOrderAlreadyQueued     = errors.New("该证书已有待执行的续期任务")
	sslOrderWorker               = sslOrderExecutor{orders: global.GWAF_CHAN_SSLOrder, space: make(chan struct{}, 1)}
)

type sslOrderExecutor struct {
	mu       sync.Mutex
	stopping bool
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	orders   chan spec.ChanSslOrder
	space    chan struct{}
	pending  map[string]struct{}
}

func StartOrderWorker(apply func(context.Context, spec.ChanSslOrder)) {
	sslOrderWorker.start(apply, func(order model.SslOrder) {
		if err := waf_service.WafSSLOrderServiceApp.FailSubmittedOrder(order, "服务停止，证书任务未执行，请重新发起"); err != nil {
			zlog.Error("记录未执行的证书订单失败", err)
		}
	})
}

func CancelOrderWorker() { sslOrderWorker.cancelWork() }

func StopOrderWorker() { sslOrderWorker.stop() }

func SubmitOrder(order spec.ChanSslOrder) error { return sslOrderWorker.submit(order) }

// SubmitScheduledOrder waits for capacity so a renewal scan can cover every site.
func SubmitScheduledOrder(order spec.ChanSslOrder) error {
	return sslOrderWorker.submitScheduled(order)
}

func (w *sslOrderExecutor) start(apply func(context.Context, spec.ChanSslOrder), failSubmitted func(model.SslOrder)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping || w.ctx != nil {
		return
	}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.done = make(chan struct{})
	w.pending = make(map[string]struct{})
	go w.run(w.ctx, w.done, apply, failSubmitted)
}

func (w *sslOrderExecutor) cancelWork() <-chan struct{} {
	w.mu.Lock()
	w.stopping = true
	done := w.done
	if w.cancel != nil {
		w.cancel()
	}
	w.mu.Unlock()
	return done
}

func (w *sslOrderExecutor) stop() {
	if done := w.cancelWork(); done != nil {
		<-done
	}
}

func (w *sslOrderExecutor) submit(order spec.ChanSslOrder) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.stopping || w.ctx == nil {
		return errSSLOrderWorkerUnavailable
	}
	key := renewalSourceID(order)
	if _, pending := w.pending[key]; pending {
		return errSSLOrderAlreadyQueued
	}
	select {
	case w.orders <- order:
		if key != "" {
			w.pending[key] = struct{}{}
		}
		return nil
	default:
		return errSSLOrderQueueFull
	}
}

func renewalSourceID(order spec.ChanSslOrder) string {
	if order.Submitted {
		return order.SourceOrderID
	}
	return order.Content.Id
}

func (w *sslOrderExecutor) submitScheduled(order spec.ChanSslOrder) error {
	for {
		err := w.submit(order)
		if errors.Is(err, errSSLOrderAlreadyQueued) {
			return nil
		}
		if !errors.Is(err, errSSLOrderQueueFull) {
			return err
		}
		select {
		case <-w.ctx.Done():
			return errSSLOrderWorkerUnavailable
		case <-w.space:
		}
	}
}

func (w *sslOrderExecutor) run(ctx context.Context, done chan<- struct{}, apply func(context.Context, spec.ChanSslOrder), failSubmitted func(model.SslOrder)) {
	defer close(done)
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
		case order := <-w.orders:
			select {
			case w.space <- struct{}{}:
			default:
			}
			if ctx.Err() == nil {
				orderCtx, cancel := context.WithCancel(ctx)
				apply(orderCtx, order)
				cancel()
				w.mu.Lock()
				delete(w.pending, renewalSourceID(order))
				w.mu.Unlock()
			} else if order.Submitted {
				failSubmitted(order.Content)
			}
		}
	}
	for {
		select {
		case order := <-w.orders:
			if order.Submitted {
				failSubmitted(order.Content)
			}
		default:
			return
		}
	}
}
