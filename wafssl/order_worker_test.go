package wafssl

import (
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"SamWaf/model/spec"
	"context"
	"errors"
	"testing"
	"time"
)

func testSSLOrder(id string, submitted bool) spec.ChanSslOrder {
	return spec.ChanSslOrder{Content: model.SslOrder{BaseOrm: baseorm.BaseOrm{Id: id}}, Submitted: submitted}
}

func receiveSSLOrder[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for certificate worker")
		panic("unreachable")
	}
}

func TestSSLOrderWorkerSerialAndScheduledBackpressure(t *testing.T) {
	worker := sslOrderExecutor{orders: make(chan spec.ChanSslOrder, 1), space: make(chan struct{}, 1)}
	started := make(chan string, 4)
	release := make(chan struct{})
	apply := func(ctx context.Context, job spec.ChanSslOrder) {
		order := job.Content
		started <- order.Id
		if order.Id == "first" {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}
	if err := worker.submit(testSSLOrder("before activate", true)); !errors.Is(err, errSSLOrderWorkerUnavailable) {
		t.Fatalf("before start: %v", err)
	}
	worker.start(apply, func(model.SslOrder) {})
	t.Cleanup(worker.stop)
	worker.start(apply, func(model.SslOrder) {})
	if err := worker.submit(testSSLOrder("first", true)); err != nil {
		t.Fatal(err)
	}
	if got := receiveSSLOrder(t, started); got != "first" {
		t.Fatal(got)
	}
	if err := worker.submit(testSSLOrder("second", true)); err != nil {
		t.Fatal(err)
	}
	if err := worker.submit(testSSLOrder("extra manual", true)); !errors.Is(err, errSSLOrderQueueFull) {
		t.Fatalf("want full queue, got %v", err)
	}
	scheduled := make(chan error, 1)
	go func() { scheduled <- worker.submitScheduled(testSSLOrder("scheduled", false)) }()
	select {
	case got := <-started:
		t.Fatalf("%s overlapped first order", got)
	case err := <-scheduled:
		t.Fatalf("scheduled order didn't wait for space: %v", err)
	default:
	}
	close(release)
	if got := receiveSSLOrder(t, started); got != "second" {
		t.Fatal(got)
	}
	if err := receiveSSLOrder(t, scheduled); err != nil {
		t.Fatal(err)
	}
	if got := receiveSSLOrder(t, started); got != "scheduled" {
		t.Fatal(got)
	}
}

func TestSSLOrderWorkerStopCancelsAndDrainsSubmittedOrders(t *testing.T) {
	worker := sslOrderExecutor{orders: make(chan spec.ChanSslOrder, 2), space: make(chan struct{}, 1)}
	started := make(chan string, 3)
	abandoned := make(chan string, 3)
	worker.start(func(ctx context.Context, job spec.ChanSslOrder) {
		order := job.Content
		started <- order.Id
		<-ctx.Done()
	}, func(order model.SslOrder) {
		abandoned <- order.Id
	})
	t.Cleanup(worker.stop)
	if err := worker.submit(testSSLOrder("active", true)); err != nil {
		t.Fatal(err)
	}
	if got := receiveSSLOrder(t, started); got != "active" {
		t.Fatal(got)
	}
	for _, order := range []spec.ChanSslOrder{testSSLOrder("pending manual", true), testSSLOrder("pending auto", false)} {
		if err := worker.submit(order); err != nil {
			t.Fatal(err)
		}
	}
	scheduled := make(chan error, 1)
	go func() { scheduled <- worker.submitScheduled(testSSLOrder("waiting auto", false)) }()
	stopped := make(chan struct{})
	go func() {
		worker.stop()
		close(stopped)
	}()
	receiveSSLOrder(t, stopped)
	if err := receiveSSLOrder(t, scheduled); !errors.Is(err, errSSLOrderWorkerUnavailable) {
		t.Fatalf("scheduled sender did not stop: %v", err)
	}
	if got := receiveSSLOrder(t, abandoned); got != "pending manual" {
		t.Fatal(got)
	}
	if len(abandoned) != 0 || len(started) != 0 || len(worker.orders) != 0 {
		t.Fatal("worker processed buffered work after stop or changed a scheduled order")
	}
	worker.start(func(context.Context, spec.ChanSslOrder) {}, func(model.SslOrder) {})
	if err := worker.submit(testSSLOrder("restart", true)); !errors.Is(err, errSSLOrderWorkerUnavailable) {
		t.Fatalf("worker accepted work after stop: %v", err)
	}
}

func TestSSLOrderWorkerDeduplicatesRenewalSource(t *testing.T) {
	worker := sslOrderExecutor{orders: make(chan spec.ChanSslOrder, 2), space: make(chan struct{}, 1)}
	started := make(chan struct{}, 1)
	worker.start(func(ctx context.Context, _ spec.ChanSslOrder) {
		started <- struct{}{}
		<-ctx.Done()
	}, func(model.SslOrder) {})
	t.Cleanup(worker.stop)
	renewal := testSSLOrder("renewal", true)
	renewal.SourceOrderID = "source"
	if err := worker.submit(renewal); err != nil {
		t.Fatal(err)
	}
	receiveSSLOrder(t, started)
	if err := worker.submit(renewal); !errors.Is(err, errSSLOrderAlreadyQueued) {
		t.Fatalf("manual renewal was not deduplicated: %v", err)
	}
	if err := worker.submitScheduled(testSSLOrder("source", false)); err != nil || len(worker.orders) != 0 {
		t.Fatalf("scheduled renewal was not skipped: err=%v, queued=%d", err, len(worker.orders))
	}
}

func TestSSLOrderWorkerStopBeforeActivate(t *testing.T) {
	worker := sslOrderExecutor{orders: make(chan spec.ChanSslOrder, 1), space: make(chan struct{}, 1)}
	worker.stop()
	worker.start(func(context.Context, spec.ChanSslOrder) {}, func(model.SslOrder) {})
	if worker.done != nil {
		t.Fatal("worker activated after shutdown began")
	}
}
