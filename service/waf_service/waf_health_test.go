package waf_service

import (
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/request"
	"SamWaf/model/wafenginmodel"
	"SamWaf/wafhealth"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHealthServiceOwnBusinessDestination(t *testing.T) {
	listeners := wafenginmodel.NewSafeServerMap()
	listeners.Set(19381, innerbean.ServerRunTime{Port: 19381, Status: 0})
	listeners.Set(19382, innerbean.ServerRunTime{Port: 19382, Status: 1})
	guard, err := newHealthDialGuard(listeners)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"127.0.0.1:19381", "[::1]:19381", "[::ffff:127.0.0.1]:19381"} {
		if guard(addr) == nil {
			t.Fatalf("listener allowed: %s", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:19382", "192.0.2.1:19381"} {
		if err := guard(addr); err != nil {
			t.Fatalf("origin rejected %s %v", addr, err)
		}
	}
}

func TestHealthServiceOwnAdminDestination(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer server.Close()
	ip, rawPort, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	oldDB, oldPort := global.GWAF_LOCAL_DB, global.GWAF_LOCAL_SERVER_PORT
	global.GWAF_LOCAL_DB = nil
	global.GWAF_LOCAL_SERVER_PORT = port
	t.Cleanup(func() { global.GWAF_LOCAL_DB = oldDB; global.GWAF_LOCAL_SERVER_PORT = oldPort })
	req := request.WafHostHealthTestReq{Host: "test.example", RemoteHost: "http://localhost", RemoteIP: ip, RemotePort: port, Limit: 5}
	cfg := model.HealthyConfig{CheckMethod: "GET", ResponseTime: 2, ExpectedCodes: "200"}
	for _, explicitIP := range []string{ip, ""} {
		req.RemoteIP = explicitIP
		res, err := WafHealthServiceApp.Test(context.Background(), req, cfg)
		if err != nil || len(res.Results) != 1 || res.Results[0].Outcome != wafhealth.Failed || hits.Load() != 0 {
			t.Fatalf("admin probe: %+v %v hits=%d", res, err, hits.Load())
		}
	}
	global.GWAF_LOCAL_SERVER_PORT = port + 1
	res, err := WafHealthServiceApp.Test(context.Background(), req, cfg)
	if err != nil || res.Results[0].Outcome != wafhealth.Passed || hits.Load() != 1 {
		t.Fatalf("local origin: %+v %v hits=%d", res, err, hits.Load())
	}
}

func TestHealthServiceConcurrencyAndCancellation(t *testing.T) {
	var active, maximum atomic.Int32
	entered := make(chan struct{}, 4)
	oldDB := global.GWAF_LOCAL_DB
	global.GWAF_LOCAL_DB = nil
	t.Cleanup(func() { global.GWAF_LOCAL_DB = oldDB })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); current > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, current) {
				break
			}
		}
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer server.Close()
	ip, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	req := request.WafHostHealthTestReq{Host: "test.example", RemoteHost: "http://origin.example", RemoteIP: ip, RemotePort: port, Limit: 5}
	cfg := model.HealthyConfig{CheckMethod: "GET", ResponseTime: 5, ExpectedCodes: "200"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	errors := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := WafHealthServiceApp.Test(ctx, req, cfg); errors <- err }()
	}
	for i := 0; i < 4; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			cancel()
			wg.Wait()
			t.Fatal("probe did not start")
		}
	}
	if _, err := WafHealthServiceApp.Test(context.Background(), req, cfg); err == nil {
		t.Fatal("fifth batch must be busy")
	}
	cancel()
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != context.Canceled {
			t.Fatalf("cancel error %v", err)
		}
	}
	if len(healthTestSlots) != 0 || maximum.Load() != 4 {
		t.Fatalf("slots=%d max=%d", len(healthTestSlots), maximum.Load())
	}
	if _, err := WafHealthServiceApp.Test(ctx, req, cfg); err != context.Canceled {
		t.Fatalf("already canceled: %v", err)
	}
	if len(healthTestSlots) != 0 {
		t.Fatal("canceled request retained slot")
	}
}
