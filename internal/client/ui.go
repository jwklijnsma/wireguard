package client

import (
	"context"
	"embed"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed ui/*
var uiFS embed.FS

const UIAddr = "127.0.0.1:51821"

// ServeUI runs the local control UI. It only listens on loopback, rejects
// foreign Host headers (DNS rebinding) and requires a custom header on every
// state-changing request (blocks cross-site requests from web pages).
func ServeUI(ctx context.Context, m *Manager, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := uiFS.ReadFile("ui/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	mux.HandleFunc("GET /app.js", func(w http.ResponseWriter, r *http.Request) {
		b, _ := uiFS.ReadFile("ui/app.js")
		w.Header().Set("Content-Type", "text/javascript")
		w.Write(b)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		js(w, 200, m.Status())
	})
	mux.HandleFunc("POST /api/connect", func(w http.ResponseWriter, r *http.Request) {
		var req ConnectRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			js(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := m.Connect(req); err != nil {
			js(w, 400, map[string]string{"error": err.Error()})
			return
		}
		js(w, 200, m.Status())
	})
	mux.HandleFunc("POST /api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		m.Disconnect()
		js(w, 200, m.Status())
	})

	_, port, _ := net.SplitHostPort(addr)
	allowed := map[string]bool{"127.0.0.1:" + port: true, "localhost:" + port: true}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowed[strings.ToLower(r.Host)] {
			http.Error(w, "forbidden host", 403)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-WG2FA") != "1" {
			http.Error(w, "forbidden", 403)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func js(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
