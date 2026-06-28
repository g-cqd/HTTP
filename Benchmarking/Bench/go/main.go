// main.go — Go net/http baseline for the consolidated battletest.
//
// The standard-library Go HTTP server, implementing the shared parity route set (/, /json, /payload,
// /hello/<name>, POST /echo, /health) so every server runs an identical workload under the same load
// generator. net/http serves each connection on its own goroutine across all cores — the idiomatic,
// production-shaped Go baseline (no third-party framework). Port from argv[1] (default 8084).
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	port := "8084"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	payload := strings.Repeat("from-scratch swift http server. ", 32) // 32 × 32 B = 1024 B

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "OK\n")
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"message":"Hello, World!"}`)
	})
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, payload)
	})
	mux.HandleFunc("/hello/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/hello/")
		greeting := r.URL.Query().Get("greeting")
		if greeting == "" {
			greeting = "Hello"
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "%s, %s!\n", greeting, name)
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "Hello from the Go baseline.\n")
	})

	server := &http.Server{Addr: "127.0.0.1:" + port, Handler: mux}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
