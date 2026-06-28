// main.go — Go net/http baseline for the consolidated battletest.
//
// The standard-library Go HTTP server, mirroring the other servers' routes (`/`, `/health`) so the
// comparison is a same-workload, same-load-generator test. Port comes from argv[1] (default 8084).
// net/http already serves each connection on its own goroutine across all cores, so this is the
// idiomatic, production-shaped Go baseline (no third-party framework).
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := "8084"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "OK\n")
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
