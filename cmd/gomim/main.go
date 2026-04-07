package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/rdmnl/gomim/internal/ca"
	"github.com/rdmnl/gomim/internal/catrust"
	"github.com/rdmnl/gomim/internal/logger"
	"github.com/rdmnl/gomim/internal/proxy"
	"github.com/rdmnl/gomim/internal/ui"
)

// Build-time metadata, populated via -ldflags by GoReleaser.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Subcommands handled before flag parsing so they can have their own
	// flag set and don't trip on unknown flags.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install-ca":
			runInstallCA(os.Args[2:])
			return
		case "uninstall-ca":
			runUninstallCA(os.Args[2:])
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}

	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	showVersion := flag.Bool("version", false, "print version and exit")
	caDir := flag.String("ca-dir", defaultCADir(), "directory for root CA cert/key")
	logPath := flag.String("log", "", "JSON log file (default stdout)")
	reverse := flag.String("reverse", "", "reverse-proxy mode: forward all requests to this upstream (e.g. https://api.anthropic.com)")
	uiAddr := flag.String("ui", "", "live web viewer listen address, off by default (e.g. -ui 127.0.0.1:8081 then open http://127.0.0.1:8081)")
	noRedact := flag.Bool("no-redact", false, "disable redaction of sensitive headers (Authorization, Cookie, X-Api-Key, ...)")
	flag.Parse()

	if *showVersion {
		log.Printf("gomim %s (commit %s, built %s)", version, commit, date)
		return
	}

	c, err := ca.LoadOrCreate(*caDir)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}

	out := os.Stdout
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("log: %v", err)
		}
		defer f.Close()
		out = f
	}
	lg := logger.New(out)
	if *noRedact {
		lg.SetRedact(false)
		log.Printf("WARNING: header redaction disabled; secrets will be written in plaintext")
	}
	p := proxy.New(c, lg)
	if *reverse != "" {
		u, err := url.Parse(*reverse)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			log.Fatalf("reverse: invalid URL %q (must be http(s)://host)", *reverse)
		}
		p.Reverse = u
		log.Printf("reverse-proxy mode: upstream = %s", u)
	}

	if *uiAddr != "" {
		go func() {
			log.Printf("live viewer at http://%s", *uiAddr)
			uiSrv := &http.Server{
				Addr:              *uiAddr,
				Handler:           ui.Handler(lg, *uiAddr),
				ReadHeaderTimeout: 10 * time.Second,
				ReadTimeout:       30 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			if err := uiSrv.ListenAndServe(); err != nil {
				log.Printf("ui: %v", err)
			}
		}()
	}

	log.Printf("gomim listening on %s", *addr)
	log.Printf("CA at %s/ca.pem - trust it via: gomim install-ca", *caDir)
	srv := &http.Server{
		Addr:              *addr,
		Handler:           p,
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      0, // streaming responses (SSE) need no write deadline
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func defaultCADir() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".gomim")
}

func runInstallCA(args []string) {
	fs := flag.NewFlagSet("install-ca", flag.ExitOnError)
	caDir := fs.String("ca-dir", defaultCADir(), "directory containing the root CA cert")
	fs.Parse(args)

	// Generate the CA if it doesn't already exist so the user doesn't
	// have to run `gomim` once first.
	if _, err := ca.LoadOrCreate(*caDir); err != nil {
		log.Fatalf("ca: %v", err)
	}
	caPath := filepath.Join(*caDir, "ca.pem")
	if err := catrust.Install(caPath); err != nil {
		log.Fatalf("install-ca: %v", err)
	}
}

func runUninstallCA(args []string) {
	fs := flag.NewFlagSet("uninstall-ca", flag.ExitOnError)
	fs.Parse(args)
	if err := catrust.Uninstall(); err != nil {
		log.Fatalf("uninstall-ca: %v", err)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `gomim - local MITM debugging proxy

Usage:
  gomim [flags]                start the proxy
  gomim install-ca [-ca-dir D] trust the gomim root CA in your system store
  gomim uninstall-ca           remove the gomim root CA from your system store
  gomim -version               print version
  gomim -h                     show this help

Flags (for the proxy):
`)
	// Build a temporary flagset just to print defaults.
	fs := flag.NewFlagSet("gomim", flag.ContinueOnError)
	fs.String("addr", "127.0.0.1:8080", "listen address")
	fs.String("ca-dir", defaultCADir(), "directory for root CA cert/key")
	fs.String("log", "", "JSON log file (default stdout)")
	fs.String("reverse", "", "reverse-proxy mode upstream URL")
	fs.String("ui", "", "live web viewer listen address, off by default (e.g. -ui 127.0.0.1:8081)")
	fs.Bool("no-redact", false, "log sensitive headers in plaintext")
	fs.SetOutput(os.Stderr)
	fs.PrintDefaults()
}
