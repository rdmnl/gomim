// Package catrust installs and removes the gomim root CA from the host
// trust store on macOS and Linux.
package catrust

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// goos is the runtime OS, overridable in tests.
var goos = runtime.GOOS

// Install adds the CA cert at caPath to the host trust store.
func Install(caPath string) error {
	if _, err := os.Stat(caPath); err != nil {
		return fmt.Errorf("CA not found at %s (run gomim once to generate it): %w", caPath, err)
	}
	switch goos {
	case "darwin":
		return installDarwin(caPath)
	case "linux":
		return installLinux(caPath)
	default:
		return fmt.Errorf("unsupported OS %q (only darwin and linux are supported)", goos)
	}
}

// Uninstall removes the gomim root CA from the host trust store.
func Uninstall() error {
	switch goos {
	case "darwin":
		return uninstallDarwin()
	case "linux":
		return uninstallLinux()
	default:
		return fmt.Errorf("unsupported OS %q", goos)
	}
}

// --- macOS ---------------------------------------------------------------

func installDarwin(caPath string) error {
	keychain := filepath.Join(os.Getenv("HOME"), "Library", "Keychains", "login.keychain-db")
	fmt.Printf("Installing %s into login keychain (you may be prompted for your password)...\n", caPath)
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", keychain, caPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security add-trusted-cert: %w", err)
	}
	fmt.Println("Done. Trusted in login keychain.")
	return nil
}

func uninstallDarwin() error {
	keychain := filepath.Join(os.Getenv("HOME"), "Library", "Keychains", "login.keychain-db")
	cmd := exec.Command("security", "delete-certificate", "-c", "gomim Root CA", keychain)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("security delete-certificate: %w", err)
	}
	fmt.Println("Removed gomim Root CA from login keychain.")
	return nil
}

// --- Linux ---------------------------------------------------------------

type linuxStore struct {
	name      string
	anchorDir string
	dest      string // file name inside anchorDir
	refresh   string // command to refresh trust store
}

// linuxStoreCandidates lists supported Linux trust stores in priority
// order. Exposed as a var so tests can substitute stub paths.
var linuxStoreCandidates = []linuxStore{
	{
		name:      "Debian/Ubuntu/Alpine",
		anchorDir: "/usr/local/share/ca-certificates",
		dest:      "gomim.crt",
		refresh:   "update-ca-certificates",
	},
	{
		name:      "Fedora/RHEL/Arch",
		anchorDir: "/etc/pki/ca-trust/source/anchors",
		dest:      "gomim.crt",
		refresh:   "update-ca-trust",
	},
}

// statFn and lookPathFn are overridable in tests.
var (
	statFn     = os.Stat
	lookPathFn = exec.LookPath
)

func detectLinuxStore() (*linuxStore, error) {
	for _, s := range linuxStoreCandidates {
		if _, err := statFn(s.anchorDir); err != nil {
			continue
		}
		if _, err := lookPathFn(s.refresh); err != nil {
			continue
		}
		s := s
		return &s, nil
	}
	return nil, errors.New("no supported Linux trust store detected (expected /usr/local/share/ca-certificates + update-ca-certificates, or /etc/pki/ca-trust/source/anchors + update-ca-trust)")
}

func installLinux(caPath string) error {
	store, err := detectLinuxStore()
	if err != nil {
		return err
	}
	dest := filepath.Join(store.anchorDir, store.dest)
	fmt.Printf("Installing %s -> %s (%s trust store)\n", caPath, dest, store.name)
	if err := sudoCopy(caPath, dest); err != nil {
		return err
	}
	if err := sudoRun(store.refresh); err != nil {
		return err
	}
	fmt.Println("Done.")
	fmt.Println()
	fmt.Println("Note: Node, Python, and other runtimes may ignore the system trust store. You may also need:")
	fmt.Printf("  NODE_EXTRA_CA_CERTS=%s   # Node\n", caPath)
	fmt.Printf("  SSL_CERT_FILE=%s          # Python / Go\n", caPath)
	return nil
}

func uninstallLinux() error {
	store, err := detectLinuxStore()
	if err != nil {
		return err
	}
	dest := filepath.Join(store.anchorDir, store.dest)
	fmt.Printf("Removing %s\n", dest)
	if err := sudoRun("rm", "-f", dest); err != nil {
		return err
	}
	if store.refresh == "update-ca-certificates" {
		if err := sudoRun(store.refresh, "--fresh"); err != nil {
			return err
		}
	} else {
		if err := sudoRun(store.refresh); err != nil {
			return err
		}
	}
	fmt.Println("Done.")
	return nil
}

// --- helpers -------------------------------------------------------------

func sudoRun(name string, args ...string) error {
	full := append([]string{name}, args...)
	if os.Geteuid() != 0 {
		full = append([]string{"sudo"}, full...)
	}
	cmd := exec.Command(full[0], full[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// sudoCopy copies src -> dst using cat | sudo tee, so the elevation
// happens only on the write side. We avoid invoking `cp` so we can stream
// from a non-root-readable home directory if needed.
func sudoCopy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	args := []string{"tee", dst}
	if os.Geteuid() != 0 {
		args = append([]string{"sudo"}, args...)
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdin = in
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}
