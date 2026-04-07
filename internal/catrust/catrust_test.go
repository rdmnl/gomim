package catrust

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stubFS lets tests pretend specific anchor dirs exist and specific
// refresh tools are on $PATH.
type stubFS struct {
	dirs map[string]bool
	cmds map[string]bool
}

func (s *stubFS) stat(name string) (os.FileInfo, error) {
	if s.dirs[name] {
		// detectLinuxStore only checks the error, not the FileInfo.
		return nil, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
}

func (s *stubFS) lookPath(name string) (string, error) {
	if s.cmds[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

// withStubs swaps statFn / lookPathFn for the duration of the test.
func withStubs(t *testing.T, dirs, cmds []string) {
	t.Helper()
	s := &stubFS{
		dirs: map[string]bool{},
		cmds: map[string]bool{},
	}
	for _, d := range dirs {
		s.dirs[d] = true
	}
	for _, c := range cmds {
		s.cmds[c] = true
	}
	origStat, origLook := statFn, lookPathFn
	statFn = s.stat
	lookPathFn = s.lookPath
	t.Cleanup(func() {
		statFn = origStat
		lookPathFn = origLook
	})
}

func TestDetectLinuxStore_Debian(t *testing.T) {
	withStubs(t,
		[]string{"/usr/local/share/ca-certificates"},
		[]string{"update-ca-certificates"},
	)
	got, err := detectLinuxStore()
	if err != nil {
		t.Fatal(err)
	}
	if got.refresh != "update-ca-certificates" {
		t.Errorf("got refresh=%q, want update-ca-certificates", got.refresh)
	}
	if !strings.Contains(got.name, "Debian") {
		t.Errorf("got name=%q, want Debian-ish", got.name)
	}
}

func TestDetectLinuxStore_Fedora(t *testing.T) {
	withStubs(t,
		[]string{"/etc/pki/ca-trust/source/anchors"},
		[]string{"update-ca-trust"},
	)
	got, err := detectLinuxStore()
	if err != nil {
		t.Fatal(err)
	}
	if got.refresh != "update-ca-trust" {
		t.Errorf("got refresh=%q, want update-ca-trust", got.refresh)
	}
	if !strings.Contains(got.name, "Fedora") {
		t.Errorf("got name=%q, want Fedora-ish", got.name)
	}
}

func TestDetectLinuxStore_DebianPreferredOverFedora(t *testing.T) {
	// Both present — Debian should win because it's first in the list.
	withStubs(t,
		[]string{
			"/usr/local/share/ca-certificates",
			"/etc/pki/ca-trust/source/anchors",
		},
		[]string{"update-ca-certificates", "update-ca-trust"},
	)
	got, err := detectLinuxStore()
	if err != nil {
		t.Fatal(err)
	}
	if got.refresh != "update-ca-certificates" {
		t.Errorf("Debian should win, got %q", got.refresh)
	}
}

func TestDetectLinuxStore_DirPresentButToolMissing(t *testing.T) {
	// Anchor dir exists but the refresh tool is missing — should fall
	// through and ultimately error.
	withStubs(t,
		[]string{"/usr/local/share/ca-certificates"},
		nil,
	)
	if _, err := detectLinuxStore(); err == nil {
		t.Error("expected error when refresh tool is missing")
	}
}

func TestDetectLinuxStore_NothingDetected(t *testing.T) {
	withStubs(t, nil, nil)
	if _, err := detectLinuxStore(); err == nil {
		t.Error("expected error when no store detected")
	}
}

func TestInstall_MissingCA(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.pem")
	err := Install(missing)
	if err == nil {
		t.Fatal("expected error for missing CA")
	}
	if !strings.Contains(err.Error(), "CA not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInstall_UnsupportedOS(t *testing.T) {
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := goos
	goos = "plan9"
	t.Cleanup(func() { goos = orig })

	err := Install(caPath)
	if err == nil {
		t.Fatal("expected error for unsupported OS")
	}
	if !strings.Contains(err.Error(), "unsupported OS") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestUninstall_UnsupportedOS(t *testing.T) {
	orig := goos
	goos = "plan9"
	t.Cleanup(func() { goos = orig })

	if err := Uninstall(); err == nil {
		t.Error("expected error for unsupported OS")
	}
}
