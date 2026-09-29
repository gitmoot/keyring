package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type tarEntry struct {
	name, body string
	typ        byte
}

func releaseArchive(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o755, Size: int64(len(e.body)), Typeflag: typ}
		if typ != tar.TypeReg {
			h.Size, h.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func goodEntries() []tarEntry {
	return []tarEntry{
		{name: "keyring", body: "new keyring binary"},
		{name: "keyring-caddy", body: "new caddy binary"},
		{name: "install.sh", body: "#!/bin/sh\n"},
		{name: "README.md", body: "readme"},
	}
}

// fakeGitHub serves one release the way GitHub does: the API's release JSON,
// and the assets under /download/<tag>/.
type fakeGitHub struct {
	tag, author  string
	archive      []byte
	sums         string // SHA256SUMS; empty: computed from archive
	assetBase    string // overrides the assets' download base
	downloads    int
	installedDir string
	installed    map[string]string
}

func (f *fakeGitHub) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		archiveName := "keyring-" + f.tag + "-darwin-arm64.tar.gz"
		switch r.URL.Path {
		case "/api/releases/latest", "/api/releases/tags/" + f.tag:
			assetBase := base + "/download/" + f.tag + "/"
			if f.assetBase != "" {
				assetBase = f.assetBase
			}
			rel := map[string]any{
				"tag_name": f.tag, "author": map[string]string{"login": f.author},
				"assets": []map[string]string{
					{"name": "SHA256SUMS", "browser_download_url": assetBase + "SHA256SUMS"},
					{"name": archiveName, "browser_download_url": assetBase + archiveName},
				},
			}
			json.NewEncoder(w).Encode(rel)
		case "/download/" + f.tag + "/SHA256SUMS":
			f.downloads++
			sums := f.sums
			if sums == "" {
				sums = fmt.Sprintf("%x  %s\n", sha256.Sum256(f.archive), archiveName)
			}
			io.WriteString(w, sums)
		case "/download/" + f.tag + "/" + archiveName:
			f.downloads++
			w.Write(f.archive)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	restore := []func(){}
	set := func(p *string, v string) { old := *p; *p = v; restore = append(restore, func() { *p = old }) }
	set(&releasesAPI, srv.URL+"/api/releases")
	set(&downloadBase, srv.URL+"/download/")
	set(&upgradeGOOS, "darwin")
	set(&upgradeWorkRoot, t.TempDir())
	set(&version, "v0.6.0")
	oldEUID, oldInstall := upgradeEUID, runInstall
	upgradeEUID = func() int { return 0 }
	runInstall = func(dir string, _ io.Reader, _, _ io.Writer) error {
		f.installedDir = dir
		f.installed = map[string]string{}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return err
			}
			f.installed[e.Name()] = string(b)
		}
		return nil
	}
	t.Cleanup(func() {
		for _, r := range restore {
			r()
		}
		upgradeEUID, runInstall = oldEUID, oldInstall
	})
}

func runUpgrade(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := run(append([]string{"upgrade"}, args...), strings.NewReader(""), &out, &out)
	return code, out.String()
}

func TestUpgradeInstallsTheVerifiedReleaseAndCleansUp(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	f.start(t)
	code, out := runUpgrade(t)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if f.installed["keyring"] != "new keyring binary" || f.installed["keyring-caddy"] != "new caddy binary" || f.installed["install.sh"] != "#!/bin/sh\n" {
		t.Fatalf("install.sh saw %v, want the release's files", f.installed)
	}
	if _, err := os.Stat(f.installedDir); !os.IsNotExist(err) {
		t.Fatalf("work directory %s left behind (err %v)", f.installedDir, err)
	}
	if !strings.Contains(out, "upgraded to v0.7.0") {
		t.Fatalf("output %q does not report the upgrade", out)
	}
}

func TestUpgradeRefusesAnArchiveThatDoesNotMatchSHA256SUMS(t *testing.T) {
	good := releaseArchive(t, goodEntries())
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]",
		archive: releaseArchive(t, []tarEntry{{name: "keyring", body: "evil"}, {name: "keyring-caddy", body: "x"}, {name: "install.sh", body: "x"}}),
		sums:    fmt.Sprintf("%x  keyring-v0.7.0-darwin-arm64.tar.gz\n", sha256.Sum256(good))}
	f.start(t)
	if code, out := runUpgrade(t); code == 0 || f.installed != nil {
		t.Fatalf("a tampered archive was installed (exit %d, installed %v): %s", code, f.installed, out)
	}
}

func TestUpgradeRefusesAReleaseNotPublishedByTheWorkflow(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "someone", archive: releaseArchive(t, goodEntries())}
	f.start(t)
	code, out := runUpgrade(t)
	if code == 0 || f.installed != nil || f.downloads != 0 {
		t.Fatalf("a hand-made release went ahead (exit %d, downloads %d): %s", code, f.downloads, out)
	}
}

func TestUpgradeRefusesAssetsOutsideTheRelease(t *testing.T) {
	archive := releaseArchive(t, goodEntries())
	// Another host serving a self-consistent archive and SHA256SUMS: only the
	// asset location check stands between it and install.sh.
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "SHA256SUMS") {
			fmt.Fprintf(w, "%x  keyring-v0.7.0-darwin-arm64.tar.gz\n", sha256.Sum256(archive))
			return
		}
		w.Write(archive)
	}))
	t.Cleanup(other.Close)
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: archive, assetBase: other.URL + "/v0.7.0/"}
	f.start(t)
	if code, out := runUpgrade(t); code == 0 || f.installed != nil {
		t.Fatalf("assets from another host were installed (exit %d): %s", code, out)
	}
}

func TestUpgradeRefusesArchivesWithAnythingButTheReleaseFiles(t *testing.T) {
	for name, entries := range map[string][]tarEntry{
		"path traversal": append(goodEntries(), tarEntry{name: "../keyring", body: "x"}),
		"nested path":    append(goodEntries(), tarEntry{name: "sub/keyring", body: "x"}),
		"unknown file":   append(goodEntries(), tarEntry{name: "evil.sh", body: "x"}),
		"symlink":        {{name: "keyring", typ: tar.TypeSymlink}, {name: "keyring-caddy", body: "x"}, {name: "install.sh", body: "x"}},
		"duplicate":      append(goodEntries(), tarEntry{name: "install.sh", body: "second"}),
		"no install.sh":  goodEntries()[:2],
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, entries)}
			f.start(t)
			if code, out := runUpgrade(t); code == 0 || f.installed != nil {
				t.Fatalf("installed %v (exit %d): %s", f.installed, code, out)
			}
			if left, _ := os.ReadDir(upgradeWorkRoot); len(left) != 0 {
				t.Fatalf("work directory left behind: %v", left)
			}
		})
	}
}

func TestUpgradeSkipsTheCurrentReleaseUnlessAskedForIt(t *testing.T) {
	f := &fakeGitHub{tag: "v0.6.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	f.start(t)
	if code, out := runUpgrade(t); code != 0 || f.installed != nil || !strings.Contains(out, "already up to date") {
		t.Fatalf("latest == current: exit %d, installed %v: %s", code, f.installed, out)
	}
	if code, out := runUpgrade(t, "--version", "v0.6.0"); code != 0 || f.installed == nil {
		t.Fatalf("--version v0.6.0 must reinstall: exit %d: %s", code, out)
	}
}

func TestUpgradeNeedsRootOnTheMac(t *testing.T) {
	f := &fakeGitHub{tag: "v0.7.0", author: "github-actions[bot]", archive: releaseArchive(t, goodEntries())}
	f.start(t)
	upgradeEUID = func() int { return 501 }
	if code, out := runUpgrade(t); code == 0 || f.installed != nil || !strings.Contains(out, "sudo") {
		t.Fatalf("non-root upgrade: exit %d: %s", code, out)
	}
}
