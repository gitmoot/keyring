package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// version is the release tag, set at build time by the release workflow
// (-ldflags "-X main.version=vX.Y.Z"). A local build says "dev".
var version = "dev"

// The upgrade trusts what the owner used to check by hand: the release page
// on github.com and its SHA256SUMS, fetched from GitHub itself, never from
// the agents' server. The publisher check proves only that a GitHub Actions
// token in this repo published the release, not that release.yml (which
// builds only tags on main) did: a workflow merged into main could publish
// one too. That is no wider than today, since such a merge could change
// release.yml itself.
var (
	releasesAPI   = "https://api.github.com/repos/gitmoot/keyring/releases"
	downloadBase  = "https://github.com/gitmoot/keyring/releases/download/"
	releaseAuthor = "github-actions[bot]"
	upgradeClient = &http.Client{Timeout: 5 * time.Minute}
	// GitHub's download host sometimes answers 5xx for minutes (#130): each
	// request is retried after these pauses (about two minutes in all),
	// alternating with the release asset API for assets.
	retryPauses  = []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	upgradeSleep = time.Sleep
	// upgradeWorkRoot must be a directory that only root can write, all the
	// way up to /: install.sh refuses to run from anywhere else.
	upgradeWorkRoot = "/var/root"
	upgradeGOOS     = runtime.GOOS
	upgradeEUID     = os.Geteuid
	// runInstall runs the release's own install.sh on its keyring binary.
	runInstall = func(dir string, stdin io.Reader, stdout, stderr io.Writer) error {
		cmd := exec.Command("/bin/sh", filepath.Join(dir, "install.sh"), filepath.Join(dir, "keyring"))
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
		return cmd.Run()
	}
)

var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// The archive may hold these regular files and nothing else.
var releaseFiles = map[string]int64{
	"keyring":       200 << 20,
	"keyring-caddy": 200 << 20,
	"install.sh":    1 << 20,
	"README.md":     1 << 20,
}

type githubRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Author     struct {
		Login string `json:"login"`
	} `json:"author"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		// APIURL is the same file through the API host
		// (<releasesAPI>/assets/<id>, Accept: application/octet-stream).
		APIURL string `json:"url"`
	} `json:"assets"`
}

// releaseAsset is one file of the release, at both of its GitHub addresses.
type releaseAsset struct{ url, apiURL string }

var assetAPIPath = regexp.MustCompile(`^/assets/[0-9]+$`)

// upgrade installs the latest release (or want, e.g. "v0.6.0" to go back) on
// this Mac. It must run as root.
func upgrade(want string, stdin io.Reader, stdout, stderr io.Writer) error {
	if upgradeGOOS != "darwin" {
		return errors.New("upgrade installs the Mac keyring; run it on the Mac")
	}
	if upgradeEUID() != 0 {
		return errors.New("run it as root: sudo keyring-upgrade")
	}
	if want != "" && !releaseTag.MatchString(want) {
		return fmt.Errorf("--version %q: want a release tag like v0.7.0", want)
	}
	url := releasesAPI + "/latest"
	if want != "" {
		url = releasesAPI + "/tags/" + want
	}
	var rel githubRelease
	if err := getJSON(url, &rel, stderr); err != nil {
		return err
	}
	if err := checkRelease(rel, want); err != nil {
		return err
	}
	if want == "" && releaseTag.MatchString(version) {
		switch c := compareTags(rel.TagName, version); {
		case c == 0:
			fmt.Fprintf(stdout, "already up to date: %s\n", version)
			return nil
		case c < 0:
			// GitHub's "latest" is the most recently published release,
			// not the highest version.
			return fmt.Errorf("the latest release %s is older than the installed %s; nothing installed (to go back on purpose: --version %s)", rel.TagName, version, rel.TagName)
		}
	}
	archiveName := "keyring-" + rel.TagName + "-darwin-arm64.tar.gz"
	sumsAsset, archiveAsset, err := releaseAssets(rel, archiveName)
	if err != nil {
		return err
	}
	sums, err := fetchAsset(sumsAsset, 64<<10, stderr)
	if err != nil {
		return err
	}
	wantSum, err := sumFor(sums, archiveName)
	if err != nil {
		return err
	}
	archive, err := fetchAsset(archiveAsset, 400<<20, stderr)
	if err != nil {
		return err
	}
	got := sha256.Sum256(archive)
	if hex.EncodeToString(got[:]) != wantSum {
		return fmt.Errorf("%s: sha256 %x does not match the release's SHA256SUMS (%s); nothing installed", archiveName, got, wantSum)
	}
	fmt.Fprintf(stdout, "%s -> %s\n%s sha256 %s (matches the release page)\n", version, rel.TagName, archiveName, wantSum)

	dir, err := os.MkdirTemp(upgradeWorkRoot, "keyring-upgrade-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := unpackRelease(archive, dir); err != nil {
		return err
	}
	if err := runInstall(dir, stdin, stdout, stderr); err != nil {
		return fmt.Errorf("install.sh: %w", err)
	}
	fmt.Fprintf(stdout, "upgraded to %s\n", rel.TagName)
	return nil
}

func checkRelease(rel githubRelease, want string) error {
	switch {
	case !releaseTag.MatchString(rel.TagName):
		return fmt.Errorf("release tag %q is not a version tag", rel.TagName)
	case want != "" && rel.TagName != want:
		return fmt.Errorf("asked for %s, GitHub returned %s", want, rel.TagName)
	case rel.Draft || rel.Prerelease:
		return fmt.Errorf("release %s is a draft or pre-release", rel.TagName)
	case rel.Author.Login != releaseAuthor:
		return fmt.Errorf("release %s was published by %q, not the release workflow (%s); nothing installed", rel.TagName, rel.Author.Login, releaseAuthor)
	}
	return nil
}

// releaseAssets returns SHA256SUMS and the archive. Each download URL must be
// exactly <downloadBase><tag>/<name>, the address GitHub gives this release's
// assets, and each API URL <releasesAPI>/assets/<id>; anything else (another
// host, another release, a ../) is refused. Either address serves the same
// bytes, and the archive is checked against SHA256SUMS whichever answered.
func releaseAssets(rel githubRelease, archiveName string) (sums, archive releaseAsset, err error) {
	base := downloadBase + rel.TagName + "/"
	found := map[string]releaseAsset{}
	for _, a := range rel.Assets {
		if a.Name != "SHA256SUMS" && a.Name != archiveName {
			continue
		}
		if a.URL != base+a.Name {
			return sums, archive, fmt.Errorf("asset %s is at %s, not %s", a.Name, a.URL, base+a.Name)
		}
		api := ""
		if rest, ok := strings.CutPrefix(a.APIURL, releasesAPI); ok && assetAPIPath.MatchString(rest) {
			api = a.APIURL
		} else if a.APIURL != "" {
			return sums, archive, fmt.Errorf("asset %s API address %s is not under %s/assets/", a.Name, a.APIURL, releasesAPI)
		}
		found[a.Name] = releaseAsset{url: a.URL, apiURL: api}
	}
	sums, okSums := found["SHA256SUMS"]
	archive, okArchive := found[archiveName]
	if !okSums || !okArchive {
		return sums, archive, fmt.Errorf("release %s lacks SHA256SUMS or %s", rel.TagName, archiveName)
	}
	return sums, archive, nil
}

// compareTags compares two vX.Y.Z tags numerically: -1, 0 or 1.
func compareTags(a, b string) int {
	pa, pb := strings.Split(a[1:], "."), strings.Split(b[1:], ".")
	for i := range 3 {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// sumFor finds name's sha256 in a sha256sum listing.
func sumFor(sums []byte, name string) (string, error) {
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			if len(f[0]) != 64 {
				break
			}
			if _, err := hex.DecodeString(f[0]); err != nil {
				break
			}
			return strings.ToLower(f[0]), nil
		}
	}
	return "", fmt.Errorf("SHA256SUMS has no valid line for %s", name)
}

// unpackRelease writes the archive's files into dir. Anything but the known
// regular files at the top level is refused, and every known file but the
// README must be present.
func unpackRelease(archive []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		limit, ok := releaseFiles[h.Name]
		if !ok || h.Typeflag != tar.TypeReg || seen[h.Name] {
			return fmt.Errorf("archive entry %q is not one of the release files; nothing installed", h.Name)
		}
		if h.Size > limit {
			return fmt.Errorf("archive entry %s is too large", h.Name)
		}
		seen[h.Name] = true
		mode := os.FileMode(0o644)
		if h.Name != "README.md" {
			mode = 0o755
		}
		f, err := os.OpenFile(filepath.Join(dir, h.Name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, io.LimitReader(tr, limit))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	for _, name := range []string{"keyring", "keyring-caddy", "install.sh"} {
		if !seen[name] {
			return fmt.Errorf("archive lacks %s; nothing installed", name)
		}
	}
	return nil
}

func getJSON(url string, v any, log io.Writer) error {
	body, err := withRetries(log, func(int) (string, string) { return url, "" }, 1<<20)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%s: %w", url, err)
	}
	return nil
}

// fetchAsset downloads an asset, alternating between its download URL and
// the release asset API while GitHub answers 5xx.
func fetchAsset(a releaseAsset, limit int64, log io.Writer) ([]byte, error) {
	return withRetries(log, func(attempt int) (string, string) {
		if attempt%2 == 1 && a.apiURL != "" {
			return a.apiURL, "application/octet-stream"
		}
		return a.url, ""
	}, limit)
}

// withRetries GETs the address at(attempt) gives until one answers 200,
// pausing per retryPauses after a network error, 429 or 5xx. Any other answer
// is final.
func withRetries(log io.Writer, at func(attempt int) (url, accept string), limit int64) ([]byte, error) {
	var last error
	for attempt := 0; ; attempt++ {
		url, accept := at(attempt)
		body, retry, err := download(url, accept, limit)
		if err == nil {
			return body, nil
		}
		last = err
		if !retry || attempt >= len(retryPauses) {
			break
		}
		fmt.Fprintf(log, "%v; trying again in %s\n", err, retryPauses[attempt])
		upgradeSleep(retryPauses[attempt])
	}
	return nil, last
}

// download GETs url; retry reports a failure worth trying again (network
// error, 429 or 5xx).
func download(url, accept string, limit int64) (body []byte, retry bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := upgradeClient.Do(req)
	if err != nil {
		return nil, true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(body)) > limit {
		return nil, false, fmt.Errorf("GET %s: larger than %d bytes", url, limit)
	}
	return body, false, nil
}
