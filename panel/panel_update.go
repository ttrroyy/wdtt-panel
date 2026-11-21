package panel

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const wdttGitHubRepository = "ttrroyy/wdtt-panel"

var wdttReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var panelUpdateLock sync.Mutex

type wdttGitHubRelease struct {
	TagName    string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
	} `json:"assets"`
}

func panelReleaseBinName() string {
	switch runtime.GOARCH {
	case "arm64":
		return "wdtt-linux-arm64"
	default:
		return "wdtt-linux-amd64"
	}
}

func panelInstallPath() string {
	if p := strings.TrimSpace(os.Getenv("WDTT_PANEL_BIN")); p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		base := filepath.Base(exe)
		if base == "wdtt" || base == "wdtt-app" || base == "wdtt-panel" {
			return exe
		}
	}
	if serviceUnitExists(panelServiceUnit) {
		return "/usr/local/bin/wdtt-panel"
	}
	return wdttServerBin
}

func fetchWdttPanelReleases() ([]string, error) {
	client := &http.Client{Timeout: 20 * time.Second}
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases?per_page=20", wdttGitHubRepository)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, githubAPIMaxBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, githubAPIError(resp.StatusCode, body)
	}
	var releases []wdttGitHubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("GitHub releases JSON: %w", err)
	}
	tags := make([]string, 0, len(releases))
	for _, rel := range releases {
		if rel.Draft || rel.Prerelease || !wdttReleaseTag.MatchString(rel.TagName) {
			continue
		}
		assets := make(map[string]bool, len(rel.Assets))
		for _, asset := range rel.Assets {
			assets[asset.Name] = true
		}
		if assets[panelReleaseBinName()+".sha256"] && assets["wdtt-runtime.tar.gz.sha256"] {
			tags = append(tags, rel.TagName)
		}
	}
	return filterReleaseTagsSinceDB(tags), nil
}

func installPanelVersion(tag string) error {
	panelUpdateLock.Lock()
	defer panelUpdateLock.Unlock()
	tag = strings.TrimSpace(tag)
	if !wdttReleaseTag.MatchString(tag) {
		return fmt.Errorf("некорректная версия панели")
	}
	binName := panelReleaseBinName()
	url := fmt.Sprintf("https://github.com/%s/releases/download/%s/", wdttGitHubRepository, tag)
	dest := panelInstallPath()
	dir, err := os.MkdirTemp(filepath.Dir(dest), ".wdtt-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	tmp := filepath.Join(dir, binName)
	if err := downloadPanelAsset(url, tmp); err != nil {
		return fmt.Errorf("скачивание %s: %w", tag, err)
	}
	if err := os.Chmod(tmp, 0755); err != nil {
		return err
	}
	nonce := filepath.Base(dir)
	backup := dest + ".bak." + nonce
	if _, err := os.Stat(dest); err == nil {
		if err := os.Link(dest, backup); err != nil {
			return fmt.Errorf("резервная копия панели: %w", err)
		}
	}
	restoreCores, err := updatePanelCores(url, nonce)
	if err != nil {
		return fmt.Errorf("обновление ядер: %w", err)
	}
	restoreRuntime, cleanupRuntime, err := updatePanelRuntime(url)
	if err != nil {
		if restoreCores != nil {
			err = errors.Join(err, restoreCores())
		}
		return fmt.Errorf("обновление файлов управления: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		if restoreErr := restoreRuntime(); restoreErr != nil {
			err = errors.Join(err, restoreErr)
		} else {
			cleanupRuntime()
		}
		if restoreCores != nil {
			err = errors.Join(err, restoreCores())
		}
		return err
	}
	cleanupRuntime()
	log.Printf("[PANEL] updated to %s (%s)", tag, dest)
	go func() {
		time.Sleep(800 * time.Millisecond)
		if err := exec.Command("systemctl", "try-restart", "wdtt-protocol@*.service", "wdtt-edge@*.service", "wdtt-protocol-watch.service", "wdtt-fleet.service").Run(); err != nil {
			log.Printf("[PANEL] restart updated services: %v", err)
		}
		if err := restartPanelService(); err != nil {
			log.Printf("[PANEL] self-restart after update: %v", err)
		}
	}()
	return nil
}

func downloadPanelAsset(baseURL, path string) error {
	name := filepath.Base(path)
	if err := downloadFile(baseURL+name+".sha256", path+".sha256"); err != nil {
		return err
	}
	if err := downloadFile(baseURL+name, path); err != nil {
		return err
	}
	digest, err := os.ReadFile(path + ".sha256")
	if err != nil {
		return err
	}
	binary, err := os.Open(path)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, err = io.Copy(hash, binary)
	binary.Close()
	if err != nil {
		return err
	}
	if fields := strings.Fields(string(digest)); len(fields) != 2 || fields[1] != name || fields[0] != hex.EncodeToString(hash.Sum(nil)) {
		return fmt.Errorf("контрольная сумма %s не совпадает", name)
	}
	return nil
}

func updatePanelCores(url, nonce string) (func() error, error) {
	const dest = "/usr/local/lib/wdtt/protocols"
	role, err := os.ReadFile("/etc/wdtt/role")
	if err != nil || strings.TrimSpace(string(role)) == "panel" {
		return nil, nil
	}
	arch := "x86_64"
	if runtime.GOARCH == "arm64" {
		arch = "aarch64"
	}
	staging, err := os.MkdirTemp(filepath.Dir(dest), ".wdtt-cores-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(staging)
	archive := filepath.Join(staging, "wdtt-cores-linux-"+arch+".tar.gz")
	if err := downloadPanelAsset(url, archive); err != nil {
		return nil, err
	}
	next := filepath.Join(staging, "cores")
	if err := unpackPanelCores(archive, next); err != nil {
		return nil, err
	}
	previous := dest + ".bak." + nonce
	if err := os.Rename(dest, previous); err != nil {
		return nil, err
	}
	if err := os.Rename(next, dest); err != nil {
		return nil, errors.Join(err, os.Rename(previous, dest))
	}
	return func() error {
		if err := os.Rename(dest, dest+".failed."+nonce); err != nil {
			return err
		}
		return os.Rename(previous, dest)
	}, nil
}

func unpackPanelCores(archive, dest string) error {
	if err := extractPanelArchive(archive, dest); err != nil {
		return err
	}
	// A partially published archive cannot replace the installed set.
	for _, name := range []string{"qwdtt", "wdtt-plus", "freeturn", "csqtt-2.1.9", "csqtt-2.5.0", "csqtt-2.5.3-community", "mrtt",
		"dnstt", "vaydns", "slipstream", "masterdns", "cottendns", "soar", "soar-native", "openflux"} {
		if info, err := os.Stat(filepath.Join(dest, name)); err != nil || info.Mode().Perm()&0111 == 0 || info.Size() == 0 {
			return fmt.Errorf("в архиве отсутствует исполняемый файл %s", name)
		}
	}
	return nil
}

func extractPanelArchive(archive, dest string) error {
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer compressed.Close()
	input := tar.NewReader(compressed)
	for {
		entry, err := input.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if entry.Typeflag != tar.TypeReg || !filepath.IsLocal(entry.Name) {
			return fmt.Errorf("недопустимая запись архива ядер: %q", entry.Name)
		}
		path := filepath.Join(dest, entry.Name)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(entry.Mode)&0755)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(out, input)
		if err := errors.Join(copyErr, out.Close()); err != nil {
			return err
		}
	}
	return nil
}

func updatePanelRuntime(url string) (restore func() error, cleanup func(), err error) {
	const dest = "/usr/local/lib/wdtt"
	staging, err := os.MkdirTemp(dest, ".wdtt-runtime-")
	if err != nil {
		return nil, nil, err
	}
	cleanup = func() { _ = os.RemoveAll(staging) }
	retainBackup := false
	defer func() {
		if err != nil && !retainBackup {
			_ = os.RemoveAll(staging)
		}
	}()
	archive := filepath.Join(staging, "wdtt-runtime.tar.gz")
	if err := downloadPanelAsset(url, archive); err != nil {
		return nil, nil, err
	}
	next := filepath.Join(staging, "next")
	if err := extractPanelArchive(archive, next); err != nil {
		return nil, nil, err
	}
	restore, err = replacePanelRuntime(next, dest)
	if err != nil {
		retainBackup = true
		return nil, nil, fmt.Errorf("%w (%s)", err, staging)
	}
	return restore, cleanup, nil
}

func replacePanelRuntime(source, dest string) (func() error, error) {
	names := []string{"protocols.py", "edge_protocols.py", "fleet.py", "frontend.py", "preflight.py", "uninstall.py", "panel-firewall.py", "node-source.tar.gz"}
	backup := filepath.Join(filepath.Dir(source), "previous")
	if err := os.Mkdir(backup, 0700); err != nil {
		return nil, err
	}
	hadFile := make(map[string]bool, len(names))
	for _, name := range names {
		info, err := os.Stat(filepath.Join(source, name))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return nil, fmt.Errorf("в архиве отсутствует %s", name)
		}
		err = os.Link(filepath.Join(dest, name), filepath.Join(backup, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		hadFile[name] = err == nil
	}
	var installed []string
	restore := func() error {
		var result error
		for _, name := range installed {
			if hadFile[name] {
				result = errors.Join(result, os.Rename(filepath.Join(backup, name), filepath.Join(dest, name)))
			} else {
				result = errors.Join(result, os.Remove(filepath.Join(dest, name)))
			}
		}
		return result
	}
	for _, name := range names {
		if err := os.Rename(filepath.Join(source, name), filepath.Join(dest, name)); err != nil {
			return nil, errors.Join(err, restore())
		}
		installed = append(installed, name)
	}
	return restore, nil
}
