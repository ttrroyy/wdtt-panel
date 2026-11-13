package panel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func withInstallation(t *testing.T) {
	t.Helper()
	previousDB, previousPath, previousDir := panelDB, panelDBPath, wdttConfigDir
	wdttConfigDir = t.TempDir()
	panelDBPath = filepath.Join(wdttConfigDir, "panel.db")
	t.Cleanup(func() {
		if panelDB != nil {
			panelDB.Close()
		}
		panelDB, panelDBPath, wdttConfigDir = previousDB, previousPath, previousDir
	})
	if err := initPanelDB(); err != nil {
		t.Fatal(err)
	}
	ensureDefaultWdttData()
	t.Setenv("WDTT_BACKEND_PORT", "2860")
	t.Setenv("WDTT_INITIAL_PASSWORD", "initial-password")
	if err := ConfigureInstallation(); err != nil {
		t.Fatal(err)
	}
	if err := writeInstallCredentials("admin", "initial-password"); err != nil {
		t.Fatal(err)
	}
}

func withStdin(t *testing.T, text string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	writer.WriteString(text)
	writer.Close()
	previous := os.Stdin
	os.Stdin = reader
	t.Cleanup(func() { os.Stdin = previous; reader.Close() })
}

func credentialsFile(t *testing.T) string {
	data, err := os.ReadFile(installCredentialsPath())
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(installCredentialsPath())
	if info.Mode().Perm() != 0600 && os.PathSeparator == '/' {
		t.Fatalf("credentials mode %v", info.Mode())
	}
	return string(data)
}

func loginMatches(t *testing.T, user, password string) bool {
	cfg, err := loadPanelConfig()
	if err != nil {
		t.Fatal(err)
	}
	return cfg.Username == user && bcrypt.CompareHashAndPassword([]byte(cfg.PasswordHash), []byte(password)) == nil
}

func TestSetCredentialsUpdatesLoginAndFile(t *testing.T) {
	withInstallation(t)
	withStdin(t, "boss\nNew Pass-1\n")
	if err := SetCredentials(); err != nil {
		t.Fatal(err)
	}
	if !loginMatches(t, "boss", "New Pass-1") || loginMatches(t, "admin", "initial-password") {
		t.Fatal("login not replaced")
	}
	if credentialsFile(t) != "boss\nNew Pass-1\n" {
		t.Fatalf("file %q", credentialsFile(t))
	}
	// Paths and the port stay: only the login changes.
	cfg, _ := loadPanelConfig()
	if cfg.Port != 2860 || cfg.WebBasePath == "/wdtt/" {
		t.Fatal("installation settings changed")
	}
}

func TestSetCredentialsRejectsIncompleteInput(t *testing.T) {
	withInstallation(t)
	for _, input := range []string{"", "boss\n", "\npassword\n", "boss\n\n", "boss", strings.Repeat("a", 257) + "\npassword\n"} {
		withStdin(t, input)
		if err := SetCredentials(); err == nil {
			t.Fatalf("accepted %q", input)
		}
		if !loginMatches(t, "admin", "initial-password") || credentialsFile(t) != "admin\ninitial-password\n" {
			t.Fatalf("login changed by %q", input)
		}
	}
}

func TestPanelPasswordChangeKeepsCredentialsFile(t *testing.T) {
	withInstallation(t)
	cfg, err := loadPanelConfig()
	if err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: cfg}
	post := func(body string) int {
		recorder := httptest.NewRecorder()
		app.handlePanelPassword(recorder, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		return recorder.Code
	}
	if post(`{"old_password":"wrong","new_password":"x"}`) != 401 || credentialsFile(t) != "admin\ninitial-password\n" {
		t.Fatal("wrong password accepted")
	}
	// A new username alone keeps the known password in the file.
	if post(`{"old_password":"initial-password","new_username":"boss"}`) != 200 || credentialsFile(t) != "boss\ninitial-password\n" {
		t.Fatalf("username change: %q", credentialsFile(t))
	}
	if post(`{"old_password":"initial-password","new_password":"second-password"}`) != 200 || credentialsFile(t) != "boss\nsecond-password\n" {
		t.Fatalf("password change: %q", credentialsFile(t))
	}
	if post(`{"old_password":"second-password","new_username":"a\nb"}`) != 400 || !loginMatches(t, "boss", "second-password") {
		t.Fatal("username with a newline accepted")
	}
}
