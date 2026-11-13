package panel

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type App struct {
	cfg       *PanelConfig
	subMu     sync.Mutex
	subCancel context.CancelFunc
	subSrv    *http.Server
}

// Run запускает HTTP-панель (блокирует до ошибки).
func Run() error {
	if err := initI18n(); err != nil {
		return fmt.Errorf("i18n: %w", err)
	}
	if err := initTemplates(); err != nil {
		return fmt.Errorf("templates: %w", err)
	}
	if err := BootstrapDB(); err != nil {
		return fmt.Errorf("panel db: %w", err)
	}

	cfg, err := loadPanelConfig()
	if err != nil {
		return err
	}
	if _, err := loadWdttInbound(); err != nil {
		log.Printf("panel inbound load: %v", err)
	}
	ensureMinimalWdttServiceUnit()
	initAssetsVer()
	if acmeCronInstalled() {
		_ = ensureAcmeCron()
	}
	if installationRole() != "panel" {
		ensureWdttXrayDirs()
		patchWdttXrayService()
		if err := patchXrayStatsAPIOnDisk(); err != nil {
			log.Printf("xray stats API patch: %v", err)
		}
		startStatusCollector()
		go func() {
			for {
				if err := syncProtocolXray(); err != nil {
					log.Printf("protocol routing: %v", err)
				}
				time.Sleep(3 * time.Second)
			}
		}()
	}
	if installationRole() == "panel" {
		startStatusCollector()
	}

	app := &App{cfg: cfg}
	// wdtt-panel-credentials changes the login in the database and sends SIGHUP: the VPN in this process keeps running.
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			if fresh, err := loadPanelConfig(); err == nil {
				app.cfg.Username, app.cfg.PasswordHash = fresh.Username, fresh.PasswordHash
			}
		}
	}()
	app.startSubscriptionServer()
	base := cfg.basePath()
	mux := http.NewServeMux()

	// Public
	mux.HandleFunc(base, app.serveLogin)
	mux.HandleFunc(strings.TrimSuffix(base, "/"), app.serveLogin)
	mux.HandleFunc(base+"login", app.handleLogin)
	mux.HandleFunc(base+"getTwoFactorEnable", app.handleTwoFactorEnable)
	mux.HandleFunc(base+"logout/", app.handleLogout)
	mux.HandleFunc(base+"logout", app.handleLogout)
	mux.HandleFunc(normalizeSubPath(cfg.SubPath), func(w http.ResponseWriter, r *http.Request) {
		if !app.cfg.SubEnable {
			http.NotFound(w, r)
			return
		}
		app.handleSubscription(w, r)
	})

	// 3x-ui assets (как в 3x-ui: долгий кэш + gzip на уровне сервера)
	assetsH := withCacheControl(assetsHandler(), "max-age=31536000, public")
	mux.Handle(normalizeSubPath(cfg.SubPath)+"assets/", http.StripPrefix(normalizeSubPath(cfg.SubPath)+"assets/", assetsH))
	mux.Handle(base+"assets/", http.StripPrefix(base+"assets/", assetsH))

	// Panel pages
	mux.HandleFunc(base+"panel/", app.serveDashboard)
	mux.HandleFunc(base+"panel/users", app.serveUsersPage)
	mux.HandleFunc(base+"panel/connections", app.serveConnectionsPage)
	mux.HandleFunc(base+"panel/nodes", func(w http.ResponseWriter, r *http.Request) {
		if app.parseSession(r) == nil {
			http.Redirect(w, r, base, 302)
			return
		}
		app.renderHTML(w, r, "nodes.html", "Ноды", nil)
	})
	mux.HandleFunc(base+"panel/api-keys", func(w http.ResponseWriter, r *http.Request) {
		if app.parseSession(r) == nil {
			http.Redirect(w, r, base, 302)
			return
		}
		app.renderHTML(w, r, "api_keys.html", "API-ключи", nil)
	})
	mux.HandleFunc(base+"panel/xray", app.serveXrayPage)
	mux.HandleFunc(base+"panel/settings", app.serveSettingsPage)

	// 3x-ui compatible xray API
	mux.HandleFunc(base+"panel/xray/", app.requireAuthCSRF(app.handleXrayAPI))
	mux.HandleFunc(base+"panel/setting/getDefaultJsonConfig", app.requireAuthCSRF(app.handleDefaultJsonConfig))
	mux.HandleFunc(base+"panel/api/custom-geo/aliases", app.requireAuthCSRF(app.handleCustomGeoAliases))
	mux.HandleFunc(base+"panel/api/server/", app.requireAuthCSRF(app.handleServerAPI))
	mux.HandleFunc(base+"panel/setting/defaultSettings", app.requireAuthCSRF(app.handleDefaultSettings))
	mux.HandleFunc(base+"panel/setting/all", app.requireAuthCSRF(app.handleSettingAll))
	mux.HandleFunc(base+"panel/setting/update", app.requireAuthCSRF(app.handleSettingUpdate))
	mux.HandleFunc(base+"panel/setting/ssh-port", app.requireAuthCSRF(app.handleSettingSSHPort))
	mux.HandleFunc(base+"panel/setting/updateUser", app.requireAuthCSRF(app.handleSettingUpdateUser))
	mux.HandleFunc(base+"panel/setting/restartPanel", app.requireAuthCSRF(app.handleSettingRestartPanel))
	mux.HandleFunc(base+"panel/api/custom-geo/list", app.requireAuthCSRF(app.handleCustomGeoList))

	// API (auth required)
	api := base + "panel/api/"
	mux.HandleFunc(api+"nodes", app.requireAuthCSRF(app.handleNodes))
	mux.HandleFunc(api+"api-keys", app.requireAuthCSRF(app.handleAPIKeys))
	mux.HandleFunc(api+"protocols", app.requireAuthCSRF(app.handleProtocols))
	mux.HandleFunc(api+"protocol-route-options", app.requireAuthCSRF(app.handleProtocolRouteOptions))
	mux.HandleFunc(api+"status", app.requireAuthCSRF(app.handleStatus))
	mux.HandleFunc(api+"inbound", app.requireAuthCSRF(app.handleInboundGet))
	mux.HandleFunc(api+"inbound/save", app.requireAuthCSRF(app.handleInboundSave))
	mux.HandleFunc(api+"firewall/ports", app.requireAuthCSRF(app.handleFirewallPortsList))
	mux.HandleFunc(api+"firewall/open", app.requireAuthCSRF(app.handleFirewallPortOpen))
	mux.HandleFunc(api+"firewall/update", app.requireAuthCSRF(app.handleFirewallPortUpdate))
	mux.HandleFunc(api+"firewall/close", app.requireAuthCSRF(app.handleFirewallPortClose))
	mux.HandleFunc(api+"firewall/ufw-enable", app.requireAuthCSRF(app.handleFirewallUFWEnable))
	mux.HandleFunc(api+"certs/list", app.requireAuthCSRF(app.handleCertsList))
	mux.HandleFunc(api+"certs/issue", app.requireAuthCSRF(app.handleCertsIssue))
	mux.HandleFunc(api+"certs/issue-ip", app.requireAuthCSRF(app.handleCertsIssueIP))
	mux.HandleFunc(api+"certs/renew", app.requireAuthCSRF(app.handleCertsRenew))
	mux.HandleFunc(api+"certs/acme-log", app.requireAuthCSRF(app.handleCertsAcmeLog))
	mux.HandleFunc(api+"certs/renew-dtls", app.requireAuthCSRF(app.handleCertsRenewDtls))
	mux.HandleFunc(api+"certs/revoke", app.requireAuthCSRF(app.handleCertsRevoke))
	mux.HandleFunc(api+"certs/delete-certbot", app.requireAuthCSRF(app.handleCertsDeleteCertbot))
	mux.HandleFunc(api+"certs/apply", app.requireAuthCSRF(app.handleCertsApply))
	mux.HandleFunc(api+"certs/install-acme", app.requireAuthCSRF(app.handleCertsInstallAcme))
	mux.HandleFunc(api+"certs/acme-cron", app.requireAuthCSRF(app.handleCertsAcmeCron))
	mux.HandleFunc(api+"xray-inbounds", app.requireAuthCSRF(app.handleXrayInboundsList))
	mux.HandleFunc(api+"xray-inbounds/save", app.requireAuthCSRF(app.handleXrayInboundSave))
	mux.HandleFunc(api+"xray-inbounds/delete", app.requireAuthCSRF(app.handleXrayInboundDelete))
	mux.HandleFunc(api+"users", app.requireAuthCSRF(app.handleUsersList))
	mux.HandleFunc(api+"users/add", app.requireAuthCSRF(app.handleUserAdd))
	mux.HandleFunc(api+"users/update", app.requireAuthCSRF(app.handleUserUpdate))
	mux.HandleFunc(api+"users/reset-traffic", app.requireAuthCSRF(app.handleUserResetTraffic))
	mux.HandleFunc(api+"users/delete", app.requireAuthCSRF(app.handleUserDelete))
	mux.HandleFunc(api+"password/main", app.requireAuthCSRF(app.handleMainPassword))
	mux.HandleFunc(api+"password/panel", app.requireAuthCSRF(app.handlePanelPassword))
	mux.HandleFunc(api+"xray/versions", app.requireAuthCSRF(app.handleXrayVersions))
	mux.HandleFunc(api+"xray/install/", app.requireAuthCSRF(app.handleXrayInstall))
	mux.HandleFunc(api+"xray/geofiles/", app.requireAuthCSRF(app.handleXrayGeofiles))
	mux.HandleFunc(api+"xray/config", app.requireAuthCSRF(app.handleXrayConfig))
	mux.HandleFunc(api+"logs", app.requireAuthCSRF(app.handleLogs))
	mux.HandleFunc(api+"vk/status", app.requireAuthCSRF(app.handleVKCreatorStatus))
	mux.HandleFunc(api+"vk/cookies", app.requireAuthCSRF(app.handleVKCreatorSaveCookies))
	mux.HandleFunc(api+"vk/cookies/clear", app.requireAuthCSRF(app.handleVKCreatorClearCookies))
	mux.HandleFunc(api+"vk/cookies/template", app.requireAuthCSRF(app.handleVKCreatorExportCookiesTemplate))
	mux.HandleFunc(api+"vk/call/create", app.requireAuthCSRF(app.handleVKCreatorCreateCall))
	mux.HandleFunc(api+"vk/call/stop", app.requireAuthCSRF(app.handleVKCreatorStopCall))
	mux.HandleFunc(api+"vk/auth/status", app.requireAuthCSRF(app.handleVKAuthStatus))
	mux.HandleFunc(api+"vk/auth/login", app.requireAuthCSRF(app.handleVKAuthLogin))
	mux.HandleFunc(api+"vk/auth/save", app.requireAuthCSRF(app.handleVKAuthSave))
	mux.HandleFunc(api+"vk/auth/clear", app.requireAuthCSRF(app.handleVKAuthClear))
	mux.HandleFunc(base+"panel/vk/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, base+"panel/vk/login/", http.StatusFound)
	})
	mux.HandleFunc(base+"panel/vk/login/", app.handleVKLoginProxy)
	registerVKLoginAssetFallbacks(mux, app)

	return startPanelServer(cfg, gzipMiddleware(mux))
}

func (a *App) serveLogin(w http.ResponseWriter, r *http.Request) {
	if a.parseSession(r) != nil {
		http.Redirect(w, r, a.cfg.basePath()+"panel/", http.StatusFound)
		return
	}
	a.renderHTML(w, r, "login.html", "pages.login.title", nil)
}

func (a *App) serveDashboard(w http.ResponseWriter, r *http.Request) {
	if a.parseSession(r) == nil {
		http.Redirect(w, r, a.cfg.basePath(), http.StatusFound)
		return
	}
	if r.URL.Path != a.cfg.basePath()+"panel/" && r.URL.Path != strings.TrimSuffix(a.cfg.basePath(), "/")+"panel/" {
		http.NotFound(w, r)
		return
	}
	a.renderHTML(w, r, "index.html", "pages.index.title", nil)
}

func (a *App) serveUsersPage(w http.ResponseWriter, r *http.Request) {
	if a.parseSession(r) == nil {
		http.Redirect(w, r, a.cfg.basePath(), http.StatusFound)
		return
	}
	a.renderHTML(w, r, "users.html", "Пользователи", nil)
}

func (a *App) serveSettingsPage(w http.ResponseWriter, r *http.Request) {
	if a.parseSession(r) == nil {
		http.Redirect(w, r, a.cfg.basePath(), http.StatusFound)
		return
	}
	a.renderHTML(w, r, "settings.html", "pages.settings.title", nil)
}
