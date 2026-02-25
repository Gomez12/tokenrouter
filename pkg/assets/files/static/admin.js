function adminApp() {
  return {
    activeTab: 'status',
    stats: {},
    appVersion: '',
    providers: [],
    conversationThreads: [],
    conversationRecords: [],
    selectedConversationKey: '',
    conversationsSettings: {enabled:true, max_items:5000, max_age_days:30},
    conversationsSaveInProgress: false,
    conversationsStatusHtml: '',
    showConversationsSettingsModal: false,
    conversationsSearch: '',
    conversationsListHtml: '',
    conversationsPagerHtml: '',
    conversationDetailHtml: '<div class="small text-body-secondary">Select a conversation to inspect chat flow.</div>',
    conversationsDebounceTimer: null,
    logEntries: [],
    logEntriesHtml: '',
    logEntriesShownCount: 0,
    logEntriesTotalCount: 0,
    logLevelFilter: 'all',
    logSearch: '',
    logDebounceTimer: null,
    logMaxLines: 5000,
    logSaveInProgress: false,
    logStatusHtml: '',
    popularProviders: [],
    modelsCatalog: [],
    allowLocalhostNoAuth: false,
    allowHostDockerInternalNoAuth: false,
    autoEnablePublicFreeModels: false,
    securitySaveInProgress: false,
    tlsSettings: {enabled:false, domain:'', email:'', cache_dir:''},
    tlsSaveInProgress: false,
    tlsActionInProgress: false,
    statsSummaryHtml: '',
    quotaSummaryHtml: '',
    statsRangeHours: '8',
    statusUpdateSpeed: 'realtime',
    usageChartGroupBy: 'model',
    usageChart: null,
    providersTableHtml: '',
    accessTokensTableHtml: '',
    modelsTableHtml: '',
    modelsFreshnessHtml: '',
    statusHtml: '',
    accessTokenStatusHtml: '',
    modalStatusHtml: '',
    deviceCodeFetchInProgress: false,
    deviceTokenPollInProgress: false,
    oauthLoginInProgress: false,
    oauthPollState: '',
    showAddProviderModal: false,
    addProviderStep: 'pick_provider',
    selectedPreset: '',
    presetInfoHtml: '',
    overrideProviderSettings: false,
    authMode: 'api_key',
    providerSearch: '',
    modelsSearch: '',
    modelsSortBy: 'provider',
    modelsSortAsc: true,
    modelsFreeOnly: false,
    providersPage: 1,
    providersPageSize: 25,
    modelsPage: 1,
    modelsPageSize: 25,
    conversationsPage: 1,
    conversationsPageSize: 25,
    logsPage: 1,
    logsPageSize: 25,
    modelsRefreshInProgress: false,
    modelsInitialized: false,
    modelsInitialLoadInProgress: false,
    quotaRefreshInProgress: false,
    editingProviderName: '',
    runtimeInstanceID: '',
    reloadingForRuntimeUpdate: false,
    themeMode: 'auto',
    activeTabCacheKey: 'opp_admin_active_tab_v1',
    modelsCacheKey: 'opp_models_catalog_cache_v1',
    modelsFreeOnlyCacheKey: 'opp_models_free_only_v1',
    themeCacheKey: 'opp_theme_mode_v1',
    usageChartGroupCacheKey: 'opp_usage_chart_group_v1',
    statsRangeCacheKey: 'opp_stats_range_hours_v1',
    statusUpdateSpeedCacheKey: 'opp_status_update_speed_v1',
    accessTokens: [],
    requiresInitialTokenSetup: false,
    showAddAccessTokenModal: false,
    accessTokenDraft: {id:'', name:'', key:'', role:'inferrer', expiry_preset:'never', expires_at:'', quota_enabled:false, quota_requests_limit:'', quota_requests_interval_seconds:'0', quota_tokens_limit:'', quota_tokens_interval_seconds:'0'},
    ws: null,
    wsReconnectTimer: null,
    wsBackoffMs: 1000,
    fallbackPoller: null,
    intervalPoller: null,
    draft: {name:'',provider_type:'',base_url:'',api_key:'',auth_token:'',refresh_token:'',token_expires_at:'',account_id:'',device_auth_url:'',device_code:'',device_auth_id:'',device_code_url:'',device_token_url:'',device_client_id:'',device_scope:'',device_grant_type:'',oauth_authorize_url:'',oauth_token_url:'',oauth_client_id:'',oauth_client_secret:'',oauth_scope:'',enabled:true,timeout_seconds:60},
    oauthAdvanced: false,
    init() {
      window.__adminSortModels = (col) => this.sortModelsBy(col);
      window.__adminProvidersFirstPage = () => this.setProvidersPage(1);
      window.__adminProvidersPrevPage = () => this.setProvidersPage(this.providersPage - 1);
      window.__adminProvidersNextPage = () => this.setProvidersPage(this.providersPage + 1);
      window.__adminProvidersLastPage = () => this.setProvidersPage(Number.MAX_SAFE_INTEGER);
      window.__adminSetProvidersPage = (v) => this.setProvidersPage(v);
      window.__adminSetProvidersPageSize = (v) => this.setProvidersPageSize(v);
      window.__adminModelsFirstPage = () => this.setModelsPage(1);
      window.__adminModelsPrevPage = () => this.setModelsPage(this.modelsPage - 1);
      window.__adminModelsNextPage = () => this.setModelsPage(this.modelsPage + 1);
      window.__adminModelsLastPage = () => this.setModelsPage(Number.MAX_SAFE_INTEGER);
      window.__adminSetModelsPage = (v) => this.setModelsPage(v);
      window.__adminSetModelsPageSize = (v) => this.setModelsPageSize(v);
      window.__adminConversationsFirstPage = () => this.setConversationsPage(1);
      window.__adminConversationsPrevPage = () => this.setConversationsPage(this.conversationsPage - 1);
      window.__adminConversationsNextPage = () => this.setConversationsPage(this.conversationsPage + 1);
      window.__adminConversationsLastPage = () => this.setConversationsPage(Number.MAX_SAFE_INTEGER);
      window.__adminSetConversationsPage = (v) => this.setConversationsPage(v);
      window.__adminSetConversationsPageSize = (v) => this.setConversationsPageSize(v);
      window.__adminLogsFirstPage = () => this.setLogsPage(1);
      window.__adminLogsPrevPage = () => this.setLogsPage(this.logsPage - 1);
      window.__adminLogsNextPage = () => this.setLogsPage(this.logsPage + 1);
      window.__adminLogsLastPage = () => this.setLogsPage(Number.MAX_SAFE_INTEGER);
      window.__adminSetLogsPage = (v) => this.setLogsPage(v);
      window.__adminSetLogsPageSize = (v) => this.setLogsPageSize(v);
      window.__adminSetUsageChartGroup = (v) => this.setUsageChartGroup(v);
      this.hydrateModelsFromCache();
      this.restoreModelsFreeOnly();
      this.restoreThemeMode();
      this.restoreUsageChartGroup();
      this.restoreStatsRangeHours();
      this.restoreStatusUpdateSpeed();
      this.restoreActiveTab();
      this.loadStats(false);
      this.loadProviders();
      this.loadAccessTokens();
      this.loadPopularProviders();
      this.loadSecuritySettings();
      this.loadTLSSettings();
      this.loadVersion();
      this.startRealtimeUpdates();
      if (window.matchMedia) {
        const media = window.matchMedia('(prefers-color-scheme: dark)');
        if (media && media.addEventListener) {
          media.addEventListener('change', () => {
            if (this.themeMode === 'auto') this.applyThemeMode();
          });
        }
      }
    },
    startRealtimeUpdates() {
      this.configureStatusUpdates();
      window.addEventListener('beforeunload', () => this.stopRealtimeUpdates());
    },
    stopRealtimeUpdates() {
      if (this.wsReconnectTimer) {
        clearTimeout(this.wsReconnectTimer);
        this.wsReconnectTimer = null;
      }
      if (this.fallbackPoller) {
        clearInterval(this.fallbackPoller);
        this.fallbackPoller = null;
      }
      if (this.intervalPoller) {
        clearInterval(this.intervalPoller);
        this.intervalPoller = null;
      }
      if (this.ws) {
        try { this.ws.close(); } catch (_) {}
        this.ws = null;
      }
    },
    isStatusRealtimeMode() {
      return this.statusUpdateSpeed === 'realtime';
    },
    statusUpdateIntervalMs() {
      const v = String(this.statusUpdateSpeed || '').trim();
      if (v === '2s') return 2000;
      if (v === '10s') return 10000;
      if (v === '30s') return 30000;
      if (v === '1m') return 60 * 1000;
      if (v === '5m') return 5 * 60 * 1000;
      if (v === '15m') return 15 * 60 * 1000;
      if (v === 'disabled') return -1;
      return 0;
    },
    configureStatusUpdates() {
      if (this.intervalPoller) {
        clearInterval(this.intervalPoller);
        this.intervalPoller = null;
      }
      this.clearFallbackPolling();
      const intervalMs = this.statusUpdateIntervalMs();
      if (intervalMs < 0) {
        if (this.wsReconnectTimer) {
          clearTimeout(this.wsReconnectTimer);
          this.wsReconnectTimer = null;
        }
        if (this.ws) {
          try { this.ws.close(); } catch (_) {}
          this.ws = null;
        }
        return;
      }
      if (this.isStatusRealtimeMode()) {
        this.connectRealtimeWebSocket();
        this.handleRealtimeRefresh(true);
        return;
      }
      if (this.ws) {
        try { this.ws.close(); } catch (_) {}
        this.ws = null;
      }
      if (this.wsReconnectTimer) {
        clearTimeout(this.wsReconnectTimer);
        this.wsReconnectTimer = null;
      }
      this.intervalPoller = setInterval(() => this.handleRealtimeRefresh(false), intervalMs);
      this.handleRealtimeRefresh(true);
    },
    ensureFallbackPolling() {
      if (!this.isStatusRealtimeMode()) return;
      if (this.fallbackPoller) return;
      this.fallbackPoller = setInterval(() => this.handleRealtimeRefresh(), 5000);
    },
    clearFallbackPolling() {
      if (!this.fallbackPoller) return;
      clearInterval(this.fallbackPoller);
      this.fallbackPoller = null;
    },
    scheduleRealtimeReconnect() {
      if (!this.isStatusRealtimeMode()) return;
      if (this.wsReconnectTimer) return;
      const delay = Math.min(this.wsBackoffMs, 30000);
      this.wsReconnectTimer = setTimeout(() => {
        this.wsReconnectTimer = null;
        this.connectRealtimeWebSocket();
      }, delay);
      this.wsBackoffMs = Math.min(this.wsBackoffMs * 2, 30000);
    },
    connectRealtimeWebSocket() {
      if (!this.isStatusRealtimeMode()) return;
      if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;
      const wsProto = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
      const wsURL = wsProto + window.location.host + '/admin/ws';
      try {
        const ws = new WebSocket(wsURL);
        this.ws = ws;
        ws.onopen = () => {
          this.wsBackoffMs = 1000;
          this.clearFallbackPolling();
          this.handleRealtimeRefresh(true);
        };
        ws.onmessage = (ev) => {
          let msg = null;
          try { msg = JSON.parse(String(ev.data || '{}')); } catch (_) {}
          if (!msg || !msg.type) return;
          if (msg.type === 'refresh') {
            this.handleRealtimeRefresh(true);
            return;
          }
          if (msg.type === 'conversation_append' && this.activeTab === 'conversations') {
            this.loadConversations(false);
          }
        };
        ws.onerror = () => {
          this.ensureFallbackPolling();
        };
        ws.onclose = () => {
          this.ensureFallbackPolling();
          this.scheduleRealtimeReconnect();
        };
      } catch (_) {
        this.ensureFallbackPolling();
        this.scheduleRealtimeReconnect();
      }
    },
    handleRealtimeRefresh(forceStats) {
      if (this.activeTab === 'status' || this.activeTab === 'quota' || this.activeTab === 'access') {
        this.loadStats(!!forceStats);
      }
      if (this.activeTab === 'providers') {
        this.loadProviders();
      } else if (this.activeTab === 'access') {
        this.loadAccessTokens();
        this.loadSecuritySettings();
        this.loadTLSSettings();
      } else if (this.activeTab === 'models') {
        this.loadModelsCatalog(false);
      } else if (this.activeTab === 'conversations') {
        this.loadConversations(false);
      } else if (this.activeTab === 'log') {
        this.loadLogs();
      }
    },
    headers() { return {'Content-Type':'application/json'}; },
    async apiFetch(url, opts) {
      const r = await fetch(url, opts);
      this.observeRuntimeInstance(r);
      return r;
    },
    observeRuntimeInstance(response) {
      if (!response || !response.headers) return;
      const nextID = String(response.headers.get('X-OPP-Instance-ID') || '').trim();
      if (!nextID) return;
      if (!this.runtimeInstanceID) {
        this.runtimeInstanceID = nextID;
        return;
      }
      if (this.runtimeInstanceID !== nextID && !this.reloadingForRuntimeUpdate) {
        this.runtimeInstanceID = nextID;
        this.reloadForRuntimeUpdate();
      }
    },
    reloadForRuntimeUpdate() {
      if (this.reloadingForRuntimeUpdate) return;
      this.reloadingForRuntimeUpdate = true;
      window.location.reload();
    },
    selectTab(tab) {
      this.activeTab = tab;
      this.persistActiveTab();
      if (tab === 'models' && !this.modelsInitialized) {
        this.loadModelsCatalog(true);
      } else if (tab === 'quota') {
        this.loadStats(false);
      } else if (tab === 'providers') {
        this.loadProviders();
      } else if (tab === 'access') {
        this.loadAccessTokens();
        this.loadSecuritySettings();
        this.loadTLSSettings();
      } else if (tab === 'conversations') {
        this.loadConversationsSettings();
        this.loadConversations(true);
      } else if (tab === 'log') {
        this.loadLogSettings();
        this.loadLogs();
      }
    },
    restoreActiveTab() {
      try {
        const tab = window.localStorage.getItem(this.activeTabCacheKey);
        if (tab === 'status' || tab === 'conversations' || tab === 'log' || tab === 'quota' || tab === 'providers' || tab === 'access' || tab === 'models') {
          this.activeTab = tab;
        }
      } catch (_) {}
      if (this.activeTab === 'models' && !this.modelsInitialized) {
        this.loadModelsCatalog(true);
      } else if (this.activeTab === 'quota') {
        this.loadStats(false);
      } else if (this.activeTab === 'conversations') {
        this.loadConversationsSettings();
        this.loadConversations(true);
      } else if (this.activeTab === 'log') {
        this.loadLogSettings();
        this.loadLogs();
      }
    },
    persistActiveTab() {
      try {
        window.localStorage.setItem(this.activeTabCacheKey, this.activeTab);
      } catch (_) {}
    },
    restoreThemeMode() {
      try {
        const v = window.localStorage.getItem(this.themeCacheKey);
        if (v === 'auto' || v === 'light' || v === 'dark') this.themeMode = v;
      } catch (_) {}
      this.applyThemeMode();
    },
    persistThemeMode() {
      try {
        window.localStorage.setItem(this.themeCacheKey, this.themeMode);
      } catch (_) {}
    },
    restoreUsageChartGroup() {
      try {
        const v = String(window.localStorage.getItem(this.usageChartGroupCacheKey) || '').trim();
        if (v === 'model' || v === 'provider' || v === 'api_key_name' || v === 'client_ip' || v === 'user_agent') {
          this.usageChartGroupBy = v;
        }
      } catch (_) {}
    },
    persistUsageChartGroup() {
      try {
        window.localStorage.setItem(this.usageChartGroupCacheKey, this.usageChartGroupBy);
      } catch (_) {}
    },
    restoreStatusUpdateSpeed() {
      try {
        const raw = String(window.localStorage.getItem(this.statusUpdateSpeedCacheKey) || '').trim();
        if (raw === 'realtime' || raw === '2s' || raw === '10s' || raw === '30s' || raw === '1m' || raw === '5m' || raw === '15m' || raw === 'disabled') {
          this.statusUpdateSpeed = raw;
        }
      } catch (_) {}
    },
    persistStatusUpdateSpeed() {
      try {
        window.localStorage.setItem(this.statusUpdateSpeedCacheKey, String(this.statusUpdateSpeed || 'realtime'));
      } catch (_) {}
    },
    setStatusUpdateSpeed(v) {
      const raw = String(v || '').trim();
      if (raw !== 'realtime' && raw !== '2s' && raw !== '10s' && raw !== '30s' && raw !== '1m' && raw !== '5m' && raw !== '15m' && raw !== 'disabled') return;
      this.statusUpdateSpeed = raw;
      this.persistStatusUpdateSpeed();
      this.configureStatusUpdates();
    },
    restoreStatsRangeHours() {
      try {
        const raw = String(window.localStorage.getItem(this.statsRangeCacheKey) || '').trim();
        if (raw === '1' || raw === '4' || raw === '8' || raw === '24' || raw === '72') {
          this.statsRangeHours = raw;
        }
      } catch (_) {}
    },
    persistStatsRangeHours() {
      try {
        window.localStorage.setItem(this.statsRangeCacheKey, String(this.statsRangeHours || '8'));
      } catch (_) {}
    },
    setStatsRangeHours(v) {
      const raw = String(v || '').trim();
      if (raw !== '1' && raw !== '4' && raw !== '8' && raw !== '24' && raw !== '72') return;
      this.statsRangeHours = raw;
      this.persistStatsRangeHours();
      this.loadStats(true);
    },
    resolvedThemeMode() {
      if (this.themeMode === 'auto') {
        try {
          return (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
        } catch (_) {
          return 'light';
        }
      }
      return this.themeMode;
    },
    applyThemeMode() {
      const resolved = this.resolvedThemeMode();
      document.documentElement.setAttribute('data-bs-theme', resolved);
    },
    themeButtonLabel() {
      if (this.themeMode === 'light') return 'Theme: Light';
      if (this.themeMode === 'dark') return 'Theme: Dark';
      return 'Theme: Auto';
    },
    themeButtonIcon() {
      if (this.themeMode === 'light') {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 1a.5.5 0 0 1 .5.5V3a.5.5 0 0 1-1 0V1.5A.5.5 0 0 1 8 1Zm0 10.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm0 3.5a.5.5 0 0 1-.5-.5V13a.5.5 0 0 1 1 0v1.5a.5.5 0 0 1-.5.5ZM2.343 3.757a.5.5 0 0 1 .707 0l1.06 1.06a.5.5 0 1 1-.707.708l-1.06-1.061a.5.5 0 0 1 0-.707Zm9.547 9.546a.5.5 0 0 1 .707 0l1.06 1.061a.5.5 0 0 1-.707.707l-1.06-1.06a.5.5 0 0 1 0-.708ZM1 8a.5.5 0 0 1 .5-.5H3a.5.5 0 0 1 0 1H1.5A.5.5 0 0 1 1 8Zm10.5 0a.5.5 0 0 1 .5-.5H13.5a.5.5 0 0 1 0 1H12a.5.5 0 0 1-.5-.5ZM2.343 12.243a.5.5 0 0 1 0 .707l-1.06 1.06a.5.5 0 0 1-.707-.707l1.06-1.06a.5.5 0 0 1 .707 0Zm9.547-9.546a.5.5 0 0 1 0 .707l-1.06 1.061a.5.5 0 0 1-.707-.708l1.06-1.06a.5.5 0 0 1 .707 0Z"/></svg>';
      }
      if (this.themeMode === 'dark') {
        return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M6 0a.75.75 0 0 1 .73.96 6.5 6.5 0 0 0 8.31 8.31.75.75 0 0 1 .96.73A7.5 7.5 0 1 1 6 0Z"/></svg>';
      }
      return '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 16 16"><path d="M8 1.5a.5.5 0 0 1 .5.5V3a.5.5 0 0 1-1 0V2a.5.5 0 0 1 .5-.5Zm0 11a.5.5 0 0 1 .5.5V14a.5.5 0 0 1-1 0v-1a.5.5 0 0 1 .5-.5ZM3 7.5a.5.5 0 0 1 0 1H2a.5.5 0 0 1 0-1h1Zm11 0a.5.5 0 0 1 0 1h-1a.5.5 0 0 1 0-1h1Zm-8.657-4.95a.5.5 0 0 1 .707 0l.707.707a.5.5 0 0 1-.707.707l-.707-.707a.5.5 0 0 1 0-.707Zm5.657 5.657a.5.5 0 0 1 .707 0l.707.707a.5.5 0 0 1-.707.707l-.707-.707a.5.5 0 0 1 0-.707ZM3.257 9.864a.5.5 0 0 1 .707 0l.707.707a.5.5 0 1 1-.707.707l-.707-.707a.5.5 0 0 1 0-.707Zm8.486-8.486a.5.5 0 0 1 .707 0l.707.707a.5.5 0 0 1-.707.707l-.707-.707a.5.5 0 0 1 0-.707ZM8 4.5a3.5 3.5 0 0 0 0 7 .5.5 0 0 0 0-1 2.5 2.5 0 1 1 0-5 .5.5 0 0 0 0-1Z"/></svg>';
    },
    cycleTheme() {
      if (this.themeMode === 'auto') this.themeMode = 'light';
      else if (this.themeMode === 'light') this.themeMode = 'dark';
      else this.themeMode = 'auto';
      this.persistThemeMode();
      this.applyThemeMode();
    },
    hydrateModelsFromCache() {
      try {
        const raw = window.localStorage.getItem(this.modelsCacheKey);
        if (!raw) return;
        const parsed = JSON.parse(raw);
        if (!Array.isArray(parsed)) return;
        this.modelsCatalog = parsed;
        this.modelsInitialized = parsed.length > 0;
        this.renderModelsCatalog();
      } catch (_) {}
    },
    persistModelsToCache() {
      try {
        window.localStorage.setItem(this.modelsCacheKey, JSON.stringify(this.modelsCatalog || []));
      } catch (_) {}
    },
    restoreModelsFreeOnly() {
      try {
        const raw = String(window.localStorage.getItem(this.modelsFreeOnlyCacheKey) || '').trim().toLowerCase();
        this.modelsFreeOnly = raw === '1' || raw === 'true';
      } catch (_) {}
    },
    persistModelsFreeOnly() {
      try {
        window.localStorage.setItem(this.modelsFreeOnlyCacheKey, this.modelsFreeOnly ? '1' : '0');
      } catch (_) {}
    },
    escapeHtml(v) {
      return String(v || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
    },
    providerIconSrc(name) {
      const raw = String(name || '').trim();
      if (!raw) {
        return 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==';
      }
      const id = raw.replace(/\.svg$/i, '').toLowerCase();
      return '/admin/static/' + encodeURIComponent(id) + '.svg';
    },
    providerIconID(name) {
      return String(name || '').trim().replace(/\.svg$/i, '').toLowerCase();
    },
    providerIconNeedsDarkInvert(name) {
      const id = this.providerIconID(name);
      const mono = new Set([
        'anthropic',
        'baseten',
        'cortecs',
        'deepinfra',
        'deepseek',
        'github-copilot',
        'helicone',
        'io-net',
        'lmstudio',
        'moonshotai',
        'nebius',
        'ollama-cloud',
        'venice',
        'vercel-ai-gateway',
        'xai',
        'zai',
        'zenmux'
      ]);
      return mono.has(id);
    },
    providerIconError(event) {
      const img = event && event.target ? event.target : null;
      if (!img) return;
      img.onerror = null;
      img.src = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==';
    },
    formatPrice(v, currency) {
      if (v === undefined || v === null || Number.isNaN(Number(v))) return '-';
      const n = Number(v);
      const c = String(currency || '').trim().toUpperCase();
      if (!c || c === 'USD') return '$' + n.toFixed(2);
      return c + ' ' + n.toFixed(2);
    },
    formatAge(checkedAt) {
      if (!checkedAt) return '';
      const t = new Date(checkedAt);
      if (Number.isNaN(t.getTime())) return '';
      const sec = Math.max(0, Math.floor((Date.now() - t.getTime()) / 1000));
      if (sec < 60) return sec + 's ago';
      const min = Math.floor(sec / 60);
      const rem = sec % 60;
      if (min < 60) return min + 'm ' + rem + 's ago';
      const hr = Math.floor(min / 60);
      const remMin = min % 60;
      return hr + 'h ' + remMin + 'm ago';
    },
    formatUntil(targetAt) {
      if (!targetAt) return '';
      const t = new Date(targetAt);
      if (Number.isNaN(t.getTime())) return '';
      let sec = Math.floor((t.getTime() - Date.now()) / 1000);
      if (sec <= 0) return 'in <1m';
      const day = 24 * 60 * 60;
      const hour = 60 * 60;
      const minute = 60;
      const days = Math.floor(sec / day);
      sec -= days * day;
      const hours = Math.floor(sec / hour);
      sec -= hours * hour;
      const mins = Math.floor(sec / minute);
      if (days > 0) {
        if (hours > 0) return 'in ' + days + 'd ' + hours + 'h';
        return 'in ' + days + 'd';
      }
      if (hours > 0) {
        if (mins > 0) return 'in ' + hours + 'h ' + mins + 'm';
        return 'in ' + hours + 'h';
      }
      if (mins > 0) return 'in ' + mins + 'm';
      return 'in ' + sec + 's';
    },
    parsePageSize(v) {
      const raw = String(v ?? '').trim().toLowerCase();
      if (raw === 'all' || raw === '0') return 0;
      const n = Number(raw);
      if (n === 25 || n === 50 || n === 100) return n;
      return 25;
    },
    paginateRows(allRows, page, pageSize) {
      const totalRows = (allRows || []).length;
      const size = this.parsePageSize(pageSize);
      if (size === 0) {
        return {
          rows: allRows || [],
          totalRows,
          totalPages: 1,
          page: 1,
          pageSize: 0
        };
      }
      const totalPages = Math.max(1, Math.ceil(totalRows / size));
      let currentPage = Number(page || 1);
      if (!Number.isFinite(currentPage)) currentPage = 1;
      currentPage = Math.min(totalPages, Math.max(1, Math.floor(currentPage)));
      const start = (currentPage - 1) * size;
      const end = start + size;
      return {
        rows: (allRows || []).slice(start, end),
        totalRows,
        totalPages,
        page: currentPage,
        pageSize: size
      };
    },
    setProvidersPage(v) {
      let n = Number(v);
      if (!Number.isFinite(n)) n = 1;
      this.providersPage = Math.max(1, Math.floor(n));
      this.renderProviders();
    },
    setProvidersPageSize(v) {
      this.providersPageSize = this.parsePageSize(v);
      this.providersPage = 1;
      this.renderProviders();
    },
    setModelsPage(v) {
      let n = Number(v);
      if (!Number.isFinite(n)) n = 1;
      this.modelsPage = Math.max(1, Math.floor(n));
      this.renderModelsCatalog();
    },
    setModelsPageSize(v) {
      this.modelsPageSize = this.parsePageSize(v);
      this.modelsPage = 1;
      this.renderModelsCatalog();
    },
    setConversationsPage(v) {
      let n = Number(v);
      if (!Number.isFinite(n)) n = 1;
      this.conversationsPage = Math.max(1, Math.floor(n));
      this.renderConversationsList();
    },
    setConversationsPageSize(v) {
      this.conversationsPageSize = this.parsePageSize(v);
      this.conversationsPage = 1;
      this.renderConversationsList();
    },
    setLogsPage(v) {
      let n = Number(v);
      if (!Number.isFinite(n)) n = 1;
      this.logsPage = Math.max(1, Math.floor(n));
      this.renderLogs();
    },
    setLogsPageSize(v) {
      this.logsPageSize = this.parsePageSize(v);
      this.logsPage = 1;
      this.renderLogs();
    },
    setUsageChartGroup(v) {
      const key = String(v || '').trim();
      if (key !== 'model' && key !== 'provider' && key !== 'api_key_name' && key !== 'client_ip' && key !== 'user_agent') return;
      this.usageChartGroupBy = key;
      this.persistUsageChartGroup();
      this.renderStats();
    },
    renderPager(totalRows, page, totalPages, pageSize, key) {
      const disabledFirst = page <= 1 ? ' disabled' : '';
      const disabledLast = page >= totalPages ? ' disabled' : '';
      const sizeValue = pageSize === 0 ? 'all' : String(pageSize);
      const firstFn = '__admin' + key + 'FirstPage';
      const prevFn = '__admin' + key + 'PrevPage';
      const setPageFn = '__adminSet' + key + 'Page';
      const nextFn = '__admin' + key + 'NextPage';
      const lastFn = '__admin' + key + 'LastPage';
      const setPageSizeFn = '__adminSet' + key + 'PageSize';
      return '' +
        '<div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mt-2">' +
          '<div class="d-flex align-items-center gap-1">' +
            '<button class="icon-btn"' + disabledFirst + ' onclick="window.' + firstFn + '()" title="First page" aria-label="First page">&laquo;</button>' +
            '<button class="icon-btn"' + disabledFirst + ' onclick="window.' + prevFn + '()" title="Previous page" aria-label="Previous page">&lsaquo;</button>' +
            '<input class="form-control form-control-sm" type="number" min="1" max="' + totalPages + '" value="' + page + '" style="max-width:86px;" onchange="window.' + setPageFn + '(this.value)" />' +
            '<button class="icon-btn"' + disabledLast + ' onclick="window.' + nextFn + '()" title="Next page" aria-label="Next page">&rsaquo;</button>' +
            '<button class="icon-btn"' + disabledLast + ' onclick="window.' + lastFn + '()" title="Last page" aria-label="Last page">&raquo;</button>' +
          '</div>' +
          '<div class="d-flex align-items-center gap-2 small text-body-secondary">' +
            '<span>Page ' + page + ' of ' + totalPages + '</span>' +
            '<span>(' + totalRows + ' rows)</span>' +
            '<select class="form-select form-select-sm" style="width:auto;" onchange="window.' + setPageSizeFn + '(this.value)">' +
              '<option value="25"' + (sizeValue === '25' ? ' selected' : '') + '>25</option>' +
              '<option value="50"' + (sizeValue === '50' ? ' selected' : '') + '>50</option>' +
              '<option value="100"' + (sizeValue === '100' ? ' selected' : '') + '>100</option>' +
              '<option value="all"' + (sizeValue === 'all' ? ' selected' : '') + '>all</option>' +
            '</select>' +
          '</div>' +
        '</div>';
    },
    renderProvidersPager(totalRows, page, totalPages, pageSize) {
      return this.renderPager(totalRows, page, totalPages, pageSize, 'Providers');
    },
    renderModelsPager(totalRows, page, totalPages, pageSize) {
      return this.renderPager(totalRows, page, totalPages, pageSize, 'Models');
    },
    resetDraft() {
      this.cancelOAuthPolling();
      this.draft = {name:'',provider_type:'',base_url:'',api_key:'',auth_token:'',refresh_token:'',token_expires_at:'',account_id:'',device_auth_url:'',device_code:'',device_auth_id:'',device_code_url:'',device_token_url:'',device_client_id:'',device_scope:'',device_grant_type:'',oauth_authorize_url:'',oauth_token_url:'',oauth_client_id:'',oauth_client_secret:'',oauth_scope:'',enabled:true,timeout_seconds:''};
      this.addProviderStep = 'pick_provider';
      this.selectedPreset = '';
      this.presetInfoHtml = '';
      this.overrideProviderSettings = false;
      this.authMode = 'api_key';
      this.providerSearch = '';
      this.editingProviderName = '';
      this.modalStatusHtml = '';
      this.oauthAdvanced = false;
    },
    openAddProviderModal() {
      this.resetDraft();
      this.showAddProviderModal = true;
    },
    closeAddProviderModal() {
      this.cancelOAuthPolling();
      this.showAddProviderModal = false;
    },
    addProviderTitle() {
      if (this.addProviderStep === 'choose_auth') return 'Add Provider - Choose Authentication';
      if (this.addProviderStep === 'api_key') return 'Add Provider - API Key';
      if (this.addProviderStep === 'oauth_browser') return 'Add Provider - Browser OAuth';
      if (this.addProviderStep === 'device_auth') return 'Add Provider - Device Auth';
      return 'Add Provider';
    },
    getSelectedPreset() {
      return (this.popularProviders || []).find((p) => p.name === this.selectedPreset) || null;
    },
    selectedPresetDisplayName() {
      const preset = this.getSelectedPreset();
      return preset ? (preset.display_name || preset.name || '') : '';
    },
    selectedPresetGetKeyURL() {
      const preset = this.getSelectedPreset();
      return preset ? String(preset.get_api_key_url || '').trim() : '';
    },
    selectedPresetApiKeyOptional() {
      const preset = this.getSelectedPreset();
      return !!(preset && preset.public_free_no_auth);
    },
    selectedPresetBaseURLTemplate() {
      const preset = this.getSelectedPreset();
      return preset ? String(preset.base_url_template || '').trim() : '';
    },
    selectedPresetBaseURLHint() {
      const preset = this.getSelectedPreset();
      return preset ? String(preset.base_url_hint || '').trim() : '';
    },
    selectedPresetBaseURLExample() {
      const preset = this.getSelectedPreset();
      return preset ? String(preset.base_url_example || '').trim() : '';
    },
    filteredPopularProviders() {
      const all = (this.popularProviders || []).slice().sort((a, b) => {
        const ad = String((a && a.display_name) || (a && a.name) || '').toLowerCase();
        const bd = String((b && b.display_name) || (b && b.name) || '').toLowerCase();
        if (ad < bd) return -1;
        if (ad > bd) return 1;
        return 0;
      });
      const q = String(this.providerSearch || '').trim().toLowerCase();
      if (!q) return all;
      return all.filter((p) => {
        const name = String((p && p.name) || '').toLowerCase();
        const display = String((p && p.display_name) || '').toLowerCase();
        const docs = String((p && p.docs_url) || '').toLowerCase();
        return name.includes(q) || display.includes(q) || docs.includes(q);
      });
    },
    filteredPopularProvidersCount() {
      return this.filteredPopularProviders().length;
    },
    selectedPresetRequiresBaseURLInput() {
      return !!this.selectedPresetBaseURLTemplate();
    },
    presetSupportsDeviceAuth(preset) {
      return !!(preset && String(preset.device_binding_url || '').trim());
    },
    presetSupportsOAuthBrowser(preset) {
      if (!preset) return false;
      return !!(String(preset.oauth_authorize_url || '').trim() && String(preset.oauth_token_url || '').trim());
    },
    presetSupportsAPIKey(preset) {
      if (!preset) return true;
      if (String(preset.get_api_key_url || '').trim()) return true;
      if (String(preset.api_key_env || '').trim()) return true;
      if (preset.public_free_no_auth) return true;
      return false;
    },
    alternateAuthTitle() {
      const preset = this.getSelectedPreset();
      if (this.presetSupportsOAuthBrowser(preset)) {
        if (preset && String(preset.name || '').trim() === 'openai') return 'Use browser OAuth (ChatGPT/Codex)';
        return 'Use browser OAuth';
      }
      return 'Use OAuth / device auth';
    },
    alternateAuthDescription() {
      const preset = this.getSelectedPreset();
      if (this.presetSupportsOAuthBrowser(preset)) return 'Sign in via browser and auto-capture OAuth tokens.';
      return 'Open device binding, complete login, then save token.';
    },
    applySelectedPreset() {
      const preset = (this.popularProviders || []).find((p) => p.name === this.selectedPreset);
      if (!preset) {
        this.presetInfoHtml = '';
        return;
      }
      this.draft.name = preset.name || '';
      this.draft.provider_type = preset.name || '';
      this.draft.base_url = String(preset.base_url || '').trim();
      if (!this.draft.base_url && String(preset.base_url_template || '').trim()) {
        this.draft.base_url = String(preset.base_url_template || '').trim();
      }
      this.draft.enabled = true;
      this.draft.timeout_seconds = '';
      this.draft.api_key = '';
      this.draft.auth_token = '';
      this.draft.refresh_token = '';
      this.draft.token_expires_at = '';
      this.draft.account_id = '';
      this.draft.device_auth_url = preset.device_binding_url || '';
      this.draft.device_code = '';
      this.draft.device_auth_id = '';
      this.draft.device_code_url = preset.device_code_url || '';
      this.draft.device_token_url = preset.device_token_url || '';
      this.draft.device_client_id = preset.device_client_id || '';
      this.draft.device_scope = preset.device_scope || '';
      this.draft.device_grant_type = preset.device_grant_type || '';
      this.draft.oauth_authorize_url = preset.oauth_authorize_url || '';
      this.draft.oauth_token_url = preset.oauth_token_url || '';
      this.draft.oauth_client_id = preset.oauth_client_id || '';
      this.draft.oauth_client_secret = preset.oauth_client_secret || '';
      this.draft.oauth_scope = preset.oauth_scope || '';
      this.overrideProviderSettings = false;
      this.authMode = 'api_key';
      this.presetInfoHtml = this.renderPresetInfo(preset);
    },
    selectProviderPreset(name) {
      this.selectedPreset = String(name || '').trim();
      this.applySelectedPreset();
      const preset = this.getSelectedPreset();
      const hasDevice = this.presetSupportsDeviceAuth(preset);
      const hasOAuth = this.presetSupportsOAuthBrowser(preset);
      const hasAPI = this.presetSupportsAPIKey(preset);
      if ((hasDevice || hasOAuth) && hasAPI) {
        this.addProviderStep = 'choose_auth';
        return;
      }
      if (hasOAuth) {
        this.authMode = 'oauth';
        this.addProviderStep = 'oauth_browser';
        return;
      }
      if (hasDevice) {
        this.authMode = 'device';
        this.addProviderStep = 'device_auth';
        return;
      }
      this.authMode = 'api_key';
      this.addProviderStep = 'api_key';
    },
    chooseApiKeyAuth() {
      this.authMode = 'api_key';
      this.modalStatusHtml = '';
      this.addProviderStep = 'api_key';
    },
    chooseAlternateAuth() {
      const preset = this.getSelectedPreset();
      if (this.presetSupportsOAuthBrowser(preset)) {
        this.authMode = 'oauth';
        this.modalStatusHtml = '';
        this.addProviderStep = 'oauth_browser';
        this.draft.base_url = String(preset.oauth_base_url || '').trim() || String(preset.base_url || '').trim();
        return;
      }
      this.authMode = 'device';
      this.modalStatusHtml = '';
      this.addProviderStep = 'device_auth';
    },
    goBackFromChoice() {
      this.addProviderStep = 'pick_provider';
    },
    goBackFromForm() {
      const preset = this.getSelectedPreset();
      if ((this.presetSupportsDeviceAuth(preset) || this.presetSupportsOAuthBrowser(preset)) && this.presetSupportsAPIKey(preset)) {
        this.addProviderStep = 'choose_auth';
        return;
      }
      this.addProviderStep = 'pick_provider';
    },
    selectedPresetSupportsDeviceAuth() {
      return this.presetSupportsDeviceAuth(this.getSelectedPreset());
    },
    selectedPresetSupportsDeviceCodeFetch() {
      const preset = this.getSelectedPreset();
      if (preset && String(preset.device_code_url || '').trim()) return true;
      return !!String(this.draft.device_code_url || '').trim();
    },
    selectedPresetSupportsDeviceTokenPolling() {
      const tokenURL = String(this.draft.device_token_url || '').trim();
      const clientID = String(this.draft.device_client_id || '').trim();
      const deviceCode = String(this.draft.device_code || '').trim();
      return !!(tokenURL && clientID && deviceCode);
    },
    deviceCodeParamName() {
      const preset = this.getSelectedPreset();
      const raw = preset ? String(preset.device_code_param || '').trim() : '';
      if (raw) return raw;
      if (preset && preset.name === 'google-gemini') return 'user_code';
      return 'code';
    },
    deviceAuthURLWithCode() {
      const base = String(this.draft.device_auth_url || '').trim();
      const code = String(this.draft.device_code || '').trim();
      if (!base || !code) return '';
      try {
        const u = new URL(base);
        u.searchParams.set(this.deviceCodeParamName(), code);
        return u.toString();
      } catch (_) {
        return '';
      }
    },
    async copyDeviceCode() {
      const code = String(this.draft.device_code || '').trim();
      if (!code) return;
      try {
        await navigator.clipboard.writeText(code);
        this.modalStatusHtml = '<span class="text-success">Device code copied.</span>';
      } catch (_) {
        this.modalStatusHtml = '<span class="text-danger">Could not copy device code.</span>';
      }
    },
    openDeviceAuth(withCode) {
      const base = String(this.draft.device_auth_url || '').trim();
      if (!base) return;
      const target = withCode ? (this.deviceAuthURLWithCode() || base) : base;
      window.open(target, '_blank', 'noopener,noreferrer');
    },
    cancelOAuthPolling() {
      this.oauthLoginInProgress = false;
      this.oauthPollState = '';
    },
    async startOAuthBrowserLogin() {
      if (this.oauthLoginInProgress) return;
      const provider = String(this.selectedPreset || '').trim();
      if (!provider) return;
      this.oauthLoginInProgress = true;
      this.modalStatusHtml = '<span class="text-body-secondary">Starting browser OAuth flow...</span>';
      try {
        const startResp = await this.apiFetch('/admin/api/providers/oauth/start', {method:'POST', headers:this.headers(), body:JSON.stringify({
          provider,
          oauth_authorize_url: String(this.draft.oauth_authorize_url || '').trim(),
          oauth_token_url: String(this.draft.oauth_token_url || '').trim(),
          oauth_client_id: String(this.draft.oauth_client_id || '').trim(),
          oauth_client_secret: String(this.draft.oauth_client_secret || '').trim(),
          oauth_scope: String(this.draft.oauth_scope || '').trim()
        })});
        if (startResp.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        const startBody = await startResp.json().catch(() => ({}));
        if (!(startResp.ok && startBody.ok)) {
          this.modalStatusHtml = '<span class="text-danger">' + this.escapeHtml(startBody.error || 'Failed to start OAuth flow.') + '</span>';
          this.oauthLoginInProgress = false;
          return;
        }
        const state = String(startBody.state || '').trim();
        const authURL = String(startBody.auth_url || '').trim();
        if (!state || !authURL) {
          this.modalStatusHtml = '<span class="text-danger">OAuth start response was incomplete.</span>';
          this.oauthLoginInProgress = false;
          return;
        }
        this.oauthPollState = state;
        window.open(authURL, '_blank', 'noopener,noreferrer');
        this.modalStatusHtml = '<span class="text-body-secondary">Complete login in browser tab. Waiting for callback...</span>';
        for (let i = 0; i < 180; i++) {
          if (!this.oauthLoginInProgress || this.oauthPollState !== state) return;
          await new Promise((resolve) => setTimeout(resolve, 1000));
          const rr = await this.apiFetch('/admin/api/providers/oauth/result?state=' + encodeURIComponent(state), {headers:this.headers()});
          if (rr.status === 401) { window.location = '/admin/login?next=/admin'; return; }
          const rb = await rr.json().catch(() => ({}));
          if (rr.status === 404) {
            this.modalStatusHtml = '<span class="text-danger">OAuth session expired or not found. Retry.</span>';
            this.oauthLoginInProgress = false;
            return;
          }
          if (!(rr.ok && rb.ok)) {
            this.modalStatusHtml = '<span class="text-danger">' + this.escapeHtml(rb.error || 'OAuth flow failed.') + '</span>';
            this.oauthLoginInProgress = false;
            return;
          }
          if (rb.pending) continue;
          this.draft.auth_token = String(rb.auth_token || '').trim();
          this.draft.refresh_token = String(rb.refresh_token || '').trim();
          this.draft.token_expires_at = String(rb.token_expires_at || '').trim();
          this.draft.account_id = String(rb.account_id || '').trim();
          if (String(rb.base_url || '').trim()) this.draft.base_url = String(rb.base_url || '').trim();
          this.modalStatusHtml = '<span class="text-success">OAuth login completed. Token captured.</span>';
          this.oauthLoginInProgress = false;
          return;
        }
        this.modalStatusHtml = '<span class="text-danger">Timed out waiting for OAuth callback.</span>';
      } finally {
        this.oauthLoginInProgress = false;
      }
    },
    async fetchDeviceCode() {
      if (this.deviceCodeFetchInProgress) return;
      this.deviceCodeFetchInProgress = true;
      this.modalStatusHtml = '<span class="text-body-secondary">Requesting device code...</span>';
      try {
        const payload = {
          provider: String(this.selectedPreset || '').trim(),
          device_code_url: String(this.draft.device_code_url || '').trim(),
          client_id: String(this.draft.device_client_id || '').trim(),
          scope: String(this.draft.device_scope || '').trim()
        };
        const r = await this.apiFetch('/admin/api/providers/device-code', {method:'POST', headers:this.headers(), body:JSON.stringify(payload)});
        if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        const body = await r.json().catch(() => ({}));
        if (!(r.ok && body.ok)) {
          const err = this.escapeHtml(body.error || 'Failed to fetch device code.');
          this.modalStatusHtml = '<span class="text-danger">' + err + '</span>';
          return;
        }
        const userCode = String(body.user_code || '').trim();
        const deviceAuthID = String(body.device_auth_id || '').trim();
        const verificationComplete = String(body.verification_uri_complete || '').trim();
        const verificationURL = String(body.verification_uri || body.verification_url || '').trim();
        const expiresIn = Number(body.expires_in || 0);
        if (userCode) this.draft.device_code = userCode;
        if (deviceAuthID) this.draft.device_auth_id = deviceAuthID;
        if (verificationComplete) this.draft.device_auth_url = verificationComplete;
        else if (verificationURL) this.draft.device_auth_url = verificationURL;
        let msg = 'Device code fetched.';
        if (expiresIn > 0) msg += ' Expires in ' + expiresIn + 's.';
        this.modalStatusHtml = '<span class="text-success">' + this.escapeHtml(msg) + '</span>';
      } finally {
        this.deviceCodeFetchInProgress = false;
      }
    },
    async pollDeviceToken() {
      if (this.deviceTokenPollInProgress) return;
      const payload = {
        provider: String(this.selectedPreset || '').trim(),
        device_token_url: String(this.draft.device_token_url || '').trim(),
        client_id: String(this.draft.device_client_id || '').trim(),
        device_code: String(this.draft.device_code || '').trim(),
        device_auth_id: String(this.draft.device_auth_id || '').trim(),
        grant_type: String(this.draft.device_grant_type || '').trim() || 'urn:ietf:params:oauth:grant-type:device_code'
      };
      if (!payload.device_token_url || !payload.client_id || !payload.device_code) {
        this.modalStatusHtml = '<span class="text-danger">Device token URL, client_id, and device_code are required.</span>';
        return;
      }
      if (payload.provider === 'openai' && !payload.device_auth_id) {
        this.modalStatusHtml = '<span class="text-danger">OpenAI headless flow requires device_auth_id. Fetch device code first.</span>';
        return;
      }
      this.deviceTokenPollInProgress = true;
      this.modalStatusHtml = '<span class="text-body-secondary">Polling device auth token...</span>';
      try {
        for (let i = 0; i < 90; i++) {
          const r = await this.apiFetch('/admin/api/providers/device-token', {method:'POST', headers:this.headers(), body:JSON.stringify(payload)});
          if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
          const body = await r.json().catch(() => ({}));
          if (!(r.ok && body.ok)) {
            this.modalStatusHtml = '<span class="text-danger">' + this.escapeHtml(body.error || 'Device token exchange failed.') + '</span>';
            return;
          }
          if (!body.pending && String(body.auth_token || '').trim()) {
            this.draft.auth_token = String(body.auth_token || '').trim();
            this.draft.refresh_token = String(body.refresh_token || '').trim();
            this.draft.account_id = String(body.account_id || '').trim();
            if (Number(body.expires_in || 0) > 0) {
              const when = new Date(Date.now() + Number(body.expires_in) * 1000).toISOString();
              this.draft.token_expires_at = when;
            }
            this.modalStatusHtml = '<span class="text-success">Device auth token received.</span>';
            return;
          }
          const waitSec = Math.max(1, Number(body.interval || 5));
          await new Promise((resolve) => setTimeout(resolve, waitSec * 1000));
        }
        this.modalStatusHtml = '<span class="text-danger">Timed out waiting for device auth token.</span>';
      } finally {
        this.deviceTokenPollInProgress = false;
      }
    },
    renderPresetInfo(preset) {
      const links = [];
      if (preset.docs_url) links.push('<a href="' + this.escapeHtml(preset.docs_url) + '" target="_blank" rel="noopener noreferrer">Docs</a>');
      if (preset.get_api_key_url) links.push('<a href="' + this.escapeHtml(preset.get_api_key_url) + '" target="_blank" rel="noopener noreferrer">Get API key</a>');
      if (preset.auth_portal_url) links.push('<a href="' + this.escapeHtml(preset.auth_portal_url) + '" target="_blank" rel="noopener noreferrer">Auth portal</a>');
      if (preset.device_binding_url) links.push('<a href="' + this.escapeHtml(preset.device_binding_url) + '" target="_blank" rel="noopener noreferrer">Device binding</a>');
      if (preset.oauth_authorize_url) links.push('Browser OAuth');
      const notes = [];
      if (preset.base_url_template) notes.push('Base URL template: <code>' + this.escapeHtml(preset.base_url_template) + '</code>');
      if (preset.base_url_hint) notes.push(this.escapeHtml(preset.base_url_hint));
      if (preset.public_free_no_auth) notes.push('Public free (no auth)');
      if (preset.free_tier_with_key) notes.push('Free tier (with key)');
      if (preset.trial_credits) notes.push('Trial credits');
      if (preset.last_verified_at) notes.push('Verified: ' + this.escapeHtml(preset.last_verified_at));
      if (preset.source_url) notes.push('<a href="' + this.escapeHtml(preset.source_url) + '" target="_blank" rel="noopener noreferrer">Pricing source</a>');
      return links.join(' · ') + (notes.length ? '<div class="mt-1">' + notes.join(' · ') + '</div>' : '');
    },
    renderStats() {
      const s = this.stats || {};
      const req = Number(s.requests || 0);
      const prompt = Number(s.prompt_tokens || 0);
      const generated = Number(s.completion_tokens || 0);
      const latency = Number(s.avg_latency_ms || 0).toFixed(1);
      const gen = Number(s.avg_generation_tps || 0).toFixed(2);
      const periodHours = Math.max(1, Number(this.statsRangeHours || 8));
      const providersAvailable = Number(s.providers_available || 0);
      const providersOnline = Number(s.providers_online || 0);
      const providerChart = this.renderUsageChart(s.requests_per_provider || {}, 'Providers');
      const buckets = Array.isArray(s.buckets) ? s.buckets : [];
      const groupField = this.usageChartGroupBy || 'model';
      const groupLabel = this.usageChartGroupLabel(groupField);
      const providersTable = this.renderUsageMetricTable('Providers', this.aggregateUsageRowsBy(buckets, 'provider'), 'Provider');
      const modelsTable = this.renderUsageMetricTable('Models', this.aggregateUsageRowsBy(buckets, 'model'), 'Model');
      const tokenNamesTable = this.renderUsageMetricTable('Token Names', this.aggregateUsageRowsBy(buckets, 'api_key_name'), 'Token Name');
      const remoteIPsTable = this.renderUsageMetricTable('Remote IPs', this.aggregateUsageRowsBy(buckets, 'client_ip'), 'Remote IP');
      const userAgentsTable = this.renderUsageMetricTable('User Agents', this.aggregateUsageRowsBy(buckets, 'user_agent'), 'User-Agent');
      this.quotaSummaryHtml = this.renderQuotaPanel(s.provider_quotas || {});
      this.statsSummaryHtml =
        '<div class="row g-2">' +
          '<div class="col-3"><div class="border rounded p-2 bg-body d-flex flex-column align-items-center justify-content-center text-center" style="min-height:78px;"><div class="small text-body-secondary">Requests</div><div class="fw-semibold">' + req + '</div></div></div>' +
          '<div class="col-3"><div class="border rounded p-2 bg-body d-flex flex-column align-items-center justify-content-center text-center" style="min-height:78px;"><div class="small text-body-secondary">Prompt / Generated</div><div class="fw-semibold">' + prompt + ' / ' + generated + '</div></div></div>' +
          '<div class="col-3"><div class="border rounded p-2 bg-body d-flex flex-column align-items-center justify-content-center text-center" style="min-height:78px;"><div class="small text-body-secondary">Avg latency ms</div><div class="fw-semibold">' + latency + '</div></div></div>' +
          '<div class="col-3"><div class="border rounded p-2 bg-body d-flex flex-column align-items-center justify-content-center text-center" style="min-height:78px;"><div class="small text-body-secondary">Avg gen tok/s</div><div class="fw-semibold">' + gen + '</div></div></div>' +
        '</div>' +
        '<div class="border rounded p-3 bg-body mt-2">' +
          '<div class="d-flex justify-content-between align-items-center mb-2">' +
            '<div class="fw-semibold">Usage by ' + this.escapeHtml(groupLabel.toLowerCase()) + ' (tokens / 5m)</div>' +
            '<div class="d-flex align-items-center">' +
              '<select class="form-select form-select-sm" style="width:auto;" onchange="window.__adminSetUsageChartGroup(this.value)">' +
                '<option value="model"' + (groupField === 'model' ? ' selected' : '') + '>Model</option>' +
                '<option value="provider"' + (groupField === 'provider' ? ' selected' : '') + '>Provider</option>' +
                '<option value="api_key_name"' + (groupField === 'api_key_name' ? ' selected' : '') + '>Token Name</option>' +
                '<option value="client_ip"' + (groupField === 'client_ip' ? ' selected' : '') + '>Remote IP</option>' +
                '<option value="user_agent"' + (groupField === 'user_agent' ? ' selected' : '') + '>User Agent</option>' +
              '</select>' +
            '</div>' +
          '</div>' +
          '<div style="height:280px;"><canvas id="modelUsageChart"></canvas></div>' +
        '</div>' +
        '<div class="small text-body-secondary mt-2">Providers available: <strong>' + providersAvailable + '</strong> · Online: <strong>' + providersOnline + '</strong></div>' +
        '<div class="row g-3 mt-1">' +
          '<div class="col-lg-6">' + providersTable + '</div>' +
          '<div class="col-lg-6">' + modelsTable + '</div>' +
          '<div class="col-lg-6">' + tokenNamesTable + '</div>' +
          '<div class="col-lg-6">' + remoteIPsTable + '</div>' +
          '<div class="col-lg-6">' + userAgentsTable + '</div>' +
        '</div>';
      setTimeout(() => this.renderUsageTimelineChart(buckets, groupField), 0);
    },
    usageChartGroupLabel(field) {
      if (field === 'provider') return 'Provider';
      if (field === 'api_key_name') return 'Token Name';
      if (field === 'client_ip') return 'Remote IP';
      if (field === 'user_agent') return 'User Agent';
      return 'Model';
    },
    renderQuotaPanel(quotaMap) {
      const chart = this.renderQuotaChart(quotaMap || {});
      if (!chart) return '<div class="small text-body-secondary">No quota data.</div>';
      return chart;
    },
    chartColor(seed) {
      let h = 0;
      const str = String(seed || '');
      for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) >>> 0;
      const hue = h % 360;
      return 'hsl(' + hue + ', 70%, 55%)';
    },
    renderUsageTimelineChart(buckets, groupField) {
      const canvas = document.getElementById('modelUsageChart');
      if (!canvas || typeof Chart === 'undefined') return;
      const now = Date.now();
      const rangeMs = Math.max(1, Number(this.statsRangeHours || 8)) * 3600 * 1000;
      const bucketMs = 5 * 60 * 1000;
      const endBucket = Math.floor(now / bucketMs) * bucketMs;
      const startBucket = Math.floor((endBucket - rangeMs) / bucketMs) * bucketMs;
      const byGroup = {};
      const field = String(groupField || 'model').trim();
      (Array.isArray(buckets) ? buckets : []).forEach((b) => {
        const raw = String(b[field] || '').trim();
        const name = raw || '(unknown)';
        const tRaw = new Date(String(b.start_at || '')).getTime();
        if (!Number.isFinite(tRaw)) return;
        const t = Math.floor(tRaw / bucketMs) * bucketMs;
        if (t < startBucket || t > endBucket) return;
        const y = Number(b.total_tokens || 0);
        if (!byGroup[name]) byGroup[name] = {};
        byGroup[name][t] = Number(byGroup[name][t] || 0) + y;
      });
      const times = [];
      for (let t = startBucket; t <= endBucket; t += bucketMs) times.push(t);
      const labels = times.map((t) => {
        const d = new Date(t);
        const hh = String(d.getHours()).padStart(2, '0');
        const mm = String(d.getMinutes()).padStart(2, '0');
        return hh + ':' + mm;
      });
      const names = Object.keys(byGroup).sort((a, b) => {
        const sumA = Object.values(byGroup[a] || {}).reduce((acc, v) => acc + Number(v || 0), 0);
        const sumB = Object.values(byGroup[b] || {}).reduce((acc, v) => acc + Number(v || 0), 0);
        return (sumB - sumA) || a.localeCompare(b);
      });
      const datasets = names.map((name) => {
        const color = this.chartColor(name);
        const seriesMap = byGroup[name] || {};
        const data = times.map((t) => Number(seriesMap[t] || 0));
        return {
          label: name,
          data,
          borderColor: color,
          backgroundColor: color,
          borderWidth: 1
        };
      });
      if (this.usageChart) {
        try { this.usageChart.destroy(); } catch (_) {}
        this.usageChart = null;
      }
      this.usageChart = new Chart(canvas.getContext('2d'), {
        type: 'bar',
        data: {labels, datasets},
        options: {
          animation: false,
          maintainAspectRatio: false,
          scales: {
            x: {
              stacked: true
            },
            y: {
              beginAtZero: true,
              stacked: true,
              title: {display: true, text: 'Tokens'}
            }
          },
          plugins: {
            legend: {display: true, position: 'bottom'},
            tooltip: {
              callbacks: {
                title: (items) => {
                  if (!items || !items.length) return '';
                  return String(items[0].label || '');
                },
                label: (ctx) => (ctx.dataset.label + ': ' + Math.round(Number(ctx.raw || 0)) + ' tokens')
              }
            }
          }
        }
      });
    },
    renderQuotaChart(quotaMap) {
      const items = Object.values(quotaMap || {});
      if (!items.length) return '';
      const cards = items.map((q) => {
        const name = this.escapeHtml(q.display_name || q.provider || 'provider');
        const checkedAtRaw = String(q.checked_at || '').trim();
        let staleLabel = '';
        if (checkedAtRaw) {
          const ts = new Date(checkedAtRaw);
          if (!Number.isNaN(ts.getTime())) {
            const ageMs = Date.now() - ts.getTime();
            if (ageMs > 60 * 60 * 1000) {
              staleLabel = 'stale ' + this.formatAge(checkedAtRaw);
            }
          }
        }
        const staleHtml = staleLabel ? (' <span class="small text-warning">(' + this.escapeHtml(staleLabel) + ')</span>') : '';
        const status = String(q.status || '');
        if (status !== 'ok') {
          const err = this.escapeHtml(String(q.error || 'quota unavailable'));
          return '<div class="border rounded p-2 bg-body" style="width:100%;flex:1 1 100%;max-width:100%;">' +
            '<div class="fw-semibold small mb-1">' + name + staleHtml + '</div>' +
            '<div class="small text-danger">' + err + '</div>' +
          '</div>';
        }
        const metrics = (Array.isArray(q.metrics) && q.metrics.length)
          ? q.metrics
          : [{metered_feature: 'codex', window: '', left_percent: q.left_percent, reset_at: q.reset_at}];
        const plan = this.escapeHtml(String(q.plan_type || '').toUpperCase());
        const metricRows = metrics.map((m) => {
          const left = Math.max(0, Math.min(100, Number(m.left_percent || 0)));
          const used = Math.max(0, Math.min(100, 100 - left));
          const ringColor = used >= 90 ? '#dc3545' : (used >= 70 ? '#fd7e14' : '#198754');
          const resetAge = this.formatUntil(m.reset_at);
          const feature = String(m.metered_feature || '').trim();
          const windowLabel = String(m.window || '').trim();
          const labelParts = [];
          if (feature) labelParts.push(feature);
          if (windowLabel) labelParts.push(windowLabel);
          const label = this.escapeHtml(labelParts.join(' · ') || 'quota');
          const tileFlex = (window.innerWidth && window.innerWidth < 768) ? '1 1 100%' : '1 1 240px';
          return '<div class="border rounded p-2 bg-body d-flex align-items-center gap-2" style="min-width:180px;flex:' + tileFlex + ';max-width:100%;">' +
            '<div style="width:62px;height:62px;border-radius:999px;background:conic-gradient(' + ringColor + ' ' + used + '%, rgba(128,128,128,0.25) 0);display:flex;align-items:center;justify-content:center;">' +
              '<div class="bg-body rounded-circle d-flex align-items-center justify-content-center fw-semibold" style="width:48px;height:48px;font-size:12px;">' + Math.round(left) + '%</div>' +
            '</div>' +
            '<div class="small" style="min-width:0;">' +
              '<div class="fw-semibold text-break">' + label + '</div>' +
              '<div class="text-body-secondary">Quota left · ' + Math.round(left) + '%</div>' +
              '<div class="text-body-secondary">' + (resetAge ? ('resets ' + this.escapeHtml(resetAge)) : 'reset unknown') + '</div>' +
            '</div>' +
          '</div>';
        }).join('');
        return '<div class="border rounded p-2 bg-body" style="width:100%;flex:1 1 100%;max-width:100%;">' +
          '<div class="small fw-semibold mb-2">' + name + (plan ? (' · ' + plan) : '') + staleHtml + '</div>' +
          '<div class="d-flex flex-wrap gap-2 align-items-stretch" style="width:100%;">' + metricRows + '</div>' +
        '</div>';
      }).join('');
      return '<div class="mt-2 d-flex flex-wrap gap-2 align-items-start" style="width:100%;">' + cards + '</div>';
    },
    renderUsageChart(sourceMap, title) {
      const colors = ['#0d6efd', '#198754', '#dc3545', '#fd7e14', '#20c997', '#6f42c1', '#0dcaf0', '#ffc107', '#6c757d', '#6610f2'];
      let items = Object.entries(sourceMap || {}).map(([name, count]) => ({name, count: Number(count || 0)})).filter((x) => x.count > 0);
      items.sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
      if (items.length > 8) items = items.slice(0, 8);
      if (items.length === 0) {
        return '<div class="border rounded p-3 bg-body"><div class="fw-semibold mb-2">' + this.escapeHtml(title) + '</div><div class="small text-body-secondary">No usage yet.</div></div>';
      }
      const maxCount = items[0].count || 1;
      const rows = items.map((item, i) => {
        const color = colors[i % colors.length];
        const w = Math.max(3, Math.round((item.count / maxCount) * 100));
        return '<div class="mb-2">' +
          '<div class="d-flex justify-content-between small mb-1">' +
            '<span><span class="d-inline-block me-1" style="width:10px;height:10px;border-radius:2px;background:' + color + ';"></span>' + this.escapeHtml(item.name) + '</span>' +
            '<span class="text-body-secondary">' + item.count + '</span>' +
          '</div>' +
          '<div class="progress" style="height:8px;"><div class="progress-bar" role="progressbar" style="width:' + w + '%;background:' + color + ';"></div></div>' +
        '</div>';
      }).join('');
      return '<div class="border rounded p-3 bg-body"><div class="fw-semibold mb-2">' + this.escapeHtml(title) + '</div>' + rows + '</div>';
    },
    aggregateUsageRowsBy(buckets, field) {
      const now = Date.now();
      const rangeMs = Math.max(1, Number(this.statsRangeHours || 8)) * 3600 * 1000;
      const cutoff = now - rangeMs;
      const map = {};
      (Array.isArray(buckets) ? buckets : []).forEach((b) => {
        const t = new Date(String(b.start_at || '')).getTime();
        if (!Number.isFinite(t) || t < cutoff) return;
        const raw = String(b[field] || '').trim();
        const name = raw || '(unknown)';
        if (!map[name]) map[name] = {name, requests: 0, pp: 0, tg: 0};
        map[name].requests += Number(b.requests || 0);
        map[name].pp += Number(b.prompt_tokens || 0);
        map[name].tg += Number(b.completion_tokens || 0);
      });
      const rows = Object.values(map).filter((x) => x.requests > 0 || x.pp > 0 || x.tg > 0);
      rows.sort((a, b) => (b.requests - a.requests) || (b.pp - a.pp) || (b.tg - a.tg) || a.name.localeCompare(b.name));
      return rows;
    },
    renderUsageMetricTable(title, rows, nameHeader) {
      const bodyRows = (Array.isArray(rows) ? rows : []).slice(0, 50).map((r) => {
        return '<tr>' +
          '<td class="text-break">' + this.escapeHtml(r.name || '') + '</td>' +
          '<td class="text-end">' + Number(r.requests || 0) + '</td>' +
          '<td class="text-end">' + Number(r.pp || 0) + '</td>' +
          '<td class="text-end">' + Number(r.tg || 0) + '</td>' +
        '</tr>';
      }).join('');
      return '<div class="border rounded p-3 bg-body">' +
        '<div class="fw-semibold mb-2">' + this.escapeHtml(title) + '</div>' +
        '<div class="table-responsive">' +
          '<table class="table table-sm align-middle mb-0">' +
            '<thead><tr><th>' + this.escapeHtml(nameHeader) + '</th><th class="text-end">Requests</th><th class="text-end">PP</th><th class="text-end">TG</th></tr></thead>' +
            '<tbody>' + (bodyRows || '<tr><td colspan="4" class="text-body-secondary">No usage yet.</td></tr>') + '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>';
    },
    renderModelStatsTable(buckets) {
      const now = Date.now();
      const rangeMs = Math.max(1, Number(this.statsRangeHours || 8)) * 3600 * 1000;
      const cutoff = now - rangeMs;
      const perModel = {};
      (Array.isArray(buckets) ? buckets : []).forEach((b) => {
        const model = String(b.model || '').trim();
        if (!model) return;
        const t = new Date(String(b.start_at || '')).getTime();
        if (!Number.isFinite(t) || t < cutoff) return;
        if (!perModel[model]) perModel[model] = {
          model,
          requests: 0,
          prompt_tokens: 0,
          completion_tokens: 0,
          total_tokens: 0,
          latency_ms_sum: 0,
          prompt_tps_sum: 0,
          generation_tps_sum: 0
        };
        const x = perModel[model];
        x.requests += Number(b.requests || 0);
        x.prompt_tokens += Number(b.prompt_tokens || 0);
        x.completion_tokens += Number(b.completion_tokens || 0);
        x.total_tokens += Number(b.total_tokens || 0);
        x.latency_ms_sum += Number(b.latency_ms_sum || 0);
        x.prompt_tps_sum += Number(b.prompt_tps_sum || 0);
        x.generation_tps_sum += Number(b.generation_tps_sum || 0);
      });
      const rowsData = Object.values(perModel).filter((x) => x.requests > 0);
      rowsData.sort((a, b) => (b.total_tokens - a.total_tokens) || (b.requests - a.requests) || a.model.localeCompare(b.model));
      if (!rowsData.length) return '';
      const rows = rowsData.map((x) => {
        const avgLatency = x.requests > 0 ? (x.latency_ms_sum / x.requests).toFixed(1) : '0.0';
        const avgPromptTPS = x.requests > 0 ? (x.prompt_tps_sum / x.requests).toFixed(2) : '0.00';
        const avgGenTPS = x.requests > 0 ? (x.generation_tps_sum / x.requests).toFixed(2) : '0.00';
        const color = this.chartColor(x.model);
        return '<tr>' +
          '<td class="text-break"><span class="d-inline-block me-2 align-middle" style="width:10px;height:10px;border-radius:2px;background:' + color + ';"></span><span class="align-middle">' + this.escapeHtml(x.model) + '</span></td>' +
          '<td class="text-end">' + Number(x.requests || 0) + '</td>' +
          '<td class="text-end">' + Number(x.prompt_tokens || 0) + '</td>' +
          '<td class="text-end">' + Number(x.completion_tokens || 0) + '</td>' +
          '<td class="text-end">' + this.escapeHtml(avgLatency) + '</td>' +
          '<td class="text-end">' + this.escapeHtml(avgPromptTPS) + '</td>' +
          '<td class="text-end">' + this.escapeHtml(avgGenTPS) + '</td>' +
        '</tr>';
      }).join('');
      return '<div class="border rounded p-3 bg-body mt-2">' +
        '<div class="fw-semibold mb-2">Per-model usage</div>' +
        '<div class="table-responsive">' +
          '<table class="table table-sm align-middle mb-0">' +
            '<thead><tr><th>Model</th><th class="text-end">Requests</th><th class="text-end">Prompt</th><th class="text-end">Generated</th><th class="text-end">Avg latency ms</th><th class="text-end">Avg prompt tok/s</th><th class="text-end">Avg gen tok/s</th></tr></thead>' +
            '<tbody>' + rows + '</tbody>' +
          '</table>' +
        '</div>' +
      '</div>';
    },
    renderProviders() {
      const rows = (this.providers || []).map((p) => {
        const rawName = String(p.name || '').trim();
        const name = this.escapeHtml(rawName);
        const display = this.escapeHtml(p.display_name || p.name);
        const iconName = this.escapeHtml(String(p.provider_type || p.name || '').trim());
        const iconCls = this.providerIconNeedsDarkInvert(iconName) ? ' provider-icon-invert-dark' : '';
        const providerLabel = '<span class="d-inline-flex align-items-center gap-2"><img src="' + this.providerIconSrc(iconName) + '" class="' + iconCls.trim() + '" onerror="this.onerror=null;this.src=&quot;data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==&quot;" alt="" width="16" height="16" style="object-fit:contain;" /><span>' + display + '</span></span>';
        const statusRaw = String(p.status || 'unknown');
        const ageText = this.formatAge(p.checked_at);
        const modelCount = Number(p.model_count || 0);
        const pricedCount = Number(p.priced_models || 0);
        const freeCount = Number(p.free_models || 0);
        let totalModels = modelCount;
        if (totalModels <= 0 && pricedCount > 0) totalModels = pricedCount;
        const unknownCount = Math.max(0, totalModels - pricedCount);
        const totalModelsText = totalModels + ' (' + freeCount + ' free, ' + unknownCount + ' unknown)';
        const responseMSValue = Number(p.response_ms || 0);
        const responseMS = responseMSValue > 0 ? responseMSValue + 'ms' : '';
        let status = this.escapeHtml(statusRaw);
        if (statusRaw === 'online') {
          const detail = [responseMS, ageText].filter(Boolean).join(' ');
          status = this.escapeHtml(detail || 'online');
        }
        const pricingAge = this.formatAge(p.pricing_last_update);
        const pricingUpdated = this.escapeHtml(pricingAge || '');
        const actionNameAttr = this.escapeHtml(rawName);
        const actions = p.managed
          ? '<div class="d-flex justify-content-end gap-1">' +
              '<button class="icon-btn" type="button" title="Edit provider" aria-label="Edit provider" data-provider-name="' + actionNameAttr + '" onclick="window.__adminEditProvider(this.getAttribute(\'data-provider-name\'))"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true"><path d="M12.146.854a.5.5 0 0 1 .708 0l2.292 2.292a.5.5 0 0 1 0 .708l-8.5 8.5a.5.5 0 0 1-.168.11l-3 1.2a.5.5 0 0 1-.65-.65l1.2-3a.5.5 0 0 1 .11-.168zM11.5 2.207 4.545 9.162l-.733 1.833 1.833-.733L12.6 3.307z"/></svg></button>' +
              '<button class="icon-btn icon-btn-danger" type="button" title="Delete provider" aria-label="Delete provider" data-provider-name="' + actionNameAttr + '" onclick="window.__adminRemoveProvider(this.getAttribute(\'data-provider-name\'))"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true"><path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5Zm2.5.5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6Zm2 .5a.5.5 0 0 1 1 0v6a.5.5 0 0 1-1 0V6Z"/><path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 1 1 0-2H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1ZM4 4v9a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4H4Z"/></svg></button>' +
            '</div>'
          : '<span class="badge text-bg-light border">Auto</span>';
        return '<tr>' +
          '<td>' + providerLabel + '</td>' +
          '<td>' + status + '</td>' +
          '<td>' + this.escapeHtml(totalModelsText) + '</td>' +
          '<td><small>' + pricingUpdated + '</small></td>' +
          '<td>' + actions + '</td>' +
          '</tr>';
      });
      const page = this.paginateRows(rows, this.providersPage, this.providersPageSize);
      this.providersPage = page.page;
      this.providersPageSize = page.pageSize;
      const tableRows = page.rows.join('');
      this.providersTableHtml =
        '<table class="table table-sm align-middle mb-0">' +
          '<thead><tr><th>Name</th><th>Status</th><th>Total Models</th><th>Pricing Updated</th><th></th></tr></thead>' +
          '<tbody>' + (tableRows || '<tr><td colspan="5" class="text-body-secondary">No providers configured.</td></tr>') + '</tbody>' +
        '</table>' +
        this.renderProvidersPager(page.totalRows, page.page, page.totalPages, page.pageSize);
    },
    renderAccessTokens() {
      const items = (this.accessTokens || []).map((t) => ({
        id: String(t.id || '').trim(),
        name: String(t.name || '').trim() || 'Token',
        role: String(t.role || '').trim().toLowerCase() || 'inferrer',
        parent_id: String(t.parent_id || '').trim(),
        redacted_key: String(t.redacted_key || '').trim(),
        expires_at: String(t.expires_at || '').trim()
      }));
      const byParent = {};
      items.forEach((t) => {
        const parent = t.parent_id;
        if (!byParent[parent]) byParent[parent] = [];
        byParent[parent].push(t);
      });
      const byID = {};
      items.forEach((t) => { if (t.id) byID[t.id] = t; });

      const roots = items.filter((t) => !t.parent_id || !byID[t.parent_id]);
      roots.sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
      Object.keys(byParent).forEach((k) => {
        byParent[k].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id));
      });

      const renderRoleBadge = (role) => {
        const r = String(role || '').trim().toLowerCase();
        if (r === 'admin') return '<span class="badge text-bg-danger">admin</span>';
        if (r === 'keymaster') return '<span class="badge text-bg-warning text-dark">keymaster</span>';
        return '<span class="badge text-bg-secondary">inferrer</span>';
      };
      const renderRow = (t, depth) => {
        const id = this.escapeHtml(t.id);
        const name = this.escapeHtml(t.name);
        const redacted = this.escapeHtml(t.redacted_key);
        const expiry = this.escapeHtml(t.expires_at || '-');
        const indent = depth > 0 ? (' style="padding-left:' + (depth * 20) + 'px;"') : '';
        const marker = depth > 0 ? '<span class="text-body-secondary me-1">↳</span>' : '';
        const row = '<tr>' +
          '<td' + indent + '>' + marker + name + '</td>' +
          '<td>' + renderRoleBadge(t.role) + '</td>' +
          '<td><code>' + redacted + '</code></td>' +
          '<td>' + expiry + '</td>' +
          '<td class="text-end">' +
            '<button class="icon-btn me-1" type="button" title="Edit token" aria-label="Edit token" data-token-id="' + id + '" onclick="window.__adminEditAccessToken(this.getAttribute(\'data-token-id\'))">' +
              '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true"><path d="M12.146.854a.5.5 0 0 1 .708 0l2.292 2.292a.5.5 0 0 1 0 .708l-8.5 8.5a.5.5 0 0 1-.168.11l-3 1.2a.5.5 0 0 1-.65-.65l1.2-3a.5.5 0 0 1 .11-.168zM11.5 2.207 4.545 9.162l-.733 1.833 1.833-.733L12.6 3.307z"/></svg>' +
            '</button>' +
            '<button class="icon-btn icon-btn-danger" type="button" title="Delete token" aria-label="Delete token" data-token-id="' + id + '" onclick="window.__adminDeleteAccessToken(this.getAttribute(\'data-token-id\'))">' +
              '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true"><path d="M5.5 5.5A.5.5 0 0 1 6 6v6a.5.5 0 0 1-1 0V6a.5.5 0 0 1 .5-.5Zm2.5.5a.5.5 0 0 0-1 0v6a.5.5 0 0 0 1 0V6Zm2 .5a.5.5 0 0 1 1 0v6a.5.5 0 0 1-1 0V6Z"/><path d="M14.5 3a1 1 0 0 1-1 1H13v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V4h-.5a1 1 0 1 1 0-2H6a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1h3.5a1 1 0 0 1 1 1ZM4 4v9a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V4H4Z"/></svg>' +
            '</button>' +
          '</td>' +
          '</tr>';
        const kids = (byParent[t.id] || []).map((c) => renderRow(c, depth + 1)).join('');
        return row + kids;
      };
      const rows = roots.map((t) => renderRow(t, 0)).join('');
      this.accessTokensTableHtml =
        '<table class="table table-sm align-middle mb-0">' +
          '<thead><tr><th>Name</th><th>Type</th><th>Key</th><th>Expiry</th><th></th></tr></thead>' +
          '<tbody>' + (rows || '<tr><td colspan="5" class="text-body-secondary">No tokens found.</td></tr>') + '</tbody>' +
        '</table>';
      window.__adminDeleteAccessToken = (id) => this.removeAccessToken(id);
      window.__adminEditAccessToken = (id) => this.openEditAccessTokenModal(id);
    },
    randomTokenKey() {
      const prefix = 'tr_';
      try {
        const bytes = new Uint8Array(48);
        if (window.crypto && window.crypto.getRandomValues) {
          window.crypto.getRandomValues(bytes);
        } else {
          for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256);
        }
        let b64 = btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
        if (b64.length < 64) b64 = (b64 + b64 + b64).slice(0, 64);
        return prefix + b64.slice(0, 64);
      } catch (_) {
        return prefix + String(Date.now()) + '_' + Math.random().toString(36).slice(2).padEnd(48, 'x');
      }
    },
    openAddAccessTokenModal() {
      this.showAddAccessTokenModal = true;
      this.accessTokenDraft = {id:'', name:'', key:this.randomTokenKey(), role:'inferrer', expiry_preset:'never', expires_at:'', quota_enabled:false, quota_requests_limit:'', quota_requests_interval_seconds:'0', quota_tokens_limit:'', quota_tokens_interval_seconds:'0'};
      this.accessTokenStatusHtml = '';
    },
    openEditAccessTokenModal(id) {
      const sid = String(id || '').trim();
      const t = (this.accessTokens || []).find((x) => String(x.id || '').trim() === sid);
      if (!t) return;
      const expiresAt = String(t.expires_at || '').trim();
      this.showAddAccessTokenModal = true;
      const q = t && t.quota ? t.quota : {};
      const qr = q && q.requests ? q.requests : {};
      const qt = q && q.tokens ? q.tokens : {};
      const hasQuota = Number(qr.limit || 0) > 0 || Number(qt.limit || 0) > 0;
      this.accessTokenDraft = {
        id: sid,
        name: String(t.name || '').trim(),
        key: '',
        role: String(t.role || 'inferrer').trim().toLowerCase() || 'inferrer',
        expiry_preset: expiresAt ? 'custom' : 'never',
        expires_at: expiresAt,
        quota_enabled: hasQuota,
        quota_requests_limit: Number(qr.limit || 0) > 0 ? String(qr.limit) : '',
        quota_requests_interval_seconds: String(Number(qr.interval_seconds || 0)),
        quota_tokens_limit: Number(qt.limit || 0) > 0 ? String(qt.limit) : '',
        quota_tokens_interval_seconds: String(Number(qt.interval_seconds || 0))
      };
      this.accessTokenStatusHtml = '';
    },
    closeAddAccessTokenModal() {
      if (this.requiresInitialTokenSetup) return;
      this.showAddAccessTokenModal = false;
      this.accessTokenDraft = {id:'', name:'', key:'', role:'inferrer', expiry_preset:'never', expires_at:'', quota_enabled:false, quota_requests_limit:'', quota_requests_interval_seconds:'0', quota_tokens_limit:'', quota_tokens_interval_seconds:'0'};
      this.accessTokenStatusHtml = '';
    },
    buildAccessTokenQuotaPayload() {
      if (!this.accessTokenDraft.quota_enabled) return null;
      const reqLimit = Math.max(0, Number(this.accessTokenDraft.quota_requests_limit || 0));
      const reqInterval = Math.max(0, Number(this.accessTokenDraft.quota_requests_interval_seconds || 0));
      const tokLimit = Math.max(0, Number(this.accessTokenDraft.quota_tokens_limit || 0));
      const tokInterval = Math.max(0, Number(this.accessTokenDraft.quota_tokens_interval_seconds || 0));
      const quota = {};
      if (reqLimit > 0) {
        quota.requests = {
          limit: Math.floor(reqLimit),
          interval_seconds: Math.floor(reqInterval)
        };
      }
      if (tokLimit > 0) {
        quota.tokens = {
          limit: Math.floor(tokLimit),
          interval_seconds: Math.floor(tokInterval)
        };
      }
      if (!quota.requests && !quota.tokens) return null;
      return quota;
    },
    regenerateAccessTokenKey() {
      this.accessTokenDraft.key = this.randomTokenKey();
    },
    async copyAccessTokenKey() {
      const key = String(this.accessTokenDraft.key || '').trim();
      if (!key) return;
      try {
        await navigator.clipboard.writeText(key);
        this.accessTokenStatusHtml = '<span class="text-success">Key copied.</span>';
      } catch (_) {
        this.accessTokenStatusHtml = '<span class="text-danger">Could not copy key.</span>';
      }
    },
    expiryPresetToRFC3339(preset) {
      const p = String(preset || 'never').trim();
      if (p === 'never') return '';
      const now = new Date();
      const out = new Date(now.getTime());
      if (p === '1d') out.setDate(out.getDate() + 1);
      else if (p === '1w') out.setDate(out.getDate() + 7);
      else if (p === '1m') out.setMonth(out.getMonth() + 1);
      else if (p === '3m') out.setMonth(out.getMonth() + 3);
      else if (p === '12m') out.setMonth(out.getMonth() + 12);
      else return '';
      return out.toISOString();
    },
    renderModelsCatalog() {
      const search = this.modelsSearch.trim().toLowerCase();
      let rows = (this.modelsCatalog || []).filter((m) => {
        if (!search) return true;
        return String(m.provider || '').toLowerCase().includes(search) || String(m.model || '').toLowerCase().includes(search);
      });
      if (this.modelsFreeOnly) {
        rows = rows.filter((m) => Number(m.input_per_1m) === 0 && Number(m.output_per_1m) === 0);
      }
      const sortBy = this.modelsSortBy;
      const dir = this.modelsSortAsc ? 1 : -1;
      rows.sort((a, b) => {
        const av = a[sortBy];
        const bv = b[sortBy];
        if (sortBy === 'input_per_1m' || sortBy === 'output_per_1m') {
          return (Number(av || 0) - Number(bv || 0)) * dir;
        }
        return String(av || '').localeCompare(String(bv || '')) * dir;
      });
      const htmlRows = rows.map((m) => {
        const providerDisplay = this.escapeHtml(m.provider_display_name || m.provider);
        const iconName = this.escapeHtml(String(m.provider_type || m.provider || '').trim());
        const iconCls = this.providerIconNeedsDarkInvert(iconName) ? ' provider-icon-invert-dark' : '';
        const providerLabel = '<span class="d-inline-flex align-items-center gap-2"><img src="' + this.providerIconSrc(iconName) + '" class="' + iconCls.trim() + '" onerror="this.onerror=null;this.src=&quot;data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==&quot;" alt="" width="16" height="16" style="object-fit:contain;" /><span>' + providerDisplay + '</span></span>';
        const model = this.escapeHtml(m.model || '-');
        const statusRaw = String(m.status || 'unknown');
        const ageText = this.formatAge(m.checked_at);
        const responseMSValue = Number(m.response_ms || 0);
        const responseMS = responseMSValue > 0 ? responseMSValue + 'ms' : '';
        let status = this.escapeHtml(statusRaw);
        if (statusRaw === 'online') {
          status = this.escapeHtml([responseMS, ageText].filter(Boolean).join(' ') || 'online');
        }
        const hasInput = !(m.input_per_1m === undefined || m.input_per_1m === null);
        const hasOutput = !(m.output_per_1m === undefined || m.output_per_1m === null);
        const inputNum = hasInput ? Number(m.input_per_1m) : null;
        const outputNum = hasOutput ? Number(m.output_per_1m) : null;
        const isFree = hasInput && hasOutput && inputNum === 0 && outputNum === 0;
        const input = this.formatPrice(inputNum, m.currency);
        const output = this.formatPrice(outputNum, m.currency);
        return '<tr>' +
          '<td>' + providerLabel + '</td>' +
          '<td>' + model + '</td>' +
          '<td>' + status + '</td>' +
          '<td class="text-end' + (isFree ? ' text-success fw-semibold' : '') + '">' + input + '</td>' +
          '<td class="text-end' + (isFree ? ' text-success fw-semibold' : '') + '">' + output + '</td>' +
          '</tr>';
      });
      const page = this.paginateRows(htmlRows, this.modelsPage, this.modelsPageSize);
      this.modelsPage = page.page;
      this.modelsPageSize = page.pageSize;
      const tableRows = page.rows.join('');
      const sortArrow = this.modelsSortAsc ? ' ▲' : ' ▼';
      const providerSort = this.modelsSortBy === 'provider' ? sortArrow : '';
      const modelSort = this.modelsSortBy === 'model' ? sortArrow : '';
      const inputSort = this.modelsSortBy === 'input_per_1m' ? sortArrow : '';
      const outputSort = this.modelsSortBy === 'output_per_1m' ? sortArrow : '';
      this.modelsTableHtml =
        '<table class="table table-sm align-middle mb-0">' +
          '<thead><tr>' +
          '<th role="button" class="text-decoration-underline" onclick="window.__adminSortModels(\'provider\')">Provider' + providerSort + '</th>' +
          '<th role="button" class="text-decoration-underline" onclick="window.__adminSortModels(\'model\')">Model' + modelSort + '</th>' +
          '<th>Status</th>' +
          '<th role="button" class="text-decoration-underline text-end" onclick="window.__adminSortModels(\'input_per_1m\')">Input / 1M' + inputSort + '</th>' +
          '<th role="button" class="text-decoration-underline text-end" onclick="window.__adminSortModels(\'output_per_1m\')">Output / 1M' + outputSort + '</th>' +
          '</tr></thead>' +
          '<tbody>' + (tableRows || '<tr><td colspan="5" class="text-body-secondary">No models available.</td></tr>') + '</tbody>' +
        '</table>' +
        this.renderModelsPager(page.totalRows, page.page, page.totalPages, page.pageSize);
    },
    renderModelsFreshness(fetchedAt, pricingUpdatedAt) {
      const now = new Date();
      const fetched = fetchedAt ? new Date(fetchedAt) : null;
      const pricing = pricingUpdatedAt ? new Date(pricingUpdatedAt) : null;
      let fetchedText = 'unknown';
      if (fetched && !Number.isNaN(fetched.getTime())) {
        const ageSec = Math.floor((now.getTime() - fetched.getTime()) / 1000);
        fetchedText = fetched.toLocaleString() + ' (' + this.formatAge(fetched.toISOString()).replace(' ago', '') + ' ago)';
        if (ageSec < 0) fetchedText = fetched.toLocaleString();
      }
      let pricingText = 'unknown';
      if (pricing && !Number.isNaN(pricing.getTime())) {
        const ageMin = Math.floor((now.getTime() - pricing.getTime()) / 60000);
        pricingText = pricing.toLocaleString() + ' (' + ageMin + 'm ago)';
      }
      this.modelsFreshnessHtml = 'Catalog fetched: <strong>' + this.escapeHtml(fetchedText) + '</strong> · Pricing cache: <strong>' + this.escapeHtml(pricingText) + '</strong>';
    },
    toggleModelsSortDir() {
      this.modelsSortAsc = !this.modelsSortAsc;
      this.renderModelsCatalog();
    },
    sortModelsBy(col) {
      if (this.modelsSortBy === col) {
        this.modelsSortAsc = !this.modelsSortAsc;
      } else {
        this.modelsSortBy = col;
        this.modelsSortAsc = true;
      }
      this.renderModelsCatalog();
    },
    toggleFreeOnly() {
      this.modelsFreeOnly = !this.modelsFreeOnly;
      this.persistModelsFreeOnly();
      this.modelsPage = 1;
      this.renderModelsCatalog();
    },
    async loadStats(force) {
      const sec = Math.max(1, Number(this.statsRangeHours || 8)) * 3600;
      const u = force ? ('/admin/api/stats?period_seconds=' + sec + '&force=1') : ('/admin/api/stats?period_seconds=' + sec);
      const r = await this.apiFetch(u, {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      this.stats = await r.json();
      this.renderStats();
    },
    async refreshQuota() {
      if (this.quotaRefreshInProgress) return;
      this.quotaRefreshInProgress = true;
      const startedAt = Date.now();
      try {
        await this.loadStats(true);
      } finally {
        const elapsed = Date.now() - startedAt;
        const minVisibleMs = 600;
        if (elapsed < minVisibleMs) {
          await new Promise((resolve) => setTimeout(resolve, minVisibleMs - elapsed));
        }
        this.quotaRefreshInProgress = false;
      }
    },
    async loadSecuritySettings() {
      const r = await this.apiFetch('/admin/api/settings/security', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json();
      this.allowLocalhostNoAuth = !!body.allow_localhost_no_auth;
      this.allowHostDockerInternalNoAuth = !!body.allow_host_docker_internal_no_auth;
      this.autoEnablePublicFreeModels = !!body.auto_enable_public_free_models;
    },
    async saveSecuritySettings() {
      if (this.securitySaveInProgress) return;
      this.securitySaveInProgress = true;
      try {
        const payload = {
          allow_localhost_no_auth: !!this.allowLocalhostNoAuth,
          allow_host_docker_internal_no_auth: !!this.allowHostDockerInternalNoAuth,
          auto_enable_public_free_models: !!this.autoEnablePublicFreeModels
        };
        const r = await this.apiFetch('/admin/api/settings/security', {method:'PUT', headers:this.headers(), body:JSON.stringify(payload)});
        if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        this.statusHtml = r.ok ? '<span class="text-success">Security settings saved.</span>' : '<span class="text-danger">Failed to save security settings.</span>';
      } finally {
        this.securitySaveInProgress = false;
      }
    },
    async loadTLSSettings() {
      const r = await this.apiFetch('/admin/api/settings/tls', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json();
      this.tlsSettings = {
        enabled: !!body.enabled,
        domain: String(body.domain || '').trim(),
        email: String(body.email || '').trim(),
        cache_dir: String(body.cache_dir || '').trim()
      };
    },
    async loadVersion() {
      const r = await this.apiFetch('/admin/api/version', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json().catch(() => ({}));
      this.appVersion = String(body.version || '').trim();
    },
    async saveTLSSettings() {
      if (this.tlsSaveInProgress) return;
      this.tlsSaveInProgress = true;
      try {
        const payload = {
          enabled: !!this.tlsSettings.enabled,
          domain: String(this.tlsSettings.domain || '').trim(),
          email: String(this.tlsSettings.email || '').trim()
        };
        const r = await this.apiFetch('/admin/api/settings/tls', {method:'PUT', headers:this.headers(), body:JSON.stringify(payload)});
        if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        const txt = await r.text();
        this.statusHtml = r.ok
          ? '<span class="text-success">TLS settings saved. Restart torod for listener changes to apply.</span>'
          : '<span class="text-danger">' + this.escapeHtml(txt || 'Failed to save TLS settings.') + '</span>';
        if (r.ok) {
          await this.loadTLSSettings();
        }
      } finally {
        this.tlsSaveInProgress = false;
      }
    },
    async testTLSCertificate() {
      await this.runTLSAction('/admin/api/settings/tls/test-certificate', 'Test certificate obtained.');
    },
    async renewTLSCertificate() {
      await this.runTLSAction('/admin/api/settings/tls/renew', 'Certificate renewed.');
    },
    async runTLSAction(url, fallbackMessage) {
      if (this.tlsActionInProgress) return;
      this.tlsActionInProgress = true;
      try {
        const r = await this.apiFetch(url, {method:'POST', headers:this.headers()});
        if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        const body = await r.json().catch(() => ({}));
        if (!r.ok || String(body.status || '').trim() !== 'ok') {
          const msg = String(body.error || '').trim() || 'TLS action failed.';
          this.statusHtml = '<span class="text-danger">' + this.escapeHtml(msg) + '</span>';
          return;
        }
        const msg = String(body.message || '').trim() || fallbackMessage;
        this.statusHtml = '<span class="text-success">' + this.escapeHtml(msg) + '</span>';
      } finally {
        this.tlsActionInProgress = false;
      }
    },
    async loadProviders() {
      const r = await this.apiFetch('/admin/api/providers', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      this.providers = await r.json();
      this.renderProviders();
      window.__adminRemoveProvider = (name) => this.removeProvider(name);
      window.__adminEditProvider = (name) => this.openEditProviderModal(name);
      window.__adminSortModels = (col) => this.sortModelsBy(col);
    },
    async loadAccessTokens() {
      const r = await this.apiFetch('/admin/api/access-tokens', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      this.accessTokens = await r.json();
      this.renderAccessTokens();
      this.requiresInitialTokenSetup = !Array.isArray(this.accessTokens) || this.accessTokens.length === 0;
      if (this.requiresInitialTokenSetup) {
        this.activeTab = 'access';
        this.persistActiveTab();
        if (!this.showAddAccessTokenModal) {
          this.openAddAccessTokenModal();
          this.accessTokenStatusHtml = '<span class="text-warning">Create your first access token to enable API access.</span>';
        }
      }
    },
    debouncedLoadConversations() {
      if (this.conversationsDebounceTimer) clearTimeout(this.conversationsDebounceTimer);
      this.conversationsDebounceTimer = setTimeout(() => this.loadConversations(true), 250);
    },
    debouncedLoadLogs() {
      if (this.logDebounceTimer) clearTimeout(this.logDebounceTimer);
      this.logDebounceTimer = setTimeout(() => this.loadLogs(), 250);
    },
    async loadLogSettings() {
      const r = await this.apiFetch('/admin/api/settings/logs', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json().catch(() => ({}));
      this.logMaxLines = Number(body.max_lines || 5000);
    },
    async saveLogSettings() {
      if (this.logSaveInProgress) return;
      const maxLines = Number(this.logMaxLines || 0);
      if (!Number.isFinite(maxLines) || maxLines < 100 || maxLines > 200000) {
        this.logStatusHtml = '<span class="text-danger">Max lines must be between 100 and 200000.</span>';
        return;
      }
      this.logSaveInProgress = true;
      try {
        const r = await this.apiFetch('/admin/api/settings/logs', {
          method:'PUT',
          headers:this.headers(),
          body:JSON.stringify({max_lines: Math.trunc(maxLines)})
        });
        if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        if (!r.ok) {
          const txt = await r.text();
          this.logStatusHtml = '<span class="text-danger">' + this.escapeHtml(txt || 'Failed to save log settings.') + '</span>';
          return;
        }
        this.logStatusHtml = '<span class="text-success">Log settings saved.</span>';
        await this.loadLogSettings();
        await this.loadLogs();
      } finally {
        this.logSaveInProgress = false;
      }
    },
    async loadLogs() {
      const params = new URLSearchParams();
      const level = String(this.logLevelFilter || 'all').trim().toLowerCase();
      const query = String(this.logSearch || '').trim();
      if (level && level !== 'all') params.set('level', level);
      if (query) params.set('q', query);
      params.set('limit', '1500');
      const u = '/admin/api/logs' + (params.toString() ? ('?' + params.toString()) : '');
      const r = await this.apiFetch(u, {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json().catch(() => ({}));
      this.logEntries = Array.isArray(body.entries) ? body.entries : [];
      this.logsPage = 1;
      this.renderLogs();
    },
    async clearLogs() {
      if (!window.confirm('Delete all persisted log entries?')) return;
      const r = await this.apiFetch('/admin/api/logs', {method:'DELETE', headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) {
        const txt = await r.text();
        this.logStatusHtml = '<span class="text-danger">' + this.escapeHtml(txt || 'Failed to clear log.') + '</span>';
        return;
      }
      this.logEntries = [];
      this.renderLogs();
      this.logStatusHtml = '<span class="text-success">Log cleared.</span>';
    },
    renderLogs() {
      const allRows = (this.logEntries || []).map((e) => {
        const level = String(e.level || 'info').trim().toLowerCase();
        const badgeCls =
          level === 'debug' ? 'text-bg-secondary' :
          level === 'info' ? 'text-bg-primary' :
          level === 'warn' ? 'text-bg-warning text-dark' :
          level === 'error' ? 'text-bg-danger' :
          level === 'fatal' ? 'text-bg-dark' : 'text-bg-secondary';
        const ts = this.escapeHtml(this.formatTimestamp(e.timestamp));
        const msg = this.escapeHtml(String(e.message || '').trim());
        return '' +
          '<tr>' +
            '<td class="small text-nowrap">' + ts + '</td>' +
            '<td class="small text-nowrap"><span class="badge ' + badgeCls + '">' + this.escapeHtml(level || 'info') + '</span></td>' +
            '<td class="small"><code style="white-space:pre-wrap;">' + msg + '</code></td>' +
          '</tr>';
      });
      const page = this.paginateRows(allRows, this.logsPage, this.logsPageSize);
      this.logsPage = page.page;
      this.logsPageSize = page.pageSize;
      this.logEntriesShownCount = (page.rows || []).length;
      this.logEntriesTotalCount = page.totalRows;
      this.logEntriesHtml =
        '<table class="table table-sm align-middle mb-0">' +
          '<thead><tr><th style="width:220px;">Time</th><th style="width:90px;">Level</th><th>Message</th></tr></thead>' +
          '<tbody>' + (page.rows.join('') || '<tr><td colspan="3" class="text-body-secondary small">No log entries.</td></tr>') + '</tbody>' +
        '</table>' +
        this.renderPager(page.totalRows, page.page, page.totalPages, page.pageSize, 'Logs');
    },
    formatTimestamp(raw) {
      const s = String(raw || '').trim();
      if (!s) return '';
      const t = new Date(s);
      if (Number.isNaN(t.getTime())) return s;
      return t.toLocaleString();
    },
    async openConversationsSettingsModal() {
      this.conversationsStatusHtml = '';
      await this.loadConversationsSettings();
      this.showConversationsSettingsModal = true;
    },
    closeConversationsSettingsModal() {
      this.showConversationsSettingsModal = false;
    },
    async loadConversationsSettings() {
      const r = await this.apiFetch('/admin/api/settings/conversations', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json().catch(() => ({}));
      this.conversationsSettings = {
        enabled: !!body.enabled,
        max_items: Number(body.max_items || 5000),
        max_age_days: Number(body.max_age_days || 30)
      };
    },
    async saveConversationsSettings() {
      if (this.conversationsSaveInProgress) return;
      const maxItems = Number(this.conversationsSettings.max_items || 0);
      const maxAgeDays = Number(this.conversationsSettings.max_age_days || 0);
      if (!Number.isFinite(maxItems) || maxItems < 100 || maxItems > 200000) {
        this.conversationsStatusHtml = '<span class="text-danger">Max items must be between 100 and 200000.</span>';
        return;
      }
      if (!Number.isFinite(maxAgeDays) || maxAgeDays < 1) {
        this.conversationsStatusHtml = '<span class="text-danger">Max age days must be at least 1.</span>';
        return;
      }
      this.conversationsSaveInProgress = true;
      try {
        const payload = {
          enabled: !!this.conversationsSettings.enabled,
          max_items: Math.trunc(maxItems),
          max_age_days: Math.trunc(maxAgeDays)
        };
        const r = await this.apiFetch('/admin/api/settings/conversations', {method:'PUT', headers:this.headers(), body:JSON.stringify(payload)});
        if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        if (!r.ok) {
          const txt = await r.text();
          this.conversationsStatusHtml = '<span class="text-danger">' + this.escapeHtml(txt || 'Failed to save conversation settings.') + '</span>';
          return;
        }
        this.conversationsStatusHtml = '<span class="text-success">Conversation settings saved.</span>';
        await this.loadConversationsSettings();
        await this.loadConversations(true);
        this.closeConversationsSettingsModal();
      } finally {
        this.conversationsSaveInProgress = false;
      }
    },
    async loadConversations(resetSelection) {
      const params = new URLSearchParams();
      const q = String(this.conversationsSearch || '').trim();
      if (q) params.set('q', q);
      params.set('limit', '5000');
      const url = '/admin/api/conversations' + (params.toString() ? ('?' + params.toString()) : '');
      const r = await this.apiFetch(url, {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json().catch(() => ({}));
      this.conversationThreads = Array.isArray(body.threads) ? body.threads : [];
      this.conversationsPage = 1;
      if (resetSelection && this.conversationThreads.length > 0) {
        this.selectedConversationKey = String(this.conversationThreads[0].conversation_key || '').trim();
      }
      if (!this.selectedConversationKey && this.conversationThreads.length > 0) {
        this.selectedConversationKey = String(this.conversationThreads[0].conversation_key || '').trim();
      }
      if (this.selectedConversationKey && !this.conversationThreads.some((x) => String(x.conversation_key || '').trim() === this.selectedConversationKey)) {
        this.selectedConversationKey = this.conversationThreads.length ? String(this.conversationThreads[0].conversation_key || '').trim() : '';
      }
      this.renderConversationsList();
      if (this.selectedConversationKey) {
        await this.loadConversationDetail(this.selectedConversationKey);
      } else {
        this.conversationRecords = [];
        this.conversationDetailHtml = '<div class="small text-body-secondary">No conversations found for current filters.</div>';
      }
    },
    async loadConversationDetail(conversationKey) {
      const key = String(conversationKey || '').trim();
      if (!key) return;
      const r = await this.apiFetch('/admin/api/conversations/' + encodeURIComponent(key), {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      const body = await r.json().catch(() => ({}));
      this.selectedConversationKey = key;
      this.conversationRecords = Array.isArray(body.records) ? body.records : [];
      this.renderConversationsList();
      this.renderConversationDetail();
    },
    renderConversationsList() {
      const allRows = (this.conversationThreads || []).map((t) => {
        const key = String(t.conversation_key || '').trim();
        const selected = key && key === this.selectedConversationKey;
        const cls = selected ? 'border-primary bg-primary-subtle' : 'border';
        const provider = this.escapeHtml(t.provider || '-');
        const model = this.escapeHtml(t.model || '-');
        const keyName = this.escapeHtml(t.api_key_name || '-');
        const remote = this.escapeHtml(t.remote_ip || '-');
        const updated = this.escapeHtml(this.formatRelativeAge(t.last_at || ''));
        const preview = this.escapeHtml(t.last_preview || '');
        return '' +
          '<button type=\"button\" class=\"btn w-100 text-start p-2 mb-2 ' + cls + '\" data-conversation-key=\"' + this.escapeHtml(key) + '\" onclick=\"window.__adminOpenConversation(this.getAttribute(\\\"data-conversation-key\\\"))\">' +
            '<div class=\"fw-semibold small\">' + provider + ' · ' + model + '</div>' +
            '<div class=\"small text-body-secondary\">' + keyName + ' · ' + remote + ' · ' + updated + '</div>' +
            '<div class=\"small text-body-secondary\">' + preview + '</div>' +
          '</button>';
      });
      const page = this.paginateRows(allRows, this.conversationsPage, this.conversationsPageSize);
      this.conversationsPage = page.page;
      this.conversationsPageSize = page.pageSize;
      this.conversationsListHtml = page.rows.join('') || '<div class=\"small text-body-secondary\">No conversations yet.</div>';
      this.conversationsPagerHtml = this.renderPager(page.totalRows, page.page, page.totalPages, page.pageSize, 'Conversations');
      window.__adminOpenConversation = (key) => this.loadConversationDetail(key);
    },
    renderConversationDetail() {
      const records = this.conversationRecords || [];
      if (!records.length) {
        this.conversationDetailHtml = '<div class=\"small text-body-secondary\">No messages captured for this conversation.</div>';
        return;
      }
      const rows = records.map((rec) => {
        const ts = this.escapeHtml(this.formatRelativeAge(rec.created_at || ''));
        const status = this.escapeHtml(String(rec.status_code || ''));
        const latency = this.escapeHtml(String(rec.latency_ms || 0) + 'ms');
        const sent = this.renderMarkdown(rec.request_text_markdown || '');
        const recv = this.renderMarkdown(rec.response_text_markdown || '');
        const reqPayload = this.escapeHtml(JSON.stringify(rec.request_payload || {}, null, 2));
        const respPayload = this.escapeHtml(JSON.stringify(rec.response_payload || {}, null, 2));
        const reqHeaders = this.escapeHtml(JSON.stringify(rec.request_headers || {}, null, 2));
        const respHeaders = this.escapeHtml(JSON.stringify(rec.response_headers || {}, null, 2));
        return '' +
          '<div class=\"border rounded p-2 mb-2\">' +
            '<div class=\"small text-body-secondary mb-2\">' + ts + ' · status ' + status + ' · ' + latency + '</div>' +
            '<div class=\"row g-2\">' +
              '<div class=\"col-md-6\"><div class=\"fw-semibold small mb-1\">Sent</div><div class=\"small\">' + sent + '</div></div>' +
              '<div class=\"col-md-6\"><div class=\"fw-semibold small mb-1\">Received</div><div class=\"small\">' + recv + '</div></div>' +
            '</div>' +
            '<details class=\"mt-2\"><summary class=\"small\">Request payload / headers</summary><pre class=\"small mt-1 mb-1\"><code>' + reqPayload + '</code></pre><pre class=\"small mb-0\"><code>' + reqHeaders + '</code></pre></details>' +
            '<details class=\"mt-2\"><summary class=\"small\">Response payload / headers</summary><pre class=\"small mt-1 mb-1\"><code>' + respPayload + '</code></pre><pre class=\"small mb-0\"><code>' + respHeaders + '</code></pre></details>' +
          '</div>';
      });
      this.conversationDetailHtml = rows.join('');
    },
    renderMarkdown(input) {
      const md = String(input || '').trim();
      if (!md) return '<span class=\"text-body-secondary\">(empty)</span>';
      try {
        let html = '';
        if (window.marked && typeof window.marked.parse === 'function') {
          html = window.marked.parse(md, {gfm:true, breaks:true});
        } else {
          html = this.escapeHtml(md).replaceAll('\\n', '<br>');
        }
        if (window.DOMPurify && typeof window.DOMPurify.sanitize === 'function') {
          html = window.DOMPurify.sanitize(html);
        }
        return html;
      } catch (_) {
        return this.escapeHtml(md).replaceAll('\\n', '<br>');
      }
    },
    async saveAccessToken() {
      if (String(this.accessTokenDraft.id || '').trim()) {
        await this.saveAccessTokenEdit();
        return;
      }
      const name = String(this.accessTokenDraft.name || '').trim();
      if (!name) {
        this.accessTokenStatusHtml = '<span class="text-danger">Name is required.</span>';
        return;
      }
      const key = String(this.accessTokenDraft.key || '').trim();
      if (!key) {
        this.accessTokenStatusHtml = '<span class="text-danger">Key is required.</span>';
        return;
      }
      const role = String(this.accessTokenDraft.role || '').trim().toLowerCase();
      if (role !== 'admin' && role !== 'keymaster' && role !== 'inferrer') {
        this.accessTokenStatusHtml = '<span class="text-danger">Type is required.</span>';
        return;
      }
      const expiresAt = this.expiryPresetToRFC3339(this.accessTokenDraft.expiry_preset);
      const payload = {
        name,
        key,
        role,
        expires_at: expiresAt,
        quota: this.buildAccessTokenQuotaPayload()
      };
      if (this.accessTokenDraft.quota_enabled && !payload.quota) {
        this.accessTokenStatusHtml = '<span class="text-danger">Set at least one quota limit.</span>';
        return;
      }
      const r = await this.apiFetch('/admin/api/access-tokens', {method:'POST', headers:this.headers(), body:JSON.stringify(payload)});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) {
        const txt = await r.text();
        this.accessTokenStatusHtml = '<span class="text-danger">' + this.escapeHtml(txt || 'Failed to add key') + '</span>';
        return;
      }
      this.closeAddAccessTokenModal();
      this.accessTokenStatusHtml = '<span class="text-success">Key added.</span>';
      await this.loadAccessTokens();
    },
    async saveAccessTokenEdit() {
      const id = String(this.accessTokenDraft.id || '').trim();
      if (!id) return;
      const name = String(this.accessTokenDraft.name || '').trim();
      if (!name) {
        this.accessTokenStatusHtml = '<span class="text-danger">Name is required.</span>';
        return;
      }
      const role = String(this.accessTokenDraft.role || '').trim().toLowerCase();
      if (role !== 'admin' && role !== 'keymaster' && role !== 'inferrer') {
        this.accessTokenStatusHtml = '<span class="text-danger">Type is required.</span>';
        return;
      }
      const preset = String(this.accessTokenDraft.expiry_preset || 'never').trim();
      const expiresAt = preset === 'custom'
        ? String(this.accessTokenDraft.expires_at || '').trim()
        : this.expiryPresetToRFC3339(preset);
      const payload = {
        name,
        role,
        expires_at: expiresAt,
        quota: this.buildAccessTokenQuotaPayload()
      };
      if (this.accessTokenDraft.quota_enabled && !payload.quota) {
        this.accessTokenStatusHtml = '<span class="text-danger">Set at least one quota limit.</span>';
        return;
      }
      const r = await this.apiFetch('/admin/api/access-tokens/' + encodeURIComponent(id), {method:'PUT', headers:this.headers(), body:JSON.stringify(payload)});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) {
        const txt = await r.text();
        this.accessTokenStatusHtml = '<span class="text-danger">' + this.escapeHtml(txt || 'Failed to update key') + '</span>';
        return;
      }
      this.closeAddAccessTokenModal();
      this.accessTokenStatusHtml = '<span class="text-success">Key updated.</span>';
      await this.loadAccessTokens();
    },
    async removeAccessToken(id) {
      const tokenId = String(id || '').trim();
      if (!tokenId) return;
      if (!window.confirm('Delete this access token?')) return;
      const r = await this.apiFetch('/admin/api/access-tokens/' + encodeURIComponent(tokenId), {method:'DELETE', headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) {
        const txt = await r.text();
        this.accessTokenStatusHtml = '<span class="text-danger">' + this.escapeHtml(txt || 'Failed to delete token') + '</span>';
        return;
      }
      this.accessTokenStatusHtml = '<span class="text-success">Token deleted.</span>';
      await this.loadAccessTokens();
    },
    openEditProviderModal(name) {
      const row = (this.providers || []).find((p) => String(p.name || '') === String(name || ''));
      if (!row) return;
      this.resetDraft();
      this.editingProviderName = String(row.name || '').trim();
      this.selectedPreset = String(row.provider_type || '').trim();
      if (!(this.popularProviders || []).some((p) => p.name === this.selectedPreset)) {
        this.selectedPreset = '';
      }
      this.draft.name = String(row.name || '').trim();
      this.draft.provider_type = String(row.provider_type || '').trim();
      this.draft.base_url = String(row.base_url || '').trim();
      this.draft.enabled = true;
      this.draft.timeout_seconds = Number(row.timeout_seconds || 0) > 0 ? Number(row.timeout_seconds) : '';
      this.overrideProviderSettings = true;
      this.authMode = 'api_key';
      this.addProviderStep = 'api_key';
      const preset = this.getSelectedPreset();
      this.presetInfoHtml = preset ? this.renderPresetInfo(preset) : '';
      this.modalStatusHtml = '<span class="text-body-secondary">Edit provider settings. Re-enter credentials to update them.</span>';
      this.showAddProviderModal = true;
    },
    async loadModelsCatalog(firstLoad, forceRefresh) {
      if (firstLoad && this.modelsCatalog.length === 0) this.modelsInitialLoadInProgress = true;
      const u = forceRefresh ? '/admin/api/models?refresh=1' : '/admin/api/models';
      const r = await this.apiFetch(u, {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) {
        if (firstLoad) this.modelsInitialLoadInProgress = false;
        return;
      }
      const body = await r.json();
      this.modelsCatalog = body.data || [];
      this.modelsInitialized = true;
      if (firstLoad || forceRefresh) this.modelsPage = 1;
      this.renderModelsCatalog();
      this.renderModelsFreshness(body.fetched_at, body.pricing_cache_updated_at);
      this.persistModelsToCache();
      if (firstLoad) this.modelsInitialLoadInProgress = false;
    },
    async refreshPricingAndModels() {
      if (this.modelsRefreshInProgress) return;
      this.modelsRefreshInProgress = true;
      try {
        await this.loadModelsCatalog(false, true);
        await this.loadProviders();
      } finally {
        this.modelsRefreshInProgress = false;
      }
    },
    async loadPopularProviders() {
      const r = await this.apiFetch('/admin/api/providers/popular', {headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      if (!r.ok) return;
      this.popularProviders = await r.json();
    },
    buildProviderPayload() {
      const payload = {name: String(this.draft.name || '').trim(), enabled: !!this.draft.enabled};
      if (this.selectedPreset) {
        payload.provider_type = String(this.selectedPreset || '').trim();
      } else if (String(this.draft.provider_type || '').trim()) {
        payload.provider_type = String(this.draft.provider_type || '').trim();
      }
      if (this.authMode === 'oauth') {
        payload.auth_token = String(this.draft.auth_token || '').trim();
        payload.refresh_token = String(this.draft.refresh_token || '').trim();
        payload.token_expires_at = String(this.draft.token_expires_at || '').trim();
        payload.account_id = String(this.draft.account_id || '').trim();
      } else if (this.authMode === 'device' && this.selectedPresetSupportsDeviceAuth()) {
        payload.auth_token = String(this.draft.auth_token || '').trim();
        payload.refresh_token = String(this.draft.refresh_token || '').trim();
        payload.token_expires_at = String(this.draft.token_expires_at || '').trim();
        payload.account_id = String(this.draft.account_id || '').trim();
        payload.device_auth_url = String(this.draft.device_auth_url || '').trim();
      } else {
        payload.api_key = String(this.draft.api_key || '').trim();
      }
      if (this.authMode === 'oauth') {
        payload.base_url = String(this.draft.base_url || '').trim();
        const tout = Number(this.draft.timeout_seconds || 0);
        payload.timeout_seconds = (Number.isFinite(tout) && tout > 0) ? tout : 60;
      } else if (this.selectedPresetRequiresBaseURLInput() || this.overrideProviderSettings || !this.selectedPreset) {
        payload.base_url = String(this.draft.base_url || '').trim();
        const tout = Number(this.draft.timeout_seconds || 0);
        if (Number.isFinite(tout) && tout > 0) payload.timeout_seconds = tout;
      }
      return payload;
    },
    async testProvider() {
      const payload = this.buildProviderPayload();
      const r = await this.apiFetch('/admin/api/providers/test', {method:'POST', headers:this.headers(), body:JSON.stringify(payload)});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      const body = await r.json().catch(() => ({}));
      if (r.ok && body.ok) {
        this.modalStatusHtml = '<span class="text-success">Connection successful. Models found: ' + Number(body.model_count || 0) + '</span>';
        return;
      }
      const err = this.escapeHtml(body.error || 'Connection failed.');
      this.modalStatusHtml = '<span class="text-danger">' + err + '</span>';
    },
    async saveProvider() {
      const payload = this.buildProviderPayload();
      const isEdit = String(this.editingProviderName || '').trim() !== '';
      const endpoint = isEdit ? ('/admin/api/providers/' + encodeURIComponent(this.editingProviderName)) : '/admin/api/providers';
      const method = isEdit ? 'PUT' : 'POST';
      if (this.authMode === 'oauth') {
        if (!String(payload.auth_token || '').trim()) {
          this.modalStatusHtml = '<span class="text-danger">Run browser OAuth login first.</span>';
          return;
        }
        const r = await this.apiFetch(endpoint, {method, headers:this.headers(), body:JSON.stringify(payload)});
        if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
        this.statusHtml = r.ok
          ? ('<span class="text-success">Provider ' + (isEdit ? 'updated' : 'added') + '.</span>')
          : ('<span class="text-danger">Failed to ' + (isEdit ? 'update' : 'add') + ' provider.</span>');
        if (!r.ok) return;
        this.closeAddProviderModal();
        this.loadProviders();
        return;
      }
      this.modalStatusHtml = '<span class="text-body-secondary">Testing provider credentials...</span>';
      const tr = await this.apiFetch('/admin/api/providers/test', {method:'POST', headers:this.headers(), body:JSON.stringify(payload)});
      if (tr.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      const tb = await tr.json().catch(() => ({}));
      if (!(tr.ok && tb.ok)) {
        const err = this.escapeHtml(tb.error || 'Provider authentication failed.');
        this.modalStatusHtml = '<span class="text-danger">' + err + '</span>';
        return;
      }
      const r = await this.apiFetch(endpoint, {method, headers:this.headers(), body:JSON.stringify(payload)});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      this.statusHtml = r.ok
        ? ('<span class="text-success">Provider ' + (isEdit ? 'updated' : 'added') + '.</span>')
        : ('<span class="text-danger">Failed to ' + (isEdit ? 'update' : 'add') + ' provider.</span>');
      if (!r.ok) return;
      this.closeAddProviderModal();
      this.loadProviders();
    },
    async removeProvider(name) {
      const providerName = String(name || '').trim();
      if (!providerName) return;
      if (!window.confirm('Delete provider "' + providerName + '"? This cannot be undone.')) return;
      const r = await this.apiFetch('/admin/api/providers/'+encodeURIComponent(providerName), {method:'DELETE', headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      this.statusHtml = r.ok ? '<span class="text-success">Provider removed.</span>' : '<span class="text-danger">Failed to remove provider.</span>';
      if (!r.ok) return;
      this.loadProviders();
    },
    async refreshModels() {
      const r = await this.apiFetch('/admin/api/models/refresh', {method:'POST', headers:this.headers()});
      if (r.status === 401) { window.location = '/admin/login?next=/admin'; return; }
      this.statusHtml = r.ok ? '<span class="text-success">Model refresh completed.</span>' : '<span class="text-danger">Model refresh failed.</span>';
      if (r.ok && this.activeTab === 'models') {
        this.loadModelsCatalog(false);
      }
    }
  }
}
