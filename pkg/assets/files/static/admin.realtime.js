(function () {
  function startRealtimeUpdates() {
    this.configureStatusUpdates();
    window.addEventListener('beforeunload', () => this.stopRealtimeUpdates());
  }

  function realtimePaused() {
    return !!this.realtimePausedForReload;
  }

  function stopRealtimeUpdates() {
    if (this.wsReconnectTimer) {
      clearTimeout(this.wsReconnectTimer);
      this.wsReconnectTimer = null;
    }
    if (this.ws) {
      try { this.ws.close(); } catch (_) {}
      this.ws = null;
    }
  }

  function isStatusRealtimeMode() {
    return this.statusUpdateSpeed === 'realtime';
  }

  function statusUpdateIntervalMs() {
    const v = String(this.statusUpdateSpeed || '').trim();
    if (v === '2s') return 2000;
    if (v === '10s') return 10000;
    if (v === '30s') return 30000;
    if (v === '1m') return 60 * 1000;
    if (v === '5m') return 5 * 60 * 1000;
    if (v === '15m') return 15 * 60 * 1000;
    if (v === 'disabled') return -1;
    return 0;
  }

  function configureStatusUpdates() {
    if (realtimePaused.call(this)) return;
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
    this.connectRealtimeWebSocket();
    if (typeof this.sendWSSubscription === 'function') this.sendWSSubscription();
    this.handleRealtimeRefresh(true);
  }

  function ensureFallbackPolling() {
    // websocket-only updates: no HTTP polling fallback
  }

  function clearFallbackPolling() {
    // websocket-only updates: no HTTP polling fallback
  }

  function scheduleRealtimeReconnect() {
    if (realtimePaused.call(this)) return;
    if (this.statusUpdateIntervalMs() < 0) return;
    if (this.wsReconnectTimer) return;
    const delay = Math.min(this.wsBackoffMs, 30000);
    this.wsReconnectTimer = setTimeout(() => {
      this.wsReconnectTimer = null;
      this.connectRealtimeWebSocket();
    }, delay);
    this.wsBackoffMs = Math.min(this.wsBackoffMs * 2, 30000);
  }

  function connectRealtimeWebSocket() {
    if (realtimePaused.call(this)) return;
    if (this.statusUpdateIntervalMs() < 0) return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) return;
    const wsProto = window.location.protocol === 'https:' ? 'wss://' : 'ws://';
    const wsURL = wsProto + window.location.host + '/admin/ws';
    try {
      const ws = new WebSocket(wsURL);
      this.ws = ws;
      ws.onopen = () => {
        this.wsBackoffMs = 1000;
        this.wsFailureCount = 0;
        if (typeof this.sendWSSubscription === 'function') this.sendWSSubscription();
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
        if (msg.type === 'changed') {
          this.handleRealtimeChange(String(msg.scope || '').trim().toLowerCase());
          return;
        }
        if (msg.type === 'conversation_append' && this.activeTab === 'conversations') {
          this.loadConversations(false);
        }
      };
      ws.onerror = () => {
        this.noteWSFailure();
      };
      ws.onclose = () => {
        this.noteWSFailure();
        this.scheduleRealtimeReconnect();
      };
    } catch (_) {
      this.noteWSFailure();
      this.scheduleRealtimeReconnect();
    }
  }

  function sendWSSubscription() {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(JSON.stringify({
        type: 'subscribe',
        update_speed: String(this.statusUpdateSpeed || 'realtime').trim() || 'realtime'
      }));
    } catch (_) {}
  }

  function noteWSFailure() {
    if (realtimePaused.call(this)) return;
    this.wsFailureCount = Number(this.wsFailureCount || 0) + 1;
    if (this.wsFailureCount >= 8 && !this.reloadingForRuntimeUpdate && this.statusUpdateIntervalMs() >= 0) {
      this.statusHtml = '<span class="text-warning">Realtime connection unstable. Reloading admin page to recover.</span>';
      this.reloadForRuntimeUpdate();
    }
  }

  function handleRealtimeRefresh(forceStats) {
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
    } else if (this.activeTab === 'network') {
      if (typeof this.refreshNetworkTabFromConfig === 'function') this.refreshNetworkTabFromConfig();
      else {
        this.loadNetworkSettings();
        this.loadTLSSettings();
      }
    }
  }

  function handleRealtimeChange(scope) {
    const s = String(scope || '').trim().toLowerCase();
    if (s === 'stats') {
      if (this.activeTab === 'status' || this.activeTab === 'quota' || this.activeTab === 'access') {
        this.loadStats(true);
      }
      return;
    }
    if (s === 'providers') {
      if (this.activeTab === 'providers') this.loadProviders();
      return;
    }
    if (s === 'access') {
      if (this.activeTab === 'access') {
        this.loadAccessTokens();
        this.loadSecuritySettings();
        this.loadTLSSettings();
      }
      return;
    }
    if (s === 'models') {
      if (this.activeTab === 'models') this.loadModelsCatalog(false);
      return;
    }
    if (s === 'conversations') {
      if (this.activeTab === 'conversations') this.loadConversations(false);
      return;
    }
    if (s === 'log') {
      if (this.activeTab === 'log') this.loadLogs();
      return;
    }
    if (s === 'network') {
      if (this.activeTab === 'network') {
        if (typeof this.refreshNetworkTabFromConfig === 'function') this.refreshNetworkTabFromConfig();
        else {
          this.loadNetworkSettings();
          this.loadTLSSettings();
        }
      }
      return;
    }
    this.handleRealtimeRefresh(true);
  }

  window.AdminRealtime = {
    startRealtimeUpdates,
    stopRealtimeUpdates,
    isStatusRealtimeMode,
    statusUpdateIntervalMs,
    configureStatusUpdates,
    ensureFallbackPolling,
    clearFallbackPolling,
    scheduleRealtimeReconnect,
    connectRealtimeWebSocket,
    sendWSSubscription,
    noteWSFailure,
    handleRealtimeRefresh,
    handleRealtimeChange
  };
})();
