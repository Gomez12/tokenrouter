(function () {
  function apiFetch(url, opts) {
    const self = this;
    return fetch(url, opts).then((r) => {
      observeRuntimeInstance.call(self, r);
      return r;
    });
  }

  function observeRuntimeInstance(response) {
    if (!response || !response.headers) return;
    const nextID = String(response.headers.get('X-OPP-Instance-ID') || '').trim();
    if (!nextID) return;
    if (!this.runtimeInstanceID) {
      this.runtimeInstanceID = nextID;
      return;
    }
    if (this.runtimeInstanceID !== nextID && !this.reloadingForRuntimeUpdate) {
      this.runtimeInstanceID = nextID;
      reloadForRuntimeUpdate.call(this);
    }
  }

  function reloadForRuntimeUpdate() {
    if (this.reloadingForRuntimeUpdate) return;
    this.reloadingForRuntimeUpdate = true;
    if (typeof this.stopRealtimeUpdates === 'function') {
      try { this.stopRealtimeUpdates(); } catch (_) {}
    }
    try {
      const u = new URL(window.location.href);
      u.searchParams.set('_rt_reload', String(Date.now()));
      window.location.replace(u.toString());
    } catch (_) {
      window.location.reload();
    }
  }

  window.AdminApi = {
    apiFetch,
    observeRuntimeInstance,
    reloadForRuntimeUpdate
  };
})();
