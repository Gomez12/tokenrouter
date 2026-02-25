(function () {
  function ensureContainer() {
    var el = document.getElementById('admin-toast-container');
    if (el) return el;
    el = document.createElement('div');
    el.id = 'admin-toast-container';
    el.style.position = 'fixed';
    el.style.top = '1rem';
    el.style.right = '1rem';
    el.style.zIndex = '2000';
    el.style.display = 'flex';
    el.style.flexDirection = 'column';
    el.style.gap = '0.5rem';
    el.style.maxWidth = 'min(92vw, 440px)';
    document.body.appendChild(el);
    return el;
  }

  function bgClass(type) {
    if (type === 'success') return 'text-bg-success';
    if (type === 'error') return 'text-bg-danger';
    if (type === 'warning') return 'text-bg-warning text-dark';
    return 'text-bg-primary';
  }

  function show(opts) {
    var o = opts || {};
    var type = String(o.type || 'info').toLowerCase();
    var message = String(o.message || '').trim();
    if (!message) return;
    message = message.replace(/^[a-z]/, function (c) { return c.toUpperCase(); });
    var duration = Number(o.duration || 5200);
    if (!Number.isFinite(duration) || duration < 1800) duration = 1800;

    var container = ensureContainer();
    var toast = document.createElement('div');
    toast.className = 'toast show align-items-center border-0 shadow-sm ' + bgClass(type);
    toast.setAttribute('role', 'status');
    toast.setAttribute('aria-live', 'polite');
    toast.setAttribute('aria-atomic', 'true');

    var body = document.createElement('div');
    body.className = 'd-flex';

    var text = document.createElement('div');
    text.className = 'toast-body';
    text.textContent = message;
    body.appendChild(text);

    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'btn-close btn-close-white me-2 m-auto';
    close.setAttribute('aria-label', 'Close');
    close.addEventListener('click', function () {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    });
    body.appendChild(close);

    toast.appendChild(body);
    container.appendChild(toast);

    window.setTimeout(function () {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }, duration);
  }

  window.AdminToast = {
    show: show
  };
})();
