(function (global) {
  'use strict';

  var API = '/api';
  var csrfToken = null;
  var csrfPromesa = null;

  function obtenerToken(forzar) {
    if (csrfToken && !forzar) {
      return Promise.resolve(csrfToken);
    }
    if (csrfPromesa && !forzar) {
      return csrfPromesa;
    }
    csrfPromesa = fetch(API + '/csrf-token', { credentials: 'same-origin' })
      .then(function (res) {
        return res.json();
      })
      .then(function (data) {
        csrfToken = (data && data.token) || null;
        csrfPromesa = null;
        return csrfToken;
      })
      .catch(function () {
        csrfPromesa = null;
        return null;
      });
    return csrfPromesa;
  }

  function invalidarToken() {
    csrfToken = null;
    csrfPromesa = null;
  }

  function esEscritura(opciones) {
    var metodo = ((opciones && opciones.method) || 'GET').toUpperCase();
    return metodo !== 'GET' && metodo !== 'HEAD' && metodo !== 'OPTIONS';
  }

  function api(url, opciones) {
    var opts = Object.assign({ credentials: 'same-origin' }, opciones || {});

    function ejecutar(token) {
      var headers = Object.assign({}, opts.headers || {});
      if (token) headers['X-CSRF-Token'] = token;
      return fetch(API + url, Object.assign({}, opts, { headers: headers })).then(function (res) {
        return res
          .json()
          .catch(function () {
            return {};
          })
          .then(function (data) {
            return { ok: res.ok, status: res.status, data: data };
          });
      });
    }

    if (!esEscritura(opts) || url === '/auth/login') {
      return ejecutar(null);
    }

    return obtenerToken(false).then(function (token) {
      return ejecutar(token).then(function (resp) {
        if (resp.status === 403 && resp.data && /csrf/i.test(resp.data.error || '')) {
          return obtenerToken(true).then(ejecutar);
        }
        return resp;
      });
    });
  }

  global.OrigenCsrf = {
    obtenerToken: obtenerToken,
    invalidarToken: invalidarToken,
    api: api,
  };
})(window);
