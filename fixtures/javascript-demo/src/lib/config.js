// Vortex-RE demonstration fixture: config loader.
'use strict';

const defaults = require('./defaults.json');

function loadConfig() {
  return {
    appName: defaults.appName,
    retries: defaults.retries,
    token: 'demo-not-a-real-secret',
  };
}

module.exports = { loadConfig };
