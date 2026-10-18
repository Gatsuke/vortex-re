// Vortex-RE demonstration fixture: updater stub.
// NOTE: './missing-module.js' is a deliberate unresolved local reference.
'use strict';

const { findAsset } = require('./missing-module.js');

const UPDATE_URL = 'https://updates.example.invalid/feed.json';

function checkForUpdates(url) {
  const feed = url || UPDATE_URL;
  // findAsset is provided by the (missing) module; the reference is the point.
  return findAsset(feed, 'latest');
}

module.exports = { checkForUpdates, UPDATE_URL };
