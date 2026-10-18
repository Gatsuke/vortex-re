// Vortex-RE demonstration fixture (CommonJS main process).
// This file exists to be inspected, not executed.
'use strict';

const { loadConfig } = require('./lib/config.js');
const { checkForUpdates } = require('./lib/updater.js');
const minimist = require('minimist');
const fs = require('fs');

const APP_MARKER = 'VORTEX_DEMO_MARKER';
const UPDATE_URL = 'https://updates.example.invalid/feed.json';

function main(argv) {
  const config = loadConfig();
  const args = minimist(argv.slice(2));
  console.log(`${APP_MARKER} starting with config`, config);
  if (args.check) {
    checkForUpdates(UPDATE_URL);
  }
  return 0;
}

if (require.main === module) {
  process.exit(main(process.argv));
}

module.exports = { main, APP_MARKER };

//# sourceMappingURL=main.js.map
