// Vortex-RE demonstration fixture (ESM renderer process).
// NOTE: './theme.js' is a deliberate unresolved local reference.
import { createButton } from './components/button.js';
import DEFAULT_THEME from './theme.js';

export function init(root) {
  const button = createButton('Click me', DEFAULT_THEME);
  root.appendChild(button);
}
