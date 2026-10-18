// Vortex-RE demonstration fixture: a small UI component.
export function createButton(label, theme) {
  const button = document.createElement('button');
  button.textContent = label || 'ok';
  if (theme && theme.accent) {
    button.style.color = theme.accent;
  }
  return button;
}
