// Confirmation for destructive forms and click-to-copy. No inline JS (strict CSP).
document.addEventListener('submit', e => {
  const msg = e.target.getAttribute('data-confirm');
  if (msg && !window.confirm(msg)) e.preventDefault();
});
document.addEventListener('click', e => {
  const el = e.target.closest('.copy');
  if (!el || !navigator.clipboard) return;
  navigator.clipboard.writeText(el.innerText.trim()).then(() => {
    el.classList.add('copied');
    setTimeout(() => el.classList.remove('copied'), 800);
  });
});
