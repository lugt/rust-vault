// Clipboard write + auto-clear after 30s.
export async function copyText(text) {
  if (!text) return;
  await navigator.clipboard.writeText(text);
  setTimeout(async () => {
    try {
      await navigator.clipboard.writeText("");
    } catch {}
  }, 30_000);
}
