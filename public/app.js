async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

document.getElementById('genKey').addEventListener('click', async () => {
  const res = await fetch('/api/generate-key');
  const data = await res.json();
  document.getElementById('key').value = data.key;
});

document.getElementById('encrypt').addEventListener('click', async () => {
  const key = document.getElementById('key').value.trim();
  const text = document.getElementById('plaintext').value;
  const res = await postJson('/api/encrypt', { text, key });
  if (res.error) document.getElementById('output').textContent = res.error;
  else document.getElementById('ciphertext').value = res.cipherText;
});

document.getElementById('decrypt').addEventListener('click', async () => {
  const key = document.getElementById('key').value.trim();
  const cipherText = document.getElementById('ciphertext').value;
  const res = await postJson('/api/decrypt', { cipherText, key });
  if (res.error) document.getElementById('output').textContent = res.error + (res.details ? ' - ' + res.details : '');
  else document.getElementById('output').textContent = res.text;
});
