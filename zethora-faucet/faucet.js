// The faucet page: one POST to /claim, then the transaction id. All text goes in with textContent, never innerHTML,
// so an error message from the wallet can never inject markup.
const form = document.getElementById('claim-form');
const input = document.getElementById('address');
const button = document.getElementById('claim-button');
const box = document.getElementById('message');

// The same shape the server checks: zethoratest: then the lower-case bech32 payload.
const ADDRESS = /^zethoratest:[a-z0-9]{20,128}$/;

function show(kind, title, text, txid) {
  box.className = 'message show ' + kind;
  box.textContent = '';

  const heading = document.createElement('b');
  heading.textContent = title;
  box.append(heading);

  if (text) {
    const body = document.createElement('p');
    body.textContent = text;
    box.append(body);
  }

  if (txid) {
    const row = document.createElement('div');
    row.className = 'txid';
    const code = document.createElement('code');
    code.textContent = txid;
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'btn ghost';
    copy.textContent = 'Copy TxID';
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(txid);
        copy.textContent = 'Copied';
      } catch {
        copy.textContent = 'Select it above';
      }
    });
    row.append(code, copy);
    box.append(row);
  }
}

async function claim(address) {
  button.disabled = true;
  button.textContent = 'Sending...';
  show('info', 'Sending 1 ZTHR...', 'The faucet wallet is signing the payment. This takes a few seconds.');
  try {
    const response = await fetch('/claim', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address }),
    });
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    if (response.ok && body && body.success) {
      input.value = '';
      show('ok', 'Sent 1 ZTHR.', 'It shows up in your balance after one confirmation. Keep this transaction id:', body.txid);
      return;
    }
    const reason = (body && body.message) || 'The faucet could not send the coins (HTTP ' + response.status + ').';
    show('err', 'Not sent.', reason);
  } catch (e) {
    show('err', 'Not sent.', 'Could not reach the faucet. Is it still running? (' + e.message + ')');
  } finally {
    button.disabled = false;
    button.textContent = 'Claim 1 ZTHR';
  }
}

form.addEventListener('submit', (event) => {
  event.preventDefault();
  const address = input.value.trim();
  if (!address) {
    show('err', 'Type an address first.', 'It looks like zethoratest:... - your wallet prints it with zethora-wallet receive --testnet.');
    input.focus();
    return;
  }
  if (!ADDRESS.test(address)) {
    show('err', 'That is not a Zethora testnet address.', 'It has to start with zethoratest: and hold only lower-case letters and digits. Copy it again from your wallet.');
    input.focus();
    return;
  }
  claim(address);
});
