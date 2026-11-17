// Build script: generates a random derangement, per-person PINs, encrypts each
// assignment with AES-GCM (key derived via PBKDF2 from name+PIN), and writes a
// self-contained index.html. The pairings never appear in plaintext in output.
const fs = require('fs');
const path = require('path');
const { webcrypto } = require('crypto');
const { subtle } = webcrypto;

const NAMES = ['Ілля', 'Наталі', 'Микита', 'Лєра', 'Ганна', 'Вова', 'Валентина'];
// Couples must not gift each other (mutual exclusions).
const COUPLES = [['Ілля', 'Наталі'], ['Ганна', 'Вова'], ['Лєра', 'Микита']];
const partner = {};
for (const [a, b] of COUPLES) { partner[a] = b; partner[b] = a; }
const ITERATIONS = 150000;

const b64 = (buf) => Buffer.from(buf).toString('base64');

// Random derangement: shuffle until nobody is assigned to themselves.
function randInt(n) { return webcrypto.getRandomValues(new Uint32Array(1))[0] % n; }
function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}
function derange(names) {
  while (true) {
    const recipients = shuffle(names);
    const ok = names.every((giver, i) => giver !== recipients[i] && partner[giver] !== recipients[i]);
    if (ok) return recipients;
  }
}

function pin4() {
  return String(1000 + (webcrypto.getRandomValues(new Uint32Array(1))[0] % 9000));
}

async function deriveKey(secret, salt) {
  const km = await subtle.importKey('raw', new TextEncoder().encode(secret), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function main() {
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const recipients = derange(NAMES);

  const pins = {};
  const entries = [];
  for (let i = 0; i < NAMES.length; i++) {
    const giver = NAMES[i];
    const recipient = recipients[i];
    const pin = pin4();
    pins[giver] = pin;
    const key = await deriveKey(`${giver}:${pin}`, salt);
    const iv = webcrypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(recipient));
    entries.push({ name: giver, iv: b64(iv), ct: b64(ct) });
  }

  const data = { salt: b64(salt), iterations: ITERATIONS, entries };
  const template = fs.readFileSync(path.join(__dirname, 'template.html'), 'utf8');
  const html = template.replace('__DATA__', JSON.stringify(data));
  fs.writeFileSync(path.join(__dirname, 'index.html'), html);

  // Print PINs for the organizer to distribute privately. (Not written to any file.)
  console.log('\n=== PINs to distribute privately (do NOT commit) ===');
  for (const name of NAMES) console.log(`${name.padEnd(12)} ${pins[name]}`);
  console.log('\nindex.html written. Pairings are NOT printed and NOT in the HTML in plaintext.');
}

main().catch((e) => { console.error(e); process.exit(1); });
