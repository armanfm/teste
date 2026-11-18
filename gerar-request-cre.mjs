/**
 * Terra Dourada — gera request-cre.json REAL com MetaMask e payload cifrado existente.
 * Executar com `node gerar-request-cre.mjs` dentro de shild-worflow.
 * Nao altera HTML existente, workflow, contrato ou chaves privadas.
 * Nao envia nenhuma transacao: apenas gera o arquivo de requisicao.
 */
import { createServer } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { recoverMessageAddress } from 'viem';

const cwd = process.cwd();
const WORKFLOW_ID = '0x001291a5aff597bd4b076a99ab2bdd0163f7de283f5984de647e17cbfce7eeda';
const AUTHORIZED_SIGNER = '0xAD9eA3D28df2E1D76aB2236aC8C7c86915e4401c';
const GATEWAY = 'https://01.gateway.zone-a.cre.chain.link';
const PORT = 18787;
const filename = resolve(cwd, 'payload.json');
const output = resolve(cwd, 'request-cre.json');
const base64url = value => Buffer.from(value).toString('base64url');
function canonicalJson(value) {
  function sorted(item) {
    if (Array.isArray(item)) return item.map(sorted);
    if (item !== null && typeof item === 'object')
      return Object.fromEntries(Object.entries(item).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([k, child]) => [k, sorted(child)]));
    return item;
  }
  return JSON.stringify(sorted(value));
}
function json(res, status, value) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Access-Control-Allow-Origin': 'http://127.0.0.1:' + PORT });
  res.end(JSON.stringify(value));
}
function validateEnvelope(p) {
  return p && p.version === 1 && /^0x[0-9a-f]{2176}$/i.test(p.kemCiphertext) && /^0x[0-9a-f]{24}$/i.test(p.nonce) && /^0x[0-9a-f]{32,}$/i.test(p.ciphertext);
}
let envelope;
try {
  const data = JSON.parse(await readFile(filename, 'utf8'));
  envelope = data?.input ?? data;
  if (typeof envelope === 'string') envelope = JSON.parse(envelope);
  if (!validateEnvelope(envelope)) throw Error('Envelope ausente ou invalido (version/kemCiphertext/nonce/ciphertext).');
} catch (e) {
  console.error('ERRO: nao foi possivel ler payload.json valido em', filename);
  console.error(e.message);
  process.exit(1);
}
const body = canonicalJson({ id: randomUUID(), jsonrpc: '2.0', method: 'workflows.execute', params: { input: envelope, workflow: { workflowID: WORKFLOW_ID.slice(2) } } });
let challenge;
function freshChallenge() {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'ETH', typ: 'JWT' }));
  const claims = { digest: '0x' + createHash('sha256').update(body).digest('hex'), iss: AUTHORIZED_SIGNER, iat: now, exp: now + 300, jti: randomUUID() };
  challenge = { message: header + '.' + base64url(JSON.stringify(claims)), expiresAt: claims.exp };
  return challenge;
}
let done = false;
const page = `<!doctype html><html lang="pt-BR"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gerar request-cre.json</title><body style="font:16px system-ui;max-width:700px;margin:40px auto;padding:20px"><h2>Terra Dourada — assinatura HTTP do CRE</h2><p>Esta pagina local so solicita uma assinatura MetaMask para criar <code>request-cre.json</code>. Nao envia transferencia, nao le chaves privadas e nao modifica o contrato.</p><p>Conta autorizada no CRE: <code>${AUTHORIZED_SIGNER}</code></p><button id="go" style="padding:12px 16px">Assinar e gerar request-cre.json</button><pre id="out" style="white-space:pre-wrap;word-break:break-word"></pre><script>
document.getElementById('go').onclick=async()=>{const show=s=>document.getElementById('out').textContent=s;try{
if(!window.ethereum)throw Error('MetaMask nao detectada. Abra esta pagina num navegador com MetaMask.');
const accounts=await window.ethereum.request({method:'eth_requestAccounts'});
const issuer=accounts[0];if(!issuer||issuer.toLowerCase()!=='${AUTHORIZED_SIGNER.toLowerCase()}')throw Error('Conta MetaMask atual '+issuer+' nao e a conta autorizada no CRE. Nao e possivel gerar JWT valido com esta conta.');
const c=await (await fetch('/challenge',{cache:'no-store'})).json();
const hex='0x'+Array.from(new TextEncoder().encode(c.message),b=>b.toString(16).padStart(2,'0')).join('');
const signature=await window.ethereum.request({method:'personal_sign',params:[hex,issuer]});
const response=await fetch('/complete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({signature})});
const result=await response.json();if(!response.ok)throw Error(result.error);
show('Arquivo gerado no computador: '+result.file+'\\nJWT valido ate: '+new Date(result.expiresAt*1000).toLocaleString());
}catch(e){show('ERRO: '+e.message)}};
</script></body></html>`;
const server = createServer(async (req, res) => {
  try {
    const origin = req.headers.origin;
    if (origin && origin !== 'http://127.0.0.1:' + PORT) return json(res, 403, { error: 'Origem nao permitida' });
    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'", 'X-Content-Type-Options': 'nosniff' });
      return res.end(page);
    }
    if (req.method === 'GET' && req.url === '/challenge') return json(res, 200, freshChallenge());
    if (req.method === 'POST' && req.url === '/complete') {
      if (!challenge || done) return json(res, 409, { error: 'Assinatura ainda nao solicitada ou arquivo ja gerado' });
      let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 2000) return json(res, 413, { error: 'Assinatura muito grande' }); }
      const signature = JSON.parse(raw).signature;
      if (!/^0x[0-9a-f]{130}$/i.test(signature)) return json(res, 400, { error: 'Assinatura ECDSA invalida' });
      if (Math.floor(Date.now() / 1000) >= challenge.expiresAt) return json(res, 410, { error: 'JWT expirou. Solicite nova assinatura' });
      const recovered = await recoverMessageAddress({ message: challenge.message, signature });
      if (recovered.toLowerCase() !== AUTHORIZED_SIGNER.toLowerCase()) return json(res, 403, { error: 'Assinatura nao pertence a conta autorizada no CRE' });
      const bytes = Buffer.from(signature.slice(2), 'hex');
      if (bytes[64] >= 27) bytes[64] -= 27;
      if (bytes[64] !== 0 && bytes[64] !== 1) return json(res, 400, { error: 'Recovery ID invalido' });
      const token = challenge.message + '.' + bytes.toString('base64url');
      await writeFile(output, JSON.stringify({ url: GATEWAY, headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }, body, expiresAt: challenge.expiresAt }, null, 2) + '\n', { mode: 0o600 });
      done = true;
      json(res, 200, { file: output, expiresAt: challenge.expiresAt });
      console.log('Arquivo gerado:', output, '\nJWT expira em 5 minutos. Nenhuma solicitacao foi enviada ao CRE.');
      return;
    }
    json(res, 404, { error: 'Nao encontrado' });
  } catch (e) { json(res, 500, { error: e.message }); }
});
server.listen(PORT, '127.0.0.1', () => console.log('Abra no navegador com MetaMask: http://127.0.0.1:' + PORT + '\nO arquivo nao sera enviado automaticamente ao CRE.'));
