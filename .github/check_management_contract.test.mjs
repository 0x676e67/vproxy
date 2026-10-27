// First export both public documents with the current real program:
//   vproxy manage api-spec > session.json
//   vproxy manage api-spec --automation > automation.json
// Then set VPROXY_CONTRACT_SESSION and VPROXY_CONTRACT_AUTOMATION to those files
// and run node --test .github/check_management_contract.test.mjs. No database,
// key, certificate, server or network access is needed. Missing inputs fail;
// these tests never reconstruct the Rust export or silently skip its checks.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { readDocument, structure } from './check_management_contract.mjs';

function fixtures() {
  try {
    const session = process.env.VPROXY_CONTRACT_SESSION;
    const automation = process.env.VPROXY_CONTRACT_AUTOMATION;
    if (!session || !automation) throw new Error();
    return { browser: readDocument(session), automation: readDocument(automation) };
  } catch {
    // Do not echo an input document, a filesystem path or an I/O diagnostic.
    throw new Error('current public contract exports are required');
  }
}

const documents = fixtures();
const operations = '/api/v1/proxy/user-operations';
const execute = `${operations}/{id}/execute`;
const localRuntime = '/api/v1/proxy/runtime/drain';
const targetRuntime = '/api/v1/targets/{id}/proxy/runtime/drain';

function reject(audience, mutate) {
  const document = structuredClone(documents[audience]);
  mutate(document);
  assert.throws(() => structure(document, audience), { message: 'contract check failed' });
}

test('current real exports retain six restricted paths and all selected Session resources', () => {
  const automation = structure(documents.automation, 'automation');
  assert.equal(automation.paths, 6);
  assert.equal(automation.operations, 12);
  assert.doesNotThrow(() => structure(documents.browser, 'browser'));
});

test('a real symlink or Windows junction entry still executes the bounded CLI', () => {
  let root;
  try {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'vproxy-contract-entry-'));
  } catch {
    throw new Error('bounded CLI alias fixture failed');
  }
  const alias = path.join(root, 'entry');
  try {
    fs.symlinkSync(path.dirname(fileURLToPath(import.meta.url)), alias, process.platform === 'win32' ? 'junction' : 'dir');
    const script = path.join(alias, 'check_management_contract.mjs');
    const invoke = automation => spawnSync(process.execPath, [script, process.env.VPROXY_CONTRACT_SESSION, automation], {
      encoding: 'utf8', timeout: 15_000, maxBuffer: 32_768, windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NODE_OPTIONS: '' },
    });
    const passed = invoke(process.env.VPROXY_CONTRACT_AUTOMATION);
    assert.equal(passed.status, 0);
    assert.equal(passed.stderr, '');
    assert.equal(JSON.parse(passed.stdout).status, 'passed');
    const failed = invoke(path.join(root, 'missing.json'));
    assert.equal(failed.status, 1);
    assert.equal(failed.stdout, '');
    assert.deepEqual(JSON.parse(failed.stderr), { status: 'failed', phase: 'bounded-input' });
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error) throw new Error('bounded CLI alias fixture failed');
    throw error;
  } finally {
    // Only unlink this exact alias and remove our now-empty temporary parent.
    // Never recursively traverse the junction into the source directory.
    try {
      if (fs.existsSync(alias)) fs.unlinkSync(alias);
      fs.rmdirSync(root);
    } catch {
      throw new Error('bounded CLI alias cleanup failed');
    }
  }
});

test('automation route, method, scope, body and response capabilities are fixed independently', () => {
  const mutations = [
    document => { delete document.paths[`${operations}/context`]; },
    document => {
      const operation = structuredClone(document.paths[operations].post);
      operation.operationId = 'unexpectedDirectWrite';
      document.paths['/api/v1/proxy/users'].post = operation;
    },
    document => {
      document.paths['/api/v1/proxy/owner'] = {
        post: { ...structuredClone(document.paths[execute].post), operationId: 'unexpectedOwnerWrite' },
      };
    },
    document => { document.paths[operations].post['x-vproxy-required-scope'] = 'users:read'; },
    document => { document.paths[operations].get['x-vproxy-required-scope'] = 'users:*'; },
    document => { document.paths[operations].post.requestBody.content['application/json'].schema.$ref = '#/components/schemas/User'; },
    document => { document.paths[operations].post.responses['201'].content['application/json'].schema.$ref = '#/components/schemas/OperationResult'; },
    document => { delete document.paths[execute].post.requestBody; },
  ];
  for (const mutation of mutations) reject('automation', mutation);
});

test('Bearer-only automation never gains cookie, CSRF, extra headers or sensitive DTOs', () => {
  const mutations = [
    document => { document.components.securitySchemes.Session = { type: 'apiKey', in: 'cookie', name: 'session' }; },
    document => { document.paths[execute].post.security = []; },
    document => { document.components.schemas.OperationInput.properties.password = { type: 'string' }; },
    document => { document.components.schemas.User['x-vproxy-sensitive'] = true; },
    document => { document.components.schemas.User.writeOnly = true; },
    document => { document.components.schemas.Credential = { type: 'object' }; },
    document => { document.components.parameters.UserOperationOrigin.required = true; },
    document => {
      document.paths[operations].post.parameters.push({ name: 'Cookie', in: 'header', schema: { type: 'string' } });
    },
  ];
  for (const mutation of mutations) reject('automation', mutation);
});

test('four non-secret changes and optional non-null node assertion stay strict in both audiences', () => {
  for (const audience of ['browser', 'automation']) {
    const mutations = [
      document => { document.components.schemas.OperationDeleteUserChange.properties.accepting = { type: 'boolean' }; },
      document => { document.components.schemas.OperationCreateUserChange.properties.action.const = 'create_credential'; },
      document => { document.components.schemas.OperationChange.oneOf.pop(); },
      document => { document.components.schemas.OperationInput.required.push('expected_node_id'); },
      document => { document.components.schemas.OperationInput.properties.expected_node_id = { type: ['string', 'null'] }; },
      document => { document.components.schemas.OperationContext.properties.controller_node_id = { type: 'string' }; },
      document => { document.components.schemas.OperationResult.required = document.components.schemas.OperationResult.required.filter(name => name !== 'rejection'); },
      document => { document.components.schemas.OperationResult.properties.payload = { type: 'object' }; },
    ];
    for (const mutation of mutations) reject(audience, mutation);
  }
});

test('HEAD preserves GET authorization, parameters, response status and headers but never data', () => {
  for (const audience of ['browser', 'automation']) {
    const mutations = [
      document => { document.paths[operations].head.responses.default.content = { 'application/json': { schema: { $ref: '#/components/schemas/ApiError' } } }; },
      document => { delete document.paths[operations].head.responses.default.headers['WWW-Authenticate']; },
      document => { document.paths[operations].head.security = []; },
      document => { document.paths[operations].head.parameters = []; },
      document => { delete document.paths[operations].head.responses['200']; },
      document => { document.paths[operations].head.requestBody = structuredClone(document.paths[operations].post.requestBody); },
    ];
    for (const mutation of mutations) reject(audience, mutation);
  }
  reject('automation', document => { document.paths[operations].head['x-vproxy-required-scope'] = 'users:read'; });
});

test('TLS, admission and runtime remain Session-only with explicit CSRF writes and exact resources', () => {
  const mutations = [
    document => { delete document.paths['/api/v1/tls/status']; },
    document => { delete document.paths['/api/v1/proxy/maintenance']; },
    document => { delete document.paths['/api/v1/proxy/runtime']; },
    document => { document.paths['/api/v1/tls/status'].get.security = [{ Automation: [] }]; },
    document => { document.paths[localRuntime].post.security = [{ Session: [] }]; },
    document => { document.paths[localRuntime].post.requestBody.content['application/json'].schema.$ref = '#/components/schemas/MaintenanceInput'; },
    document => {
      const responses = document.paths[localRuntime].post.responses;
      responses['200'] = responses['202'];
      delete responses['202'];
    },
    document => { delete document.paths[targetRuntime].post.responses['502']; },
    document => { document.paths[targetRuntime].post.responses['502'].content['application/json'].schema.$ref = '#/components/schemas/LoginInput'; },
    document => { document.components.schemas.ProxyRuntimeState.properties.phase.enum.push('runtime_stopped'); },
    document => { document.components.schemas.ProxyRuntimeDrainRequest.required.pop(); },
    document => { document.components.schemas.TlsLeafMetadata.properties.pem = { type: 'string' }; },
    document => { document.components.schemas.MaintenanceStatus.required = document.components.schemas.MaintenanceStatus.required.filter(name => name !== 'active_operations'); },
    document => { document.components.schemas.Counter['x-vproxy-maximum-decimal'] = '9223372036854775807'; },
  ];
  for (const mutation of mutations) reject('browser', mutation);
  for (const name of ['TlsIdentityStatus', 'MaintenanceStatus', 'ProxyRuntimeStatus']) {
    reject('automation', document => { document.components.schemas[name] = { type: 'object' }; });
  }
});

test('retained target history is Session-only, bounded, exact-ID and non-secret', () => {
  const list = '/api/v1/targets/{id}/commands/history';
  const exact = `${list}/{job_id}`;
  for (const mutation of [
    document => { delete document.paths[list]; },
    document => { document.paths[list].get.security = [{ Automation: [] }]; },
    document => { document.paths[exact].parameters.pop(); },
    document => { document.paths[list].get.parameters.pop(); },
    document => { document.components.schemas.TargetCommandHistoryEntry.properties.secret = { type: 'string' }; },
    document => { document.components.schemas.TargetCommandHistoryPage.properties.items.maxItems = 128; },
    document => { document.components.schemas.TargetCommandHistoryEntry.required.pop(); },
  ]) reject('browser', mutation);
  reject('automation', document => { document.paths[list] = structuredClone(documents.browser.paths[list]); });
});

test('durable alert review keeps exact transitions, bounded retention and Session authority', () => {
  const events = '/api/v1/alert-events';
  const acknowledge = '/api/v1/alert-episodes/{id}/acknowledge';
  for (const mutation of [
    document => { delete document.paths[events]; },
    document => { document.paths[events].get.parameters.pop(); },
    document => { document.paths[acknowledge].post.security = [{ Session: [] }]; },
    document => { delete document.paths[acknowledge].post.responses['409']; },
    document => { document.components.schemas.AlertHistoryEvent.properties.secret = { type: 'string' }; },
    document => { document.components.schemas.AlertHistoryEpisode.properties.id = { $ref: '#/components/schemas/Id' }; },
    document => { document.components.schemas.AlertHistoryPage.properties.trimmed = { type: 'boolean' }; },
    document => { document.components.schemas.AlertHistoryPage.properties.items.maxItems = 100; },
    document => { document.components.schemas.AlertHistorySummary.properties.retained_episode_count.maximum = 6144; },
    document => { document.components.schemas.AlertHistoryAcknowledgementInput.properties.expected_transition_sequence = { type: 'integer' }; },
  ]) reject('browser', mutation);
  reject('automation', document => { document.paths[events] = structuredClone(documents.browser.paths[events]); });
});
