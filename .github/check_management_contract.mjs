#!/usr/bin/env node
// Offline checks of two real exports, not an official complete OpenAPI validator
// or proof that a server accepts every instance described by its JSON Schemas.
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual, parseArgs } from 'node:util';

const MAX_BYTES = 2 * 1024 * 1024;
const DIALECT = 'https://json-schema.org/draft/2020-12/schema';
const METHODS = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']);
const PATH_FIELDS = new Set(['$ref', 'summary', 'description', 'servers', 'parameters']);
// Keep capabilities independent of the supplied exports. A new route, method,
// scope or DTO needs an explicit review here, not a prefix-based exception.
const AUTOMATION_PATHS = {
  '/api/v1/proxy/users': {
    scope: 'users:read', get: { responses: { 200: 'UserPage' }, parameters: ['query:after', 'query:limit', 'query:include_deleted'] },
  },
  '/api/v1/proxy/users/search': {
    scope: 'users:read', get: { responses: { 200: 'UserSearchPage' }, parameters: ['query:mode', 'query:q', 'query:after', 'query:limit', 'query:include_deleted'] },
  },
  '/api/v1/proxy/user-operations': {
    scope: 'users:write', get: { responses: { 200: 'OperationPage' }, parameters: ['query:before', 'query:limit'] },
    post: { request: 'OperationInput', responses: { 201: 'OperationReserved' }, parameters: ['header:Origin'] },
  },
  '/api/v1/proxy/user-operations/context': {
    scope: 'users:write', get: { responses: { 200: 'OperationContext' }, parameters: [] },
  },
  '/api/v1/proxy/user-operations/{id}': {
    scope: 'users:write', get: { responses: { 200: 'OperationResult' }, parameters: [] },
  },
  '/api/v1/proxy/user-operations/{id}/execute': {
    scope: 'users:write', post: { request: 'OperationInput', responses: { 200: 'OperationTerminal' }, parameters: ['header:Origin'] },
  },
};
const AUTOMATION_SCHEMAS = new Set([
  'ApiError', 'Id', 'NullableId', 'Revision', 'Name', 'Protocol',
  'User', 'UserPage', 'UserSearchPage', 'UserSearchCursor',
  'UserNameInput', 'UserProtocolsInput', 'OperationContext', 'OperationChange',
  'OperationCreateUserChange', 'OperationUpdateUserChange',
  'OperationSetUserActiveChange', 'OperationDeleteUserChange', 'OperationInput',
  'OperationRejection', 'OperationResult', 'OperationReserved', 'OperationTerminal', 'OperationPage',
]);
const SESSION_PATHS = {
  '/api/v1/alert-events': { get: { responses: { 200: 'AlertHistoryPage' }, parameters: ['query:before', 'query:limit', 'query:origin_node_id', 'query:episode_id'] } },
  '/api/v1/alert-events/{id}': { get: { responses: { 200: 'AlertHistoryEvent' } } },
  '/api/v1/alert-episodes/{id}': { get: { responses: { 200: 'AlertHistoryEpisode' } } },
  '/api/v1/alert-episodes/{id}/acknowledge': { post: { request: 'AlertHistoryAcknowledgementInput', responses: { 200: 'AlertHistoryEpisode' }, errors: ['409'] } },
  '/api/v1/alert-summary': { get: { responses: { 200: 'AlertHistorySummary' } } },
  '/api/v1/targets/{id}/commands/history': { get: { responses: { 200: 'TargetCommandHistoryPage' }, parameters: ['query:before', 'query:limit'] } },
  '/api/v1/targets/{id}/commands/history/{job_id}': { get: { responses: { 200: 'TargetCommandHistoryEntry' } } },
  '/api/v1/tls/status': { get: { responses: { 200: 'TlsIdentityStatus' } } },
  '/api/v1/proxy/maintenance': {
    get: { responses: { 200: 'MaintenanceStatus' } },
    post: { request: 'MaintenanceInput', responses: { 200: 'MaintenanceChange' } },
  },
  '/api/v1/targets/{id}/proxy/maintenance': { get: { responses: { 200: 'MaintenanceStatus' } } },
  '/api/v1/targets/{id}/maintenance/commands/refresh': {
    post: { request: 'TargetJobInput', responses: { 200: 'TargetJob' } },
  },
  '/api/v1/targets/{id}/maintenance/commands': {
    post: { request: 'MaintenanceCommandInput', responses: { 200: 'MaintenanceDeliveredSubmission', 202: 'MaintenancePendingSubmission' } },
  },
  '/api/v1/proxy/runtime': { get: { responses: { 200: 'ProxyRuntimeStatus' } } },
  '/api/v1/proxy/runtime/drain': { post: { request: 'ProxyRuntimeDrainRequest', responses: { 202: 'ProxyRuntimeStatus' }, errors: ['409'] } },
  '/api/v1/proxy/runtime/drains/{runtime_id}/{request_id}': { get: { responses: { 200: 'ProxyRuntimeStatus' }, errors: ['404'] } },
  '/api/v1/targets/{id}/proxy/runtime': { get: { responses: { 200: 'ProxyRuntimeStatus' }, errors: ['502'] } },
  '/api/v1/targets/{id}/proxy/runtime/drain': { post: { request: 'TargetProxyRuntimeDrainInput', responses: { 202: 'ProxyRuntimeStatus' }, errors: ['409', '502'] } },
  '/api/v1/targets/{id}/proxy/runtime/drains/{runtime_id}/{request_id}': { get: { responses: { 200: 'ProxyRuntimeStatus' }, errors: ['502'] } },
};
const USER_ACTIONS = ['create_user', 'update_user', 'set_user_active', 'delete_user'];
const ID = 'AAAAAAAAAAAAAAAAAAAAAA';
const OTHER_ID = 'AQEBAQEBAQEBAQEBAQEBAQ';
let phase = 'arguments';

function requireCondition(value) {
  if (!value) throw new Error('contract check failed');
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Read at most MAX_BYTES + 1, even if a regular file grows after the stat.
// A symlink, special file, changed identity or concurrently changed file fails.
export function readDocument(filename) {
  const before = fs.lstatSync(filename, { bigint: true });
  requireCondition(before.isFile() && !before.isSymbolicLink());
  requireCondition(before.size > 0n && before.size <= BigInt(MAX_BYTES));
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const opened = fs.fstatSync(descriptor, { bigint: true });
    requireCondition(opened.isFile() && opened.dev === before.dev && opened.ino === before.ino);
    const buffer = Buffer.alloc(MAX_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const received = fs.readSync(descriptor, buffer, length, buffer.length - length, null);
      if (received === 0) break;
      length += received;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    requireCondition(length > 0 && length <= MAX_BYTES && BigInt(length) === opened.size);
    requireCondition(after.size === opened.size && after.mtimeNs === opened.mtimeNs && after.ctimeNs === opened.ctimeNs);
    const document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length)));
    requireCondition(object(document));
    return document;
  } finally {
    fs.closeSync(descriptor);
  }
}

function walk(value, visit) {
  const pending = [{ value, depth: 0 }];
  let count = 0;
  while (pending.length !== 0) {
    const next = pending.pop();
    requireCondition(++count <= 100_000 && next.depth <= 64);
    if (next.value === null || typeof next.value !== 'object') continue;
    visit(next.value);
    for (const child of Object.values(next.value)) pending.push({ value: child, depth: next.depth + 1 });
  }
}

function localReference(document, reference) {
  requireCondition(typeof reference === 'string' && reference.startsWith('#/'));
  const pointer = decodeURIComponent(reference.slice(2));
  let value = document;
  for (const encoded of pointer.split('/')) {
    requireCondition(!/~(?![01])/u.test(encoded));
    const name = encoded.replaceAll('~1', '/').replaceAll('~0', '~');
    requireCondition(value !== null && typeof value === 'object' && Object.hasOwn(value, name));
    value = value[name];
  }
  return value;
}

function dereference(document, value) {
  const seen = new Set();
  while (object(value) && Object.hasOwn(value, '$ref')) {
    requireCondition(!seen.has(value.$ref) && seen.size < 32);
    seen.add(value.$ref);
    value = localReference(document, value.$ref);
  }
  requireCondition(object(value));
  return value;
}

function security(document, value) {
  requireCondition(Array.isArray(value));
  const schemes = document.components.securitySchemes ?? {};
  for (const alternative of value) {
    requireCondition(object(alternative) && Object.keys(alternative).length !== 0);
    for (const [name, scopes] of Object.entries(alternative)) {
      requireCondition(Object.hasOwn(schemes, name));
      // This repository exports only apiKey and HTTP bearer schemes, not OAuth.
      requireCondition(Array.isArray(scopes) && scopes.length === 0);
      requireCondition(['apiKey', 'http'].includes(schemes[name].type));
    }
  }
}

function parameters(document, values) {
  requireCondition(Array.isArray(values));
  const parameters = new Map();
  for (const value of values) {
    const parameter = dereference(document, value);
    requireCondition(typeof parameter.name === 'string' && parameter.name.length !== 0);
    requireCondition(['path', 'query', 'header', 'cookie'].includes(parameter.in));
    requireCondition(Object.hasOwn(parameter, 'schema'));
    if (parameter.in === 'path') requireCondition(parameter.required === true);
    const key = `${parameter.in}:${parameter.name}`;
    requireCondition(!parameters.has(key));
    parameters.set(key, parameter);
  }
  return parameters;
}

function equalSet(actual, expected) {
  requireCondition(isDeepStrictEqual([...actual].sort(), [...expected].sort()));
}

function exactSecurity(operation, names) {
  requireCondition(Array.isArray(operation.security) && operation.security.length === 1);
  requireCondition(object(operation.security[0]));
  equalSet(Object.keys(operation.security[0]), names);
  requireCondition(Object.values(operation.security[0]).every(scopes => Array.isArray(scopes) && scopes.length === 0));
}

function schemaReference(value, name) {
  requireCondition(object(value) && isDeepStrictEqual(value, { $ref: `#/components/schemas/${name}` }));
}

function jsonContent(value, name) {
  requireCondition(object(value.content));
  equalSet(Object.keys(value.content), ['application/json']);
  schemaReference(value.content['application/json']?.schema, name);
}

// Compare every status/header, including default error responses. A HEAD can
// perform a read, but must not acquire a request body or return response data.
function headMatches(document, item) {
  if (!Object.hasOwn(item, 'get')) return;
  const get = item.get;
  const head = item.head;
  requireCondition(object(head) && !Object.hasOwn(head, 'requestBody'));
  for (const key of ['security', 'parameters', 'x-vproxy-required-scope']) {
    requireCondition(isDeepStrictEqual(head[key], get[key]));
  }
  equalSet(Object.keys(head.responses), Object.keys(get.responses));
  for (const [status, value] of Object.entries(get.responses)) {
    const expected = { ...dereference(document, value) };
    delete expected.content;
    const actual = dereference(document, head.responses[status]);
    requireCondition(!Object.hasOwn(actual, 'content') && isDeepStrictEqual(actual, expected));
  }
}

function capabilityPaths(document, table, automation) {
  for (const [route, definition] of Object.entries(table)) {
    const item = document.paths[route];
    requireCondition(object(item));
    const methods = Object.keys(definition).filter(method => METHODS.has(method));
    if (Object.hasOwn(definition, 'get')) methods.push('head');
    equalSet(Object.keys(item).filter(method => METHODS.has(method)), methods);
    const slots = [...route.matchAll(/\{([^{}]+)\}/gu)].map(match => `path:${match[1]}`);
    for (const method of methods) {
      const expected = definition[method === 'head' ? 'get' : method];
      const operation = item[method];
      exactSecurity(operation, automation ? ['Automation'] : method === 'post' ? ['Session', 'Csrf'] : ['Session']);
      if (automation) requireCondition(operation['x-vproxy-required-scope'] === definition.scope);
      const combined = new Map(parameters(document, item.parameters ?? []));
      for (const [key, value] of parameters(document, operation.parameters ?? [])) combined.set(key, value);
      const extras = automation ? expected.parameters : method === 'post' ? ['header:Origin'] : expected.parameters ?? [];
      equalSet(combined.keys(), [...slots, ...extras]);
      if (combined.has('header:Origin')) requireCondition(combined.get('header:Origin').required === !automation);
      if (method === 'head') continue;
      equalSet(Object.keys(operation.responses).filter(status => /^[23][0-9]{2}$/u.test(status)), Object.keys(expected.responses));
      for (const [status, name] of Object.entries(expected.responses)) jsonContent(dereference(document, operation.responses[status]), name);
      for (const status of expected.errors ?? []) jsonContent(dereference(document, operation.responses[status]), 'ApiError');
      if (expected.request) {
        const body = dereference(document, operation.requestBody);
        requireCondition(body.required === true);
        jsonContent(body, expected.request);
      } else {
        requireCondition(!Object.hasOwn(operation, 'requestBody'));
      }
    }
  }
}

function objectShape(schemas, name, fields, required = fields) {
  const schema = schemas[name];
  requireCondition(object(schema) && schema.type === 'object' && schema.additionalProperties === false && object(schema.properties));
  requireCondition(Array.isArray(schema.required));
  equalSet(Object.keys(schema.properties), fields);
  equalSet(schema.required, required);
  return schema.properties;
}

function userOperationShapes(schemas) {
  const changes = {
    OperationCreateUserChange: ['action', 'name', 'protocols', 'concurrent_limit'],
    OperationUpdateUserChange: ['action', 'id', 'name', 'protocols', 'concurrent_limit'],
    OperationSetUserActiveChange: ['action', 'id', 'active'],
    OperationDeleteUserChange: ['action', 'id'],
  };
  for (const [index, [name, fields]] of Object.entries(changes).entries()) {
    const properties = objectShape(schemas, name, fields);
    requireCondition(properties.action.const === USER_ACTIONS[index]);
  }
  requireCondition(Array.isArray(schemas.OperationChange?.oneOf) && schemas.OperationChange.oneOf.length === 4);
  equalSet(schemas.OperationChange.oneOf.map(value => value.$ref), Object.keys(changes).map(name => `#/components/schemas/${name}`));
  const input = objectShape(schemas, 'OperationInput', ['expected_node_id', 'expected_revision', 'expected_epoch', 'change'], ['expected_revision', 'expected_epoch', 'change']);
  for (const name of ['expected_revision', 'expected_epoch']) schemaReference(input[name], 'Revision');
  schemaReference(input.expected_node_id, 'Id');
  schemaReference(input.change, 'OperationChange');
  objectShape(schemas, 'OperationContext', ['node_id', 'policy_revision', 'expected_epoch', 'local']);
  objectShape(schemas, 'OperationPage', ['items', 'next_cursor']);
  const result = objectShape(schemas, 'OperationResult', ['id', 'node_id', 'sequence', 'expected_revision', 'expected_epoch', 'action', 'user_id', 'state', 'saved_revision', 'rejection']);
  equalSet(result.action.enum, USER_ACTIONS);
  equalSet(result.state.enum, ['reserved', 'saved', 'rejected']);
  equalSet(schemas.OperationRejection?.enum ?? [], ['invalid_policy', 'policy_conflict', 'resource_not_found', 'policy_capacity', 'resource_managed', 'owner_conflict']);
}

function sessionShapes(schemas) {
  const source = ['incident_id', 'kind', 'origin_node_id', 'resource_id', 'check', 'target', 'code', 'first_observed_at_unix_ms', 'last_observed_at_unix_ms', 'evidence_sequence'];
  const event = objectShape(schemas, 'AlertHistoryEvent', ['sequence', 'node_id', 'episode_id', 'boot_id', ...source, 'transition', 'observed_at_unix_ms', 'recorded_at_unix_ms', 'end_reason', 'administrator_id', 'acknowledged_transition_sequence']);
  const episode = objectShape(schemas, 'AlertHistoryEpisode', ['id', 'node_id', 'boot_id', ...source, 'status', 'ended_at_unix_ms', 'end_reason', 'latest_transition_sequence', 'acknowledged_transition_sequence', 'acknowledged_by', 'acknowledged_at_unix_ms', 'acknowledgement_event_sequence', 'is_acknowledged']);
  equalSet(event.transition.enum, ['opened', 'reason_changed', 'recovered', 'unmonitored', 'acknowledged']);
  for (const name of ['sequence', 'episode_id']) schemaReference(event[name], 'Revision');
  for (const name of ['id', 'latest_transition_sequence']) schemaReference(episode[name], 'Revision');
  schemaReference(event.incident_id, 'AlertEpisodeId');
  const alertPage = objectShape(schemas, 'AlertHistoryPage', ['node_id', 'items', 'next_cursor', 'oldest_sequence', 'trimmed']);
  schemaReference(alertPage.trimmed, 'Counter');
  requireCondition(alertPage.items.maxItems === 50);
  const summary = objectShape(schemas, 'AlertHistorySummary', ['node_id', 'retained_episode_count', 'retained_event_count', 'unacknowledged_count', 'oldest_sequence', 'trimmed']);
  requireCondition(summary.retained_episode_count.maximum === 16384 && summary.retained_event_count.maximum === 16384 && summary.unacknowledged_count.maximum === 16384);
  const acknowledgement = objectShape(schemas, 'AlertHistoryAcknowledgementInput', ['expected_node_id', 'expected_transition_sequence']);
  schemaReference(acknowledgement.expected_node_id, 'Id');
  schemaReference(acknowledgement.expected_transition_sequence, 'Revision');
  objectShape(schemas, 'TargetCommandHistoryEntry', ['sequence', 'controller_node_id', 'administrator_id', 'protocol_version', 'action', 'job', 'user_id', 'credential_id', 'imported', 'recorded_at_unix_s', 'updated_at_unix_s']);
  objectShape(schemas, 'TargetCommandHistoryPage', ['items', 'next_cursor', 'oldest_sequence', 'trimmed']);
  requireCondition(schemas.TargetCommandHistoryPage.properties.items.maxItems === 50);
  schemaReference(schemas.TargetCommandHistoryEntry.properties.job, 'TargetJob');
  for (const name of ['user_id', 'credential_id']) schemaReference(schemas.TargetCommandHistoryEntry.properties[name], 'NullableId');
  objectShape(schemas, 'TlsIdentityStatus', ['node_id', 'observed_at_unix_s', 'entries']);
  const tls = objectShape(schemas, 'TlsIdentityEntry', ['role', 'source', 'id', 'protocol', 'state', 'certificate', 'valid_now']);
  objectShape(schemas, 'TlsLeafMetadata', ['sha256', 'not_before_unix_s', 'not_after_unix_s']);
  equalSet(tls.role.enum, ['management', 'node', 'proxy']);
  equalSet(tls.source.enum, ['manual', 'acme']);
  equalSet(tls.state.enum, ['disabled', 'pending', 'unavailable', 'loaded']);
  requireCondition(schemas.TlsIdentityStatus.properties.entries.minItems === 2 && schemas.TlsIdentityStatus.properties.entries.maxItems === 18);
  objectShape(schemas, 'MaintenanceOwnership', ['controller_node_id', 'epoch', 'last_terminal_command']);
  objectShape(schemas, 'MaintenanceStatus', ['node_id', 'ownership', 'saved_revision', 'durable_applied_revision', 'running', 'saved_accepting', 'applied_revision', 'runtime_accepting', 'active_operations']);
  objectShape(schemas, 'MaintenanceChange', ['saved_revision', 'applied_revision', 'running']);
  objectShape(schemas, 'MaintenanceInput', ['expected_node_id', 'expected_revision', 'expected_epoch', 'accepting']);
  objectShape(schemas, 'MaintenanceMutation', ['action', 'accepting']);
  const drain = objectShape(schemas, 'ProxyRuntimeDrainRequest', ['expected_node_id', 'expected_epoch', 'expected_revision', 'runtime_id', 'request_id']);
  for (const name of ['expected_node_id', 'runtime_id', 'request_id']) schemaReference(drain[name], 'Id');
  for (const name of ['expected_epoch', 'expected_revision']) schemaReference(drain[name], 'Revision');
  objectShape(schemas, 'TargetProxyRuntimeDrainInput', ['expected_target_revision', 'request']);
  const runtime = objectShape(schemas, 'ProxyRuntimeState', ['runtime_id', 'phase', 'request', 'active_operations']);
  equalSet(runtime.phase.enum, ['serving', 'draining', 'drained', 'interrupted', 'failed']);
  objectShape(schemas, 'ProxyRuntimeStatus', ['node_id', 'ownership', 'saved_revision', 'saved_accepting', 'runtime']);
  requireCondition(schemas.Counter?.type === 'string' && schemas.Counter.maxLength === 20 && schemas.Counter['x-vproxy-maximum-decimal'] === '18446744073709551615');
}

export function structure(document, audience) {
  requireCondition(document.openapi === '3.1.2' && document.jsonSchemaDialect === DIALECT);
  requireCondition(object(document.info) && typeof document.info.title === 'string' && document.info.title.length !== 0);
  requireCondition(typeof document.info.version === 'string' && document.info.version.length !== 0);
  requireCondition(object(document.paths) && Object.keys(document.paths).length !== 0);
  requireCondition(object(document.components) && object(document.components.schemas));
  requireCondition(object(document.components.securitySchemes));
  requireCondition(Array.isArray(document.servers) && document.servers.length !== 0);
  requireCondition(document.servers.every(server => object(server) && typeof server.url === 'string' && server.url.startsWith('https://')));
  const ids = new Set();
  const inline = [];
  walk(document, value => {
    if (Object.hasOwn(value, '$ref')) localReference(document, value.$ref);
    if (Object.hasOwn(value, 'schema')) inline.push(value.schema);
  });
  if (Object.hasOwn(document, 'security')) security(document, document.security);
  for (const [route, item] of Object.entries(document.paths)) {
    requireCondition(route.startsWith('/api/v1/') && object(item));
    requireCondition(Object.keys(item).every(key => METHODS.has(key) || PATH_FIELDS.has(key) || key.startsWith('x-')));
    const slots = [...route.matchAll(/\{([^{}]+)\}/gu)].map(match => match[1]);
    requireCondition(new Set(slots).size === slots.length);
    requireCondition(route.replaceAll(/\{[^{}]+\}/gu, '').search(/[{}]/u) === -1);
    const inherited = parameters(document, item.parameters ?? []);
    let operations = 0;
    for (const [method, operation] of Object.entries(item)) {
      if (!METHODS.has(method)) continue;
      operations++;
      requireCondition(object(operation) && typeof operation.operationId === 'string' && operation.operationId.length !== 0);
      requireCondition(!ids.has(operation.operationId));
      ids.add(operation.operationId);
      security(document, operation.security ?? document.security ?? []);
      const combined = new Map(inherited);
      for (const [key, parameter] of parameters(document, operation.parameters ?? [])) combined.set(key, parameter);
      const declared = [...combined.values()].filter(parameter => parameter.in === 'path').map(parameter => parameter.name).sort();
      requireCondition(JSON.stringify(declared) === JSON.stringify([...slots].sort()));
      requireCondition(object(operation.responses) && Object.keys(operation.responses).length !== 0);
      for (const [status, value] of Object.entries(operation.responses)) {
        requireCondition(/^(?:[1-5](?:[0-9]{2}|XX)|default)$/u.test(status));
        const response = dereference(document, value);
        requireCondition(typeof response.description === 'string');
        if (Object.hasOwn(response, 'content')) requireCondition(object(response.content));
      }
      if (Object.hasOwn(operation, 'requestBody')) {
        const body = dereference(document, operation.requestBody);
        requireCondition(object(body.content) && Object.keys(body.content).length !== 0);
      }
    }
    requireCondition(operations !== 0);
    headMatches(document, item);
  }
  userOperationShapes(document.components.schemas);
  if (audience === 'automation') {
    equalSet(Object.keys(document.paths), Object.keys(AUTOMATION_PATHS));
    requireCondition(JSON.stringify(Object.keys(document.components.securitySchemes)) === '["Automation"]');
    const scheme = document.components.securitySchemes.Automation;
    requireCondition(scheme.type === 'http' && scheme.scheme === 'bearer' && scheme.bearerFormat === 'vpa1');
    requireCondition(Object.keys(document.components.schemas).every(name => AUTOMATION_SCHEMAS.has(name)));
    walk([...Object.values(document.components.schemas), ...inline], value => {
      requireCondition(value['x-vproxy-sensitive'] !== true && value.writeOnly !== true);
      if (object(value.properties)) {
        requireCondition(!Object.keys(value.properties).some(name => /^(?:password|current_password|new_password|password_hash|secret|token|access_token|credential|credentials|csrf_token|administrator|authorization|verifier|digest)$/u.test(name)));
      }
    });
    capabilityPaths(document, AUTOMATION_PATHS, true);
  } else {
    capabilityPaths(document, SESSION_PATHS, false);
    sessionShapes(document.components.schemas);
  }
  return { paths: Object.keys(document.paths).length, operations: ids.size, inline };
}

function schemaValidators(document, inline, audience, dependencies) {
  const ajv = new dependencies.Ajv2020({
    allErrors: true, strict: false, logger: false, validateFormats: true,
    coerceTypes: false, useDefaults: false, removeAdditional: false,
  });
  dependencies.addFormats(ajv);
  const schemas = document.components.schemas;
  for (const schema of [...Object.values(schemas), ...inline]) {
    requireCondition(typeof schema === 'boolean' || object(schema));
    // Current exports have one local components namespace. Do not introduce a
    // second schema resource/dynamic resolver while claiming local-only checks.
    walk(schema, value => {
      requireCondition(!Object.hasOwn(value, '$id') && !Object.hasOwn(value, '$dynamicRef'));
      if (Object.hasOwn(value, '$schema')) requireCondition(value.$schema === DIALECT);
      if (Object.hasOwn(value, '$ref')) requireCondition(typeof value.$ref === 'string' && value.$ref.startsWith('#/components/schemas/'));
    });
    requireCondition(ajv.validateSchema(schema));
  }
  // This is a resolution registry, NOT an OpenAPI document meta-validation.
  // Compiling a fragment below applies that actual Schema Object and preserves
  // its existing #/components/schemas references without modifying the inputs.
  const registry = `urn:vproxy:management-contract:${audience}`;
  const definitions = Object.fromEntries(inline.map((schema, index) => [`inline${index}`, schema]));
  ajv.addSchema({ $id: registry, $schema: DIALECT, components: { schemas }, $defs: definitions });
  const validators = new Map();
  for (const name of Object.keys(schemas)) {
    const escaped = name.replaceAll('~', '~0').replaceAll('/', '~1');
    validators.set(name, ajv.compile({ $ref: `${registry}#/components/schemas/${escaped}` }));
  }
  for (let index = 0; index < inline.length; index++) ajv.compile({ $ref: `${registry}#/$defs/inline${index}` });
  return validators;
}

function syntheticCases(browser, automation) {
  const counts = { groups: 14, accepted: 0, rejected: 0 };
  const check = (validators, name, value, expected) => {
    requireCondition(validators.has(name));
    requireCondition(validators.get(name)(value) === expected);
    counts[expected ? 'accepted' : 'rejected']++;
  };
  const publicUser = {
    id: ID, name: 'Example user', active: true, deleted: false,
    protocols: ['http', 'socks5'], concurrent_limit: 2, revision: '9007199254740993',
  };
  // These examples check represented schema constraints, not UTF-8 byte limits,
  // decimal upper-bound annotations, authorization, query binding or live I/O.
  for (const validators of [browser, automation]) {
    check(validators, 'Name', '用户 Alpha', true);
    for (const name of ['line\nbreak', 'control\u0085', '']) check(validators, 'Name', name, false);
    check(validators, 'Revision', '9007199254740993', true);
    for (const value of [9007199254740992, '01', '0']) check(validators, 'Revision', value, false);
    check(validators, 'User', publicUser, true);
    check(validators, 'User', { ...publicUser, deleted: true, active: false }, true);
    check(validators, 'User', { ...publicUser, deleted: true }, false);
    check(validators, 'User', { ...publicUser, secret: 'synthetic-only' }, false);
  }
  check(browser, 'Counter', '18446744073709551615', true);
  check(browser, 'Counter', 9007199254740992, false);
  const owner = { controller_node_id: null, epoch: '1', last_terminal_command: '0' };
  check(browser, 'UserPolicyOwner', owner, true);
  check(browser, 'UserPolicyOwner', { ...owner, last_terminal_command: '18446744073709551615' }, false);
  const saved = {
    controller_epoch: '3', command_id: '7', status: 'saved', metadata_revision: '9007199254740993',
    rejection: null, listener_id: ID, generation: 'a'.repeat(64),
  };
  const rejected = { ...saved, status: 'rejected', metadata_revision: null, rejection: 'endpoint_revision_changed', listener_id: null, generation: null };
  check(browser, 'MetadataReceipt', saved, true);
  check(browser, 'MetadataReceipt', rejected, true);
  for (const value of [{ ...saved, metadata_revision: null }, { ...saved, rejection: 'invalid_endpoint' }, { ...rejected, listener_id: ID }]) check(browser, 'MetadataReceipt', value, false);
  const policy = {
    node_id: ID, job_id: OTHER_ID, controller_epoch: '1', command_id: '7', expected_policy_revision: '4',
    state: 'pending', policy_revision: null, outcome_code: null, attempts: 0, next_attempt: '0',
  };
  const metadata = {
    ...policy, expected_policy_revision: null, resource: 'proxy_endpoints', expected_metadata_revision: '3',
    metadata_revision: null, endpoint: { listener_id: ID, generation: 'a'.repeat(64) },
  };
  check(browser, 'TargetJob', policy, true);
  check(browser, 'TargetJob', metadata, true);
  check(browser, 'TargetJob', { ...metadata, expected_policy_revision: '4' }, false);
  check(browser, 'TargetJob', { ...metadata, state: 'applied' }, false);
  check(browser, 'TargetJob', { ...metadata, routing: { kind: 'prefix', id: ID } }, false);
  check(browser, 'TargetJob', { ...policy, expected_policy_revision: null }, false);
  check(browser, 'TargetJob', { ...policy, payload: {} }, false);
  const history = {
    sequence: '1', controller_node_id: OTHER_ID, administrator_id: ID,
    protocol_version: 1, action: 'create_user', job: { ...policy, user_creation: true }, user_id: null,
    credential_id: null, imported: false, recorded_at_unix_s: '0', updated_at_unix_s: null,
  };
  check(browser, 'TargetCommandHistoryEntry', history, true);
  check(browser, 'TargetCommandHistoryEntry', { ...history, imported: true, recorded_at_unix_s: null }, true);
  for (const value of [
    { ...history, sequence: 1 }, { ...history, action: 'run_shell' },
    { ...history, protocol_version: 4 }, { ...history, secret: 'synthetic-only' },
    { ...history, recorded_at_unix_s: '-1' }, { ...history, recorded_at_unix_s: '01' },
    { ...history, user_id: '' }, { ...history, imported: null },
  ]) check(browser, 'TargetCommandHistoryEntry', value, false);
  const historyPage = { items: [history], next_cursor: null, oldest_sequence: '1', trimmed: false };
  check(browser, 'TargetCommandHistoryPage', historyPage, true);
  check(browser, 'TargetCommandHistoryPage', { ...historyPage, items: [], trimmed: true }, true);
  check(browser, 'TargetCommandHistoryPage', { ...historyPage, items: Array(51).fill(history) }, false);
  check(browser, 'TargetCommandHistoryPage', { ...historyPage, next_cursor: 1 }, false);
  const reserved = {
    id: ID, node_id: OTHER_ID, sequence: '2', expected_revision: '3', expected_epoch: '1',
    action: 'create_user', user_id: null, state: 'reserved', saved_revision: null, rejection: null,
  };
  const completed = { ...reserved, state: 'saved', user_id: ID, saved_revision: '4' };
  const refused = { ...reserved, state: 'rejected', rejection: 'policy_conflict' };
  const changes = [
    { action: 'create_user', name: 'Example user', protocols: ['http', 'socks5'], concurrent_limit: 2 },
    { action: 'update_user', id: ID, name: 'Example user', protocols: [], concurrent_limit: 1 },
    { action: 'set_user_active', id: ID, active: false },
    { action: 'delete_user', id: ID },
  ];
  for (const validators of [browser, automation]) {
    for (const change of changes) {
      check(validators, 'OperationChange', change, true);
      const missing = { ...change };
      delete missing[change.action === 'create_user' ? 'name' : 'id'];
      check(validators, 'OperationChange', missing, false);
      check(validators, 'OperationChange', { ...change, secret: 'synthetic-only' }, false);
    }
    for (const change of [
      { action: 'create_credential', user_id: ID }, { action: 'set_admission', accepting: true },
      { ...changes[3], name: 'unexpected' }, { ...changes[0], actor: ID },
      { ...changes[0], protocols: ['http', 'http'] }, { ...changes[0], concurrent_limit: 0 },
    ]) check(validators, 'OperationChange', change, false);
    const input = { expected_revision: '3', expected_epoch: '1', change: changes[0] };
    check(validators, 'OperationInput', input, true);
    check(validators, 'OperationInput', { ...input, expected_node_id: OTHER_ID }, true);
    for (const value of [
      { ...input, expected_node_id: null }, { ...input, expected_node_id: `${ID.slice(0, 21)}B` },
      { ...input, expected_epoch: 1 }, { ...input, expected_revision: '0' },
      { ...input, id: ID }, { ...input, expected_node_id: OTHER_ID, secret: 'synthetic-only' },
    ]) check(validators, 'OperationInput', value, false);
    const context = { node_id: ID, policy_revision: '3', expected_epoch: '1', local: false };
    check(validators, 'OperationContext', context, true);
    check(validators, 'OperationContext', { ...context, local: true }, true);
    check(validators, 'OperationContext', { ...context, local: null }, false);
    for (const value of [reserved, completed, refused]) check(validators, 'OperationResult', value, true);
    for (const action of USER_ACTIONS.slice(1)) {
      check(validators, 'OperationResult', { ...reserved, action, user_id: ID }, true);
      check(validators, 'OperationResult', { ...refused, action, user_id: ID }, true);
    }
    for (const value of [
      { ...reserved, saved_revision: '4' }, { ...completed, user_id: null },
      { ...completed, rejection: 'policy_conflict' }, { ...refused, rejection: null },
      { ...reserved, action: 'update_user' }, { ...refused, user_id: ID },
    ]) check(validators, 'OperationResult', value, false);
    for (const key of ['user_id', 'saved_revision', 'rejection']) {
      const missing = { ...reserved };
      delete missing[key];
      check(validators, 'OperationResult', missing, false);
    }
    check(validators, 'OperationReserved', reserved, true);
    check(validators, 'OperationReserved', completed, false);
    check(validators, 'OperationTerminal', completed, true);
    check(validators, 'OperationTerminal', refused, true);
    check(validators, 'OperationTerminal', reserved, false);
    const page = { items: [reserved], next_cursor: '2' };
    check(validators, 'OperationPage', page, true);
    check(validators, 'OperationPage', { ...page, items: Array(51).fill(reserved) }, false);
    check(validators, 'OperationPage', { ...page, payload: input }, false);
  }
  const incident = {
    id: '9007199254740993', kind: 'egress_check', origin_node_id: ID, resource_id: OTHER_ID,
    check: 'tcp', target: '[::1]:443', status: 'active', code: 'egress_connection_refused',
    first_observed_at_unix_ms: '9007199254740993', last_observed_at_unix_ms: null,
    ended_at_unix_ms: null, age_millis: '18446744073709551615', evidence_sequence: '7', evidence_fresh: false,
  };
  const event = {
    sequence: '1', node_id: ID, episode_id: '1', boot_id: ID, incident_id: '18446744073709551615',
    transition: 'opened', kind: 'health_catalog', origin_node_id: ID, resource_id: null,
    check: null, target: null, code: 'health_catalog_stale', first_observed_at_unix_ms: null,
    last_observed_at_unix_ms: null, evidence_sequence: '18446744073709551615',
    observed_at_unix_ms: null, recorded_at_unix_ms: '18446744073709551615', end_reason: null,
    administrator_id: null, acknowledged_transition_sequence: null,
  };
  check(browser, 'AlertHistoryEvent', event, true);
  check(browser, 'AlertHistoryEvent', { ...event, sequence: '2', transition: 'acknowledged', administrator_id: OTHER_ID, acknowledged_transition_sequence: '1' }, true);
  check(browser, 'AlertHistoryEvent', { ...event, sequence: '3', transition: 'unmonitored', end_reason: 'monitor_restarted' }, true);
  for (const value of [
    { ...event, sequence: 1 }, { ...event, episode_id: ID }, { ...event, incident_id: '0' },
    { ...event, evidence_sequence: 9007199254740992 }, { ...event, evidence_fresh: true },
    { ...event, end_reason: 'monitor_restarted' }, { ...event, transition: 'acknowledged' },
    { ...event, transition: 'unmonitored' }, { ...event, secret: 'synthetic-only' },
  ]) check(browser, 'AlertHistoryEvent', value, false);
  const episode = {
    id: '1', node_id: ID, boot_id: ID, incident_id: '18446744073709551615', kind: 'health_catalog',
    origin_node_id: ID, resource_id: null, check: null, target: null, status: 'active', code: 'health_catalog_stale',
    first_observed_at_unix_ms: null, last_observed_at_unix_ms: null, ended_at_unix_ms: null,
    evidence_sequence: null, end_reason: null, latest_transition_sequence: '1',
    acknowledged_transition_sequence: null, acknowledged_by: null, acknowledged_at_unix_ms: null,
    acknowledgement_event_sequence: null, is_acknowledged: false,
  };
  check(browser, 'AlertHistoryEpisode', episode, true);
  check(browser, 'AlertHistoryEpisode', { ...episode, acknowledged_transition_sequence: '1', acknowledged_by: OTHER_ID, acknowledgement_event_sequence: '2', is_acknowledged: true }, true);
  for (const value of [
    { ...episode, is_acknowledged: true }, { ...episode, acknowledged_by: OTHER_ID },
    { ...episode, status: 'unmonitored' }, { ...episode, ended_at_unix_ms: '1' },
    { ...episode, latest_transition_sequence: 1 }, { ...episode, status: 'muted' },
  ]) check(browser, 'AlertHistoryEpisode', value, false);
  const eventPage = { node_id: ID, items: [event], next_cursor: null, oldest_sequence: '1', trimmed: '0' };
  check(browser, 'AlertHistoryPage', eventPage, true);
  check(browser, 'AlertHistoryPage', { ...eventPage, items: Array(51).fill(event) }, false);
  check(browser, 'AlertHistoryPage', { ...eventPage, trimmed: false }, false);
  const alertSummary = { node_id: ID, retained_episode_count: 16384, retained_event_count: 16384, unacknowledged_count: 16384, oldest_sequence: '1', trimmed: '18446744073709551615' };
  check(browser, 'AlertHistorySummary', alertSummary, true);
  check(browser, 'AlertHistorySummary', { ...alertSummary, retained_episode_count: 16385 }, false);
  check(browser, 'AlertHistorySummary', { ...alertSummary, retained_event_count: 16385 }, false);
  const acknowledgement = { expected_node_id: ID, expected_transition_sequence: '1' };
  check(browser, 'AlertHistoryAcknowledgementInput', acknowledgement, true);
  check(browser, 'AlertHistoryAcknowledgementInput', { ...acknowledgement, expected_transition_sequence: 1 }, false);
  check(browser, 'AlertHistoryAcknowledgementInput', { ...acknowledgement, force: true }, false);
  const alerts = {
    boot_id: ID, revision: '1', observed_at_unix_ms: null, age_millis: null, collection_error: false,
    coverage: { local_egress: true, local_traffic: false, local_proxy_expected: false, remote_cached: true, remote_egress: false, remote_observation: false },
    active_count: 1, recent_count: 0, dropped: '0', items: [incident], next_cursor: null,
  };
  check(browser, 'AlertPage', alerts, true);
  const { remote_observation: _backgroundCoverage, ...legacyAlertCoverage } = alerts.coverage;
  check(browser, 'AlertPage', { ...alerts, coverage: legacyAlertCoverage }, false);
  check(browser, 'AlertPage', { ...alerts, active_count: 12288, coverage: { ...alerts.coverage, remote_observation: true } }, true);
  const observationFailure = { ...incident, kind: 'remote_observation', origin_node_id: OTHER_ID, resource_id: null, check: null, target: null, evidence_fresh: false };
  for (const code of ['remote_observation_pending', 'remote_observation_unavailable', 'remote_observation_unsupported', 'remote_observation_not_authorized', 'remote_observation_stale', 'remote_observation_changed', 'remote_observation_capacity', 'remote_observation_incomplete'])
    check(browser, 'AlertIncident', { ...observationFailure, code }, true);
  for (const patch of [{ resource_id: ID }, { check: 'bind' }, { target: '127.0.0.1:443' }])
    check(browser, 'AlertIncident', { ...observationFailure, code: 'remote_observation_stale', ...patch }, false);
  const httpsIncident = { ...incident, kind: 'management_https', resource_id: null, check: null, target: null };
  for (const code of ['https_identity_unavailable', 'https_identity_expiring', 'acme_attempt_unavailable', 'acme_review_required', 'acme_worker_stopped']) {
    check(browser, 'AlertIncident', { ...httpsIncident, code }, true);
  }
  for (const included of [false, true]) {
    check(browser, 'AlertPage', { ...alerts, coverage: { ...alerts.coverage, local_management_https: included },
      items: [{ ...httpsIncident, code: 'https_identity_unavailable' }] }, true);
  }
  for (const value of [
    { ...httpsIncident, resource_id: OTHER_ID }, { ...httpsIncident, check: 'bind' },
    { ...httpsIncident, target: '127.0.0.1:443' },
  ]) check(browser, 'AlertIncident', { ...value, code: 'https_identity_unavailable' }, false);
  for (const included of [null, 0, 'true']) {
    check(browser, 'AlertPage', { ...alerts, coverage: { ...alerts.coverage, local_management_https: included } }, false);
  }
  check(browser, 'AlertIncident', { ...incident, status: 'unmonitored', ended_at_unix_ms: null }, true);
  check(browser, 'AlertIncident', { ...incident, status: 'recovered', ended_at_unix_ms: '9007199254740994' }, true);
  for (const value of [
    { ...incident, id: '0' }, { ...incident, evidence_sequence: 9007199254740992 },
    { ...incident, evidence_fresh: null }, { ...incident, ended_at_unix_ms: '1' },
    { ...incident, code: 'raw_private_error' }, { ...incident, check: 'bind', target: '[::1]:443' },
    { ...incident, kind: 'policy' }, { ...incident, secret: 'synthetic-only' },
  ]) check(browser, 'AlertIncident', value, false);
  for (const value of [
    { ...alerts, active_count: 12289 }, { ...alerts, recent_count: 257 },
    { ...alerts, items: Array(17).fill(incident) },
    { ...alerts, coverage: { ...alerts.coverage, remote_egress: true } },
    { ...alerts, coverage: { ...alerts.coverage, remote_observation: null } },
    { ...alerts, next_cursor: '' },
  ]) check(browser, 'AlertPage', value, false);
  const manualTls = { mode: 'manual' };
  const acme = {
    mode: 'acme', environment: 'staging', challenge: 'tls-alpn-01', certificate: null,
    activity: 'waiting', next_attempt_at_unix_s: '0', last_failure: null,
    observed_at_unix_s: '9007199254740993',
  };
  const certificate = {
    not_before_unix_s: '9007199254740992', not_after_unix_s: '18446744073709551615', available: true,
  };
  check(browser, 'AcmeStatus', manualTls, true);
  check(browser, 'AcmeStatus', { ...manualTls, certificate: null }, false);
  check(browser, 'AcmeStatus', acme, true);
  for (const activity of ['working', 'stopped']) {
    check(browser, 'AcmeStatus', { ...acme, activity, next_attempt_at_unix_s: null, certificate, last_failure: 'attempt_unavailable' }, true);
    check(browser, 'AcmeStatus', { ...acme, activity, next_attempt_at_unix_s: '1' }, false);
  }
  check(browser, 'AcmeStatus', { ...acme, environment: 'production', challenge: 'http-01', certificate, last_failure: 'review_required' }, true);
  for (const value of [
    { ...acme, next_attempt_at_unix_s: null }, { ...acme, observed_at_unix_s: 9007199254740992 },
    { ...acme, observed_at_unix_s: '01' }, { ...acme, next_attempt_at_unix_s: '-1' },
    { ...acme, environment: 'custom' }, { ...acme, challenge: 'dns-01' },
    { ...acme, activity: 'ready' }, { ...acme, last_failure: 'raw_private_error' },
    { ...acme, contact: 'synthetic-only@example.invalid' },
    { ...acme, certificate: { ...certificate, not_after_unix_s: 9007199254740992 } },
    { ...acme, certificate: { ...certificate, private_key: 'synthetic-only' } },
  ]) check(browser, 'AcmeStatus', value, false);
  const incompleteAcme = { ...acme };
  delete incompleteAcme.next_attempt_at_unix_s;
  check(browser, 'AcmeStatus', incompleteAcme, false);
  // These are represented lexical/nullable/phase constraints, not comparisons
  // between IDs, decimal strings or validity intervals. Those remain producer
  // validation and integration-test responsibilities, as the schemas state.
  const leaf = { sha256: 'a'.repeat(64), not_before_unix_s: '-1', not_after_unix_s: '1' };
  const management = { role: 'management', source: 'manual', id: null, protocol: null, state: 'loaded', certificate: leaf, valid_now: true };
  const node = { role: 'node', source: 'manual', id: null, protocol: null, state: 'disabled', certificate: null, valid_now: null };
  const tls = { node_id: ID, observed_at_unix_s: '0', entries: [management, node] };
  check(browser, 'TlsIdentityStatus', tls, true);
  check(browser, 'TlsIdentityStatus', { ...tls, observed_at_unix_s: null }, true);
  check(browser, 'TlsUnixSeconds', '-1', true);
  for (const value of ['-0', '01', 0]) check(browser, 'TlsUnixSeconds', value, false);
  for (const value of [
    { ...tls, entries: [management] }, { ...tls, entries: Array(19).fill(node) },
    { ...tls, entries: [{ ...management, certificate: { ...leaf, private_key: 'synthetic-only' } }, node] },
    { ...tls, entries: [{ ...management, role: 'remote' }, node] },
  ]) check(browser, 'TlsIdentityStatus', value, false);
  const maintenance = {
    node_id: ID, ownership: owner, saved_revision: '3', durable_applied_revision: null,
    running: false, saved_accepting: false, applied_revision: null, runtime_accepting: null, active_operations: null,
  };
  const observedMaintenance = { ...maintenance, running: true, applied_revision: '3', runtime_accepting: false, active_operations: '18446744073709551615' };
  check(browser, 'MaintenanceStatus', maintenance, true);
  check(browser, 'MaintenanceStatus', { ...maintenance, running: true }, true);
  check(browser, 'MaintenanceStatus', observedMaintenance, true);
  for (const value of [
    { ...observedMaintenance, running: false }, { ...observedMaintenance, active_operations: null },
    { ...maintenance, runtime_accepting: false }, { ...observedMaintenance, active_operations: 0 },
    { ...observedMaintenance, active_operations: '01' }, { ...maintenance, drained: true },
  ]) check(browser, 'MaintenanceStatus', value, false);
  check(browser, 'MaintenanceChange', { saved_revision: '3', applied_revision: null, running: false }, true);
  check(browser, 'MaintenanceChange', { saved_revision: '3', applied_revision: '3', running: true }, true);
  check(browser, 'MaintenanceChange', { saved_revision: '3', applied_revision: null, running: true }, false);
  const drain = { expected_node_id: ID, expected_epoch: '1', expected_revision: '3', runtime_id: OTHER_ID, request_id: ID };
  check(browser, 'ProxyRuntimeDrainRequest', drain, true);
  check(browser, 'ProxyRuntimeDrainRequest', { ...drain, force: true }, false);
  const incompleteDrain = { ...drain };
  delete incompleteDrain.request_id;
  check(browser, 'ProxyRuntimeDrainRequest', incompleteDrain, false);
  const runtime = { node_id: ID, ownership: owner, saved_revision: '3', saved_accepting: false, runtime: null };
  check(browser, 'ProxyRuntimeStatus', runtime, true);
  const serving = { runtime_id: OTHER_ID, phase: 'serving', request: null, active_operations: null };
  check(browser, 'ProxyRuntimeStatus', { ...runtime, runtime: serving }, true);
  for (const phase of ['draining', 'drained', 'interrupted', 'failed']) {
    const current = { ...serving, phase, request: drain, active_operations: '0' };
    check(browser, 'ProxyRuntimeStatus', { ...runtime, runtime: current }, true);
    check(browser, 'ProxyRuntimeStatus', { ...runtime, runtime: { ...current, request: null } }, false);
    check(browser, 'ProxyRuntimeStatus', { ...runtime, runtime: current, saved_accepting: true }, false);
  }
  for (const value of [
    { ...serving, phase: 'runtime_stopped' }, { ...serving, request: drain },
    { ...serving, active_operations: 0 }, { ...serving, active_operations: '01' },
    { ...serving, stopped: true },
  ]) check(browser, 'ProxyRuntimeState', value, false);
  return counts;
}

function main() {
  const parsed = parseArgs({ options: { 'web-root': { type: 'string' } }, allowPositionals: true });
  requireCondition(parsed.positionals.length === 2);
  const webRoot = path.resolve(parsed.values['web-root'] ?? fileURLToPath(new URL('../web/', import.meta.url)));
  phase = 'dependencies';
  const webRequire = createRequire(path.join(webRoot, 'package.json'));
  const formatsPackage = webRequire.resolve('ajv-formats/package.json');
  // Resolve Ajv from ajv-formats' own dependency graph, not a hoisted Ajv 6.
  const formatsRequire = createRequire(formatsPackage);
  const module = formatsRequire('ajv/dist/2020.js');
  const formats = webRequire('ajv-formats');
  const dependencies = { Ajv2020: module.default ?? module, addFormats: formats.default ?? formats };
  const version = formatsRequire('ajv/package.json').version;
  requireCondition(typeof version === 'string' && version.startsWith('8.'));
  phase = 'bounded-input';
  const documents = parsed.positionals.map(readDocument);
  const validators = [];
  const results = {};
  for (let index = 0; index < documents.length; index++) {
    const audience = index === 0 ? 'browser' : 'automation';
    phase = `${audience}-structure`;
    const checked = structure(documents[index], audience);
    phase = `${audience}-schema`;
    validators.push(schemaValidators(documents[index], checked.inline, audience, dependencies));
    results[audience] = { paths: checked.paths, operations: checked.operations, schemas: validators[index].size, inline_schemas: checked.inline.length };
  }
  phase = 'synthetic-cases';
  const cases = syntheticCases(validators[0], validators[1]);
  process.stdout.write(`${JSON.stringify({
    status: 'passed', ajv: version, documents: results, cases,
    scope: 'Draft2020-12 meta-validation, schema compilation, selected structure and synthetic constraints; not full OpenAPI or API conformance',
  })}\n`);
}

try {
  // ESM resolves its own URL through symlinks. Canonicalize the entry as well:
  // spelling/case/junction aliases must not silently turn a CLI run into an
  // import that exits successfully without checking either document.
  if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))) {
    main();
  }
} catch {
  // Never print Ajv errors, submitted instances, file contents or paths.
  process.stderr.write(`${JSON.stringify({ status: 'failed', phase })}\n`);
  process.exitCode = 1;
}
