#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { closeSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

// Local-only proposal until the external control route is separately approved.
// Run prepare, retain its credential-free receipt, then run apply in that job.
// No secret-detail requests, secret logging/transfer, or secret rotation.
const ACCOUNT = 'e84b55c82d29ff76b789af0aea3d9121';
const PROJECT = '0sec-ai-homepage';
const PROJECT_ID = '76c877a0-0225-4703-ac8f-f74d74ecf25d';
const SITEKEY = '0x4AAAAAADQF9nRKE8xR1UAF';
const DOMAIN = '0.security';
const API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}`;
const PROJECT_URL = `${API}/pages/projects/${PROJECT}`;
const WIDGET_URL = `${API}/challenges/widgets/${SITEKEY}`;
// List responses omit the secret returned by the widget-detail endpoint.
const WIDGET_READ_URL = `${API}/challenges/widgets?filter=sitekey:${SITEKEY}&per_page=5&page=1`;
const EDITABLE = ['domains', 'mode', 'name', 'bot_fight_mode', 'clearance_level', 'ephemeral_id', 'offlabel', 'region'];
const KNOWN_WIDGET = new Set([...EDITABLE, 'sitekey', 'created_on', 'modified_on', 'deployed_via', 'last_modified_via']);
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const fingerprint = value => createHash('sha256').update(JSON.stringify(value, (_, item) =>
  item && typeof item === 'object' && !Array.isArray(item)
    ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b)))
    : item)).digest('hex');

function context() {
  const env = process.env;
  assert(env.GITHUB_REPOSITORY === '0sec-labs/0sec' && env.GITHUB_REPOSITORY_ID === '1339271188', 'Wrong control repository');
  assert(env.GITHUB_REF === 'refs/heads/chore/pages-preflight-20260916' && env.GITHUB_EVENT_NAME === 'workflow_dispatch', 'Wrong control invocation');
  assert(/^[a-f0-9]{40}$/.test(env.GITHUB_SHA ?? ''), 'Missing control source SHA');
  assert(/^[1-9][0-9]*$/.test(env.GITHUB_RUN_ID ?? '') && /^[1-9][0-9]*$/.test(env.GITHUB_RUN_ATTEMPT ?? ''), 'Missing run identity');
  assert(UUID.test(env.EXPECTED_PRODUCTION ?? ''), 'Expected production UUID required');
  assert(env.RUNNER_TEMP && env.CLOUDFLARE_API_TOKEN, 'Missing runner context or credential');
  return {
    file: join(env.RUNNER_TEMP, `turnstile-domain-${env.GITHUB_RUN_ID}-${env.GITHUB_RUN_ATTEMPT}.json`),
    run_id: env.GITHUB_RUN_ID, run_attempt: env.GITHUB_RUN_ATTEMPT, source: env.GITHUB_SHA,
  };
}

function save(file, value, initial = false) {
  const target = initial ? file : `${file}.${randomUUID()}.tmp`;
  const fd = openSync(target, 'wx', 0o600);
  try { writeFileSync(fd, `${JSON.stringify(value, null, 2)}\n`); fsyncSync(fd); }
  finally { closeSync(fd); }
  if (!initial) renameSync(target, file);
  const directory = openSync(dirname(file), 'r');
  try { fsyncSync(directory); } finally { closeSync(directory); }
}

async function api(url, method = 'GET', body) {
  assert((method === 'GET' && [PROJECT_URL, WIDGET_READ_URL].includes(url)) || (method === 'PUT' && url === WIDGET_URL), 'Unapproved request');
  const response = await fetch(url, {
    method, redirect: 'error', signal: AbortSignal.timeout(30_000),
    headers: { Authorization: `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`, 'Content-Type': 'application/json' },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  assert(response.ok, `Cloudflare ${method} failed (${response.status})`);
  // A widget update may return its secret. Never parse or retain that response.
  if (method === 'PUT') { await response.body?.cancel(); return; }
  const value = await response.json();
  assert(value.success === true && value.result !== undefined, 'Invalid Cloudflare read response');
  return value;
}

async function project() {
  const value = (await api(PROJECT_URL)).result;
  assert(value.id === PROJECT_ID && value.name === PROJECT, 'Wrong Pages project');
  assert(value.production_branch === 'main' && value.domains?.includes(DOMAIN), 'Wrong Pages domain or branch');
  const source = value.source;
  assert(source?.type === 'github' && source.config?.owner === '0sec-labs' && String(source.config.repo_id) === '1202833352' && source.config.production_branch === 'main', 'Wrong private source identity');
  assert(source.config.production_deployments_enabled === false && source.config.preview_deployment_setting === 'none', 'Automatic deployments must remain frozen');
  const canonical = value.canonical_deployment;
  assert(canonical?.id === process.env.EXPECTED_PRODUCTION && canonical.project_name === PROJECT && canonical.environment === 'production', 'Production selection changed');
  assert(canonical.latest_stage?.name === 'deploy' && canonical.latest_stage.status === 'success' && canonical.deployment_trigger?.metadata?.branch === 'main', 'Invalid canonical production');
  return { canonical: canonical.id, source_fingerprint: fingerprint(source), configuration_fingerprint: fingerprint(value.deployment_configs) };
}

function settings(widget) {
  assert(widget.sitekey === SITEKEY && Object.keys(widget).every(key => KNOWN_WIDGET.has(key)), 'Unexpected widget identity or fields');
  assert(Array.isArray(widget.domains) && widget.domains.length > 0 && widget.domains.length <= 10 && widget.domains.every(domain => typeof domain === 'string') && new Set(widget.domains).size === widget.domains.length, 'Invalid widget domains');
  assert(widget.domains.includes('0sec.ai'), 'Existing 0sec.ai domain must be preserved');
  assert(['managed', 'invisible', 'non-interactive'].includes(widget.mode), 'Unknown widget mode');
  assert(typeof widget.name === 'string' && widget.name.length > 0 && widget.name.length <= 254, 'Invalid widget name');
  for (const key of ['bot_fight_mode', 'ephemeral_id', 'offlabel']) assert(typeof widget[key] === 'boolean', `Missing widget setting: ${key}`);
  assert(['no_clearance', 'jschallenge', 'managed', 'interactive'].includes(widget.clearance_level), 'Unknown clearance setting');
  assert(['world', 'china'].includes(widget.region), 'Unknown widget region');
  const result = Object.fromEntries(EDITABLE.map(key => [key, widget[key]]));
  result.domains = [...widget.domains].sort();
  return result;
}

async function widget() {
  const body = await api(WIDGET_READ_URL);
  assert(Array.isArray(body.result), 'Malformed widget inventory');
  const matches = body.result.filter(value => value.sitekey === SITEKEY);
  assert(matches.length === 1, 'Exact existing widget not found uniquely');
  const value = matches[0];
  assert(typeof value.modified_on === 'string' && Number.isFinite(Date.parse(value.modified_on)), 'Missing widget revision');
  return { settings: settings(value), modified_on: value.modified_on };
}

async function main() {
  const [mode, ...extra] = process.argv.slice(2);
  assert(['prepare', 'apply'].includes(mode) && extra.length === 0, 'Use prepare or apply only');
  const run = context();
  if (mode === 'prepare') {
    const beforeProject = await project();
    const before = await widget();
    const after = { ...before.settings, domains: [...new Set([...before.settings.domains, DOMAIN])].sort() };
    assert(after.domains.length <= 10, 'Adding the domain would exceed the existing widget limit');
    const receipt = {
      schema_version: 1, operation: 'add-existing-widget-website-domain',
      state: before.settings.domains.includes(DOMAIN) ? 'already_configured' : 'prepared',
      prepared_at: new Date().toISOString(), account: ACCOUNT, project: PROJECT, project_id: PROJECT_ID, sitekey: SITEKEY,
      run_id: run.run_id, run_attempt: run.run_attempt, source: run.source,
      project_before: beforeProject, widget_before: before, widget_after: after,
      rollback: { method: 'PUT', url: WIDGET_URL, body: before.settings, requires_current_settings_fingerprint: fingerprint(after), requires_fresh_authorization: true },
      put_attempts: 0, mutation_may_have_occurred: false, secret_rotation_performed: false,
      server_secret_pair_verified: false, pages_mutation_performed: false, deployment_performed: false,
    };
    save(run.file, receipt, true);
    console.log(JSON.stringify({ state: receipt.state, receipt: run.file, sitekey: SITEKEY, domains_before: before.settings.domains, domains_after: after.domains }));
    return;
  }

  assert(lstatSync(run.file).isFile() && !lstatSync(run.file).isSymbolicLink(), 'Invalid prepared receipt file');
  const receipt = JSON.parse(readFileSync(run.file, 'utf8'));
  assert(receipt.schema_version === 1 && receipt.operation === 'add-existing-widget-website-domain' && receipt.account === ACCOUNT && receipt.project === PROJECT && receipt.project_id === PROJECT_ID && receipt.sitekey === SITEKEY, 'Wrong receipt identity');
  assert(receipt.run_id === run.run_id && receipt.run_attempt === run.run_attempt && receipt.source === run.source, 'Receipt belongs to another source or run');
  assert(receipt.put_attempts === 0 && ['prepared', 'already_configured'].includes(receipt.state), 'Write attempt already consumed; reconcile with GETs, never retry PUT');
  const planned = { ...receipt.widget_before.settings, domains: [...new Set([...receipt.widget_before.settings.domains, DOMAIN])].sort() };
  assert(fingerprint(planned) === fingerprint(receipt.widget_after), 'Prepared change is not the single approved domain addition');
  const freshProject = await project();
  const freshWidget = await widget();
  assert(fingerprint(freshProject) === fingerprint(receipt.project_before), 'Pages state changed since preparation');
  assert(fingerprint(freshWidget) === fingerprint(receipt.widget_before), 'Widget changed since preparation');
  if (receipt.state === 'already_configured') {
    assert(freshWidget.settings.domains.includes(DOMAIN), 'Previously configured domain disappeared');
    console.log(JSON.stringify({ state: 'already_configured', put_attempts: 0, mutation_performed: false }));
    return;
  }
  assert(!freshWidget.settings.domains.includes(DOMAIN), 'Domain is already configured');
  receipt.state = 'write_started';
  receipt.put_attempts = 1;
  receipt.mutation_may_have_occurred = true;
  save(run.file, receipt);
  let requestAcknowledged = false;
  try { await api(WIDGET_URL, 'PUT', receipt.widget_after); requestAcknowledged = true; }
  catch (error) {
    // Retain bounded HTTP evidence, never a provider response or transport detail.
    receipt.request_failure = /^Cloudflare PUT failed \([1-5][0-9]{2}\)$/.test(error?.message ?? '')
      ? error.message : 'Request interrupted or transport failed';
  }
  // Reconcile with GETs even after an ambiguous PUT. Never issue a second PUT.
  try {
    const afterWidget = await widget();
    const afterProject = await project();
    receipt.observed_widget_after = afterWidget;
    receipt.observed_project_after = afterProject;
    assert(fingerprint(afterWidget.settings) === fingerprint(receipt.widget_after), 'Widget outcome is not the exact prepared configuration');
    assert(fingerprint(afterProject) === fingerprint(receipt.project_before), 'Pages state changed during the widget operation');
    receipt.state = 'verified';
    receipt.verified_at = new Date().toISOString();
    receipt.request_acknowledged = requestAcknowledged;
    receipt.get_reconciled = true;
    save(run.file, receipt);
    console.log(JSON.stringify({ state: receipt.state, receipt: run.file, sitekey: SITEKEY, domains: afterWidget.settings.domains, put_attempts: 1, request_acknowledged: requestAcknowledged, get_reconciled: true, pages_mutation_performed: false, server_secret_pair_verified: false }));
  } catch {
    receipt.state = 'unresolved';
    receipt.request_acknowledged = requestAcknowledged;
    receipt.get_reconciled = false;
    save(run.file, receipt);
    throw new Error('Widget write is unresolved; inspect the retained receipt and reconcile with GETs before any further action');
  }
}

try { await main(); }
catch (error) { console.error(`turnstile domain control: ${error.message}`); process.exitCode = 1; }
