#!/usr/bin/env node
'use strict';

/**
 * Register and enroll trainer identities with the Fabric CA so that each
 * trainer has MSP material under organizations/.../users/<trainer-id>.
 *
 * The script assumes the Fabric CA server is running and reachable from the
 * host. Customize the CA URL, TLS cert, admin home, etc. with the provided
 * flags. Secrets default to "<trainerId>pw".
 *
 * Notable flags:
 *   --canonical-ca-cert <path|skip>   Copy this CA cert into each trainer MSP.
 *
 * Example:
 *   node scripts/enroll-trainer-identities.js \
 *     --ca-url http://localhost:7054 \
 *     --ca-name ca-org1 \
 *     --tls-cert organizations/peerOrganizations/org1.nebula.com/msp/cacerts/ca.org1.nebula.com-cert.pem
 */

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const SETUP_DIR = path.join(ROOT, 'nodes-setup');
const DEFAULT_NODES_DIR = path.join(SETUP_DIR, 'nodes');
const ORG_ROOT = path.join(ROOT, 'organizations', 'peerOrganizations', 'org1.nebula.com');
const DEFAULT_USERS_DIR = path.join(ORG_ROOT, 'users');
const DEFAULT_ADMIN_HOME = path.join(DEFAULT_USERS_DIR, 'Admin@org1.nebula.com');
const DEFAULT_TLS_CERT = path.join(ORG_ROOT, 'tlsca', 'tlsca.org1.nebula.com-cert.pem');
const DEFAULT_MSP_TEMPLATE = path.join(ORG_ROOT, 'msp', 'config.yaml');
const DEFAULT_CANONICAL_CA_CERT = path.join(
  ORG_ROOT,
  'msp',
  'cacerts',
  'ca.org1.nebula.com-cert.pem',
);

const defaults = {
  nodesDir: DEFAULT_NODES_DIR,
  usersDir: DEFAULT_USERS_DIR,
  adminHome: DEFAULT_ADMIN_HOME,
  tlsCert: DEFAULT_TLS_CERT,
  mspTemplate: DEFAULT_MSP_TEMPLATE,
  canonicalCACert: DEFAULT_CANONICAL_CA_CERT,
  caURL: 'http://localhost:7054',
  caName: 'ca-org1',
  secretTemplate: '{trainerId}pw',
  skipRegister: false,
  skipTLS: false,
  force: false,
};

function parseArgs(argv) {
  const opts = { ...defaults };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--nodes':
        opts.nodesDir = path.resolve(argv[++i]);
        break;
      case '--users':
        opts.usersDir = path.resolve(argv[++i]);
        break;
      case '--admin-home':
        opts.adminHome = path.resolve(argv[++i]);
        break;
      case '--tls-cert':
        opts.tlsCert = path.resolve(argv[++i]);
        break;
      case '--msp-template':
        opts.mspTemplate = path.resolve(argv[++i]);
        break;
      case '--canonical-ca-cert': {
        const value = argv[++i];
        if (!value || value.toLowerCase() === 'none' || value.toLowerCase() === 'skip') {
          opts.canonicalCACert = null;
        } else {
          opts.canonicalCACert = path.resolve(value);
        }
        break;
      }
      case '--ca-url':
        opts.caURL = argv[++i];
        break;
      case '--ca-name':
        opts.caName = argv[++i];
        break;
      case '--secret-template':
        opts.secretTemplate = argv[++i];
        break;
      case '--skip-register':
        opts.skipRegister = true;
        i -= 1;
        break;
      case '--skip-tls':
        opts.skipTLS = true;
        i -= 1;
        break;
      case '--force':
        opts.force = true;
        i -= 1;
        break;
      default:
        throw new Error(`Unknown flag: ${arg}`);
    }
  }
  return opts;
}

function readNodes(dir) {
  if (!fs.existsSync(dir)) {
    throw new Error(`nodes directory not found: ${dir}`);
  }
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.json')).sort();
  if (!files.length) {
    throw new Error(`no node definitions found in ${dir}`);
  }
  return files.map((file, index) => {
    const data = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'));
    return { file, data, index };
  });
}

function deriveTrainerId(nodeId, index) {
  const str = String(nodeId || '');
  const match = str.match(/(\d+)(?!.*\d)/);
  if (match) {
    const seq = parseInt(match[1], 10) + 1;
    return `trainer-node-${String(seq).padStart(3, '0')}`;
  }
  const fallback = str || `node-${index + 1}`;
  const sanitized = fallback.replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '');
  if (sanitized) {
    return `trainer-${sanitized.toLowerCase()}`;
  }
  return `trainer-node-${String(index + 1).padStart(3, '0')}`;
}

function template(str, ctx) {
  return str
    .replace(/{trainerId}/g, ctx.trainerId)
    .replace(/{nodeId}/g, ctx.nodeId)
    .replace(/{index}/g, String(ctx.index + 1));
}

function ensureFile(pathToCheck, description) {
  if (!fs.existsSync(pathToCheck)) {
    throw new Error(`${description} not found at ${pathToCheck}`);
  }
}

function runFabricCA(args, opts, allowFailure = false) {
  const env = {
    ...process.env,
    FABRIC_CA_CLIENT_HOME: opts.adminHome,
  };
  const result = spawnSync('fabric-ca-client', args, {
    cwd: ROOT,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.status !== 0) {
    const stderr = (result.stderr || '').trim();
    if (allowFailure) {
      return { ok: false, output: stderr };
    }
    throw new Error(stderr || `fabric-ca-client exited with code ${result.status}`);
  }
  return { ok: true, output: (result.stdout || '').trim() };
}

function extractEndpoint(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol}//${parsed.host}`;
  } catch (err) {
    throw new Error(`invalid CA URL: ${url}`);
  }
}

function registerTrainer(trainerId, secret, opts) {
  if (opts.skipRegister) {
    return { status: 'skipped' };
  }
  const endpoint = extractEndpoint(opts.caURL);
  const args = [
    'register',
    '--caname',
    opts.caName,
    '--id.name',
    trainerId,
    '--id.secret',
    secret,
    '--id.type',
    'client',
    '--tls.certfiles',
    opts.tlsCert,
    '--url',
    endpoint,
  ];
  const result = runFabricCA(args, opts, true);
  if (!result.ok && /already registered/i.test(result.output || '')) {
    return { status: 'exists' };
  }
  if (!result.ok) {
    throw new Error(result.output || `failed to register ${trainerId}`);
  }
  return { status: 'registered' };
}

function enrollTrainer(trainerId, secret, opts) {
  const endpoint = new URL(opts.caURL);
  const enrollURL = `${endpoint.protocol}//${encodeURIComponent(trainerId)}:${encodeURIComponent(secret)}@${endpoint.host}`;
  const mspDir = path.join(opts.usersDir, trainerId, 'msp');
  if (!opts.force && fs.existsSync(mspDir) && fs.readdirSync(mspDir).length > 0) {
    ensureConfigTemplate(mspDir, opts, false);
    syncCanonicalCACert(mspDir, opts, false);
    return { status: 'exists', mspDir };
  }
  fs.mkdirSync(mspDir, { recursive: true });
  const args = [
    'enroll',
    '-u',
    enrollURL,
    '--caname',
    opts.caName,
    '-M',
    mspDir,
    '--tls.certfiles',
    opts.tlsCert,
  ];
  runFabricCA(args, opts);
  ensureConfigTemplate(mspDir, opts, true);
  syncCanonicalCACert(mspDir, opts, true);
  return { status: 'enrolled', mspDir };
}

function enrollTLS(trainerId, secret, opts) {
  if (opts.skipTLS) {
    return { status: 'skipped' };
  }
  const endpoint = new URL(opts.caURL);
  const enrollURL = `${endpoint.protocol}//${encodeURIComponent(trainerId)}:${encodeURIComponent(secret)}@${endpoint.host}`;
  const tlsDir = path.join(opts.usersDir, trainerId, 'tls');
  if (!opts.force && fs.existsSync(tlsDir) && fs.readdirSync(tlsDir).length > 0) {
    return { status: 'exists', tlsDir };
  }
  fs.mkdirSync(tlsDir, { recursive: true });
  const args = [
    'enroll',
    '-u',
    enrollURL,
    '--caname',
    opts.caName,
    '-M',
    tlsDir,
    '--enrollment.profile',
    'tls',
    '--csr.hosts',
    trainerId,
    '--csr.hosts',
    'localhost',
    '--tls.certfiles',
    opts.tlsCert,
  ];
  runFabricCA(args, opts);
  finalizeTLSArtifacts(tlsDir);
  return { status: 'enrolled', tlsDir };
}

function ensureConfigTemplate(mspDir, opts, overwrite) {
  if (!opts.mspTemplate) {
    return;
  }
  ensureFile(opts.mspTemplate, 'MSP template');
  const destination = path.join(mspDir, 'config.yaml');
  if (!overwrite && fs.existsSync(destination)) {
    return;
  }
  fs.copyFileSync(opts.mspTemplate, destination);
}

function syncCanonicalCACert(mspDir, opts, overwrite) {
  if (!opts.canonicalCACert) {
    return;
  }
  ensureFile(opts.canonicalCACert, 'Canonical CA cert');
  const caDir = path.join(mspDir, 'cacerts');
  fs.mkdirSync(caDir, { recursive: true });
  const desiredName = path.basename(opts.canonicalCACert);
  const destination = path.join(caDir, desiredName);
  if (!overwrite && fs.existsSync(destination)) {
    return;
  }
  fs.copyFileSync(opts.canonicalCACert, destination);
}

function finalizeTLSArtifacts(tlsDir) {
  const caDir = path.join(tlsDir, 'tlscacerts');
  const signDir = path.join(tlsDir, 'signcerts');
  const keyDir = path.join(tlsDir, 'keystore');
  const caFiles = fs.existsSync(caDir) ? fs.readdirSync(caDir) : [];
  const certFiles = fs.existsSync(signDir) ? fs.readdirSync(signDir) : [];
  const keyFiles = fs.existsSync(keyDir) ? fs.readdirSync(keyDir) : [];
  if (!caFiles.length || !certFiles.length || !keyFiles.length) {
    throw new Error(`TLS enrollment incomplete under ${tlsDir}`);
  }
  fs.copyFileSync(path.join(caDir, caFiles[0]), path.join(tlsDir, 'ca.crt'));
  fs.copyFileSync(path.join(signDir, certFiles[0]), path.join(tlsDir, 'client.crt'));
  fs.copyFileSync(path.join(keyDir, keyFiles[0]), path.join(tlsDir, 'client.key'));
}

function main() {
  try {
    const opts = parseArgs(process.argv);
    ['fabric-ca-client'].forEach((binary) => {
      const check = spawnSync(binary, ['version'], { encoding: 'utf8' });
      if (check.status !== 0) {
        throw new Error(`${binary} is not available in PATH`);
      }
    });
    ensureFile(opts.tlsCert, 'CA TLS cert');
    ensureFile(opts.adminHome, 'CA admin home');
    const nodes = readNodes(opts.nodesDir);
    const summary = [];
    nodes.forEach(({ data, index }) => {
      const nodeId = data.node_id || data.nodeId || `node_${index + 1}`;
      const trainerId = deriveTrainerId(nodeId, index);
      const secret = template(opts.secretTemplate, { trainerId, nodeId, index });
      const registerInfo = registerTrainer(trainerId, secret, opts);
      const enrollInfo = enrollTrainer(trainerId, secret, opts);
      const tlsInfo = enrollTLS(trainerId, secret, opts);
      summary.push({
        trainerId,
        nodeId,
        secret,
        registerStatus: registerInfo.status,
        enrollStatus: enrollInfo.status,
        tlsStatus: tlsInfo.status,
      });
    });
    console.log('Enrollment summary:');
    summary.forEach((entry) => {
      console.log(
        `- ${entry.trainerId}: register=${entry.registerStatus} msp=${entry.enrollStatus} tls=${entry.tlsStatus}`,
      );
    });
    console.log('Done.');
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();
