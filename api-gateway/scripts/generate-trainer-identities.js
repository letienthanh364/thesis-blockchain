#!/usr/bin/env node
'use strict';

/**
 * Generate Ed25519 keypairs and unsigned VC payloads for every trainer node
 * definition found under ../nodes. Private keys and public key artifacts are
 * stored under ../keys and VC JSON bodies are written to ../api/vc-unsigned.
 *
 * Usage examples:
 *   node scripts/generate-trainer-identities.js
 *   node scripts/generate-trainer-identities.js --force --issuer did:nebula:admin002
 *   node scripts/generate-trainer-identities.js --job-id-template job_{nodeId}
 *
 * Flags:
 *   --issuer <did>               VC issuer DID. Default: did:nebula:admin001
 *   --subject-prefix <did>       Prefix added to trainer IDs for VC subjects. Default: did:nebula
 *   --subject-template <tmpl>    Optional template; supports {trainerId} and {nodeId}.
 *   --job-id <value>             Static job identifier.
 *   --job-id-template <tmpl>     Template for job IDs. Supports {trainerId}, {nodeId}, {dataset}.
 *   --valid-from <ISO8601>       Validity window start. Default: now.
 *   --valid-until <ISO8601>      Validity window end. Default: +365 days.
 *   --permissions <csv>          Comma-separated permissions list. Default: train,commit.
 *   --force                      Overwrite any existing artifacts.
 */

const fs = require('fs');
const path = require('path');
const { generateKeyPairSync } = require('crypto');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const SETUP_DIR = path.join(ROOT, 'nodes-setup');
const NODES_DIR = path.join(SETUP_DIR, 'nodes');
const KEYS_DIR = path.join(SETUP_DIR, 'keys');
const VC_DIR = path.join(SETUP_DIR, 'vc-unsigned');
const TOKENS_DIR = path.join(SETUP_DIR, 'tokens');

const defaultOptions = {
  issuer: 'did:nebula:admin001',
  subjectPrefix: 'did:nebula',
  subjectTemplate: null,
  jobId: 'job_2025_heart_model',
  jobIdTemplate: null,
  validFrom: new Date().toISOString(),
  validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
  permissions: ['train', 'commit'],
  force: false,
  jwtScript: path.join(ROOT, 'jwt.js'),
  jwtModes: [],
  authSecret: process.env.AUTH_JWT_SECRET || null,
};

function parseArgs(argv) {
  const opts = { ...defaultOptions };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--issuer':
        opts.issuer = argv[++i];
        break;
      case '--subject-prefix':
        opts.subjectPrefix = argv[++i];
        break;
      case '--subject-template':
        opts.subjectTemplate = argv[++i];
        break;
      case '--job-id':
        opts.jobId = argv[++i];
        opts.jobIdTemplate = null;
        break;
      case '--job-id-template':
        opts.jobIdTemplate = argv[++i];
        opts.jobId = null;
        break;
      case '--valid-from':
        opts.validFrom = argv[++i];
        break;
      case '--valid-until':
        opts.validUntil = argv[++i];
        break;
      case '--permissions':
        opts.permissions = argv[++i].split(',').map((item) => item.trim()).filter(Boolean);
        break;
      case '--generate-jwt':
        opts.jwtModes = argv[++i].split(',').map((item) => item.trim().toLowerCase()).filter(Boolean);
        break;
      case '--auth-secret':
        opts.authSecret = argv[++i];
        break;
      case '--jwt-script':
        opts.jwtScript = path.resolve(argv[++i]);
        break;
      case '--force':
        opts.force = true;
        break;
      default:
        console.error(`Unknown flag: ${arg}`);
        process.exit(1);
    }
  }
  if (opts.jwtModes.length) {
    const normalized = [];
    opts.jwtModes.forEach((mode) => {
      if (mode === 'both') {
        normalized.push('registration', 'runtime');
      } else if (mode === 'registration' || mode === 'runtime') {
        normalized.push(mode);
      } else if (mode) {
        console.error(`Unknown JWT mode: ${mode}. Use registration, runtime, or both.`);
        process.exit(1);
      }
    });
    opts.jwtModes = [...new Set(normalized)];
  }
  return opts;
}

function readNodeDefinitions() {
  if (!fs.existsSync(NODES_DIR)) {
    console.error(`Nodes directory not found: ${NODES_DIR}`);
    process.exit(1);
  }
  const files = fs.readdirSync(NODES_DIR)
    .filter((file) => file.endsWith('.json'))
    .sort();
  if (!files.length) {
    console.error(`No node definitions found in ${NODES_DIR}`);
    process.exit(1);
  }
  return files.map((file) => {
    const fullPath = path.join(NODES_DIR, file);
    const raw = fs.readFileSync(fullPath, 'utf8');
    return { file, fullPath, data: JSON.parse(raw) };
  });
}

function ensureDirectories(generateTokens) {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  fs.mkdirSync(VC_DIR, { recursive: true });
  if (generateTokens) {
    fs.mkdirSync(TOKENS_DIR, { recursive: true });
  }
}

function sanitize(str) {
  return String(str)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function deriveTrainerId(node, index) {
  if (node.trainer_id) {
    return String(node.trainer_id).trim();
  }
  const nodeId = node.node_id || node.nodeId || '';
  const asString = String(nodeId);
  const match = asString.match(/(\d+)(?!.*\d)/);
  if (match) {
    const seq = parseInt(match[1], 10);
    return `trainer-node-${String(seq).padStart(3, '0')}`;
  }
  const fallback = sanitize(`trainer-${asString || index}`);
  return fallback || `trainer-node-${String(index + 1).padStart(3, '0')}`;
}

function deriveSubject(nodeId, trainerId, opts) {
  if (opts.subjectTemplate) {
    return opts.subjectTemplate
      .replace(/{nodeId}/g, nodeId)
      .replace(/{trainerId}/g, trainerId);
  }
  return `${opts.subjectPrefix}:${trainerId}`;
}

function deriveJobId(node, trainerId, opts) {
  if (opts.jobIdTemplate) {
    const datasetName = node.dataset?.name || 'dataset';
    return opts.jobIdTemplate
      .replace(/{nodeId}/g, node.node_id || '')
      .replace(/{trainerId}/g, trainerId)
      .replace(/{dataset}/g, datasetName);
  }
  if (opts.jobId) {
    return opts.jobId;
  }
  const dataset = sanitize(node.dataset?.name || 'dataset');
  return `job_${dataset}`;
}

function writeKeyMaterial(trainerId, opts) {
  const privateKeyPath = path.join(KEYS_DIR, `${trainerId}_sk.pem`);
  const publicKeyPemPath = path.join(KEYS_DIR, `${trainerId}_pk.pem`);
  const publicKeyB64Path = path.join(KEYS_DIR, `${trainerId}_public_key.b64`);

  if (!opts.force && fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyB64Path)) {
    return {
      privateKeyPath,
      publicKeyPemPath,
      publicKeyB64Path,
      publicKeyB64: fs.readFileSync(publicKeyB64Path, 'utf8').trim(),
      created: false,
    };
  }

  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privatePem = privateKey.export({ format: 'pem', type: 'pkcs8' });
  const publicPem = publicKey.export({ format: 'pem', type: 'spki' });
  const publicDer = publicKey.export({ format: 'der', type: 'spki' });
  const rawPublicKey = publicDer.slice(-32);
  const publicKeyB64 = rawPublicKey.toString('base64');

  fs.writeFileSync(privateKeyPath, privatePem, { mode: 0o600 });
  fs.writeFileSync(publicKeyPemPath, publicPem);
  fs.writeFileSync(publicKeyB64Path, `${publicKeyB64}\n`);

  return {
    privateKeyPath,
    publicKeyPemPath,
    publicKeyB64Path,
    publicKeyB64,
    created: true,
  };
}

function writeUnsignedVc(trainerId, vcPayload, opts) {
  const vcPath = path.join(VC_DIR, `${trainerId}.json`);
  if (!opts.force && fs.existsSync(vcPath)) {
    return { vcPath, created: false };
  }
  fs.writeFileSync(vcPath, `${JSON.stringify(vcPayload, null, 2)}\n`);
  return { vcPath, created: true };
}

function generateJwt(trainerId, subject, opts, mode, keyInfo) {
  const outputPath = path.join(TOKENS_DIR, `${trainerId}_${mode}.jwt`);
  if (!opts.force && fs.existsSync(outputPath)) {
    return { mode, outputPath, created: false, token: fs.readFileSync(outputPath, 'utf8').trim() };
  }

  const env = { ...process.env, JWT_SUB: subject };
  const args = [opts.jwtScript, '--sub', subject];
  if (mode === 'registration') {
    if (!opts.authSecret) {
      throw new Error('Registration JWT requested but --auth-secret or AUTH_JWT_SECRET is missing');
    }
    env.JWT_ALG = 'HS256';
    env.AUTH_JWT_SECRET = opts.authSecret;
  } else if (mode === 'runtime') {
    env.JWT_ALG = 'EdDSA';
    env.TRAINER_PRIVATE_KEY = keyInfo.privateKeyPath;
  } else {
    throw new Error(`Unknown JWT mode ${mode}`);
  }

  const result = spawnSync('node', args, { env, cwd: ROOT, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(`Failed to generate ${mode} JWT for ${trainerId}: ${result.stderr || result.stdout}`);
  }

  const token = result.stdout.trim();
  fs.writeFileSync(outputPath, `${token}\n`);
  return { mode, outputPath, created: true, token };
}

function main() {
  const options = parseArgs(process.argv);
  ensureDirectories(options.jwtModes.length > 0);
  const nodes = readNodeDefinitions();
  const summary = [];

  nodes.forEach(({ data }, index) => {
    const trainerId = deriveTrainerId(data, index);
    const nodeLabel = data.node_id || data.nodeId || `node_${index + 1}`;
    const subject = deriveSubject(nodeLabel, trainerId, options);
    const jobId = deriveJobId(data, trainerId, options);

    const keyInfo = writeKeyMaterial(trainerId, options);
    const vcPayload = {
      issuer: options.issuer,
      subject,
      job_id: jobId,
      valid_from: options.validFrom,
      valid_until: options.validUntil,
      permissions: options.permissions,
    };
    const vcInfo = writeUnsignedVc(trainerId, vcPayload, options);

    const tokens = [];
    if (options.jwtModes.length) {
      options.jwtModes.forEach((mode) => {
        tokens.push(generateJwt(trainerId, subject, options, mode, keyInfo));
      });
    }

    summary.push({
      trainerId,
      subject,
      publicKey: keyInfo.publicKeyB64,
      keyCreated: keyInfo.created,
      vcCreated: vcInfo.created,
      vcPath: vcInfo.vcPath,
      tokens,
    });
  });

  console.log('Trainer artifacts:');
  summary.forEach((entry) => {
    const base =
      `- ${entry.trainerId}: VC=${path.relative(ROOT, entry.vcPath)} ` +
      `(new VC: ${entry.vcCreated}, new keys: ${entry.keyCreated}) ` +
      `pub=${entry.publicKey}`;
    const tokenStr = entry.tokens.length
      ? ` tokens=${entry.tokens.map((t) => `${t.mode}:${path.relative(ROOT, t.outputPath)}`).join(', ')}`
      : '';
    console.log(base + tokenStr);
  });
  console.log('Done.');
}

main();
