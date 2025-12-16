#!/usr/bin/env node
'use strict';

/**
 * Build a JSON array suitable for the /auth/register-trainers endpoint using
 * the artifacts generated under nodes-setup/.
 *
 * Example:
 *   node scripts/build-bulk-register-payload.js \
 *     --did-template did:nebula:hospitalA-{trainerId} \
 *     --jwt-template {trainerId}
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const SETUP_DIR = path.join(ROOT, 'nodes-setup');
const DEFAULTS = {
  nodesDir: path.join(SETUP_DIR, 'nodes'),
  signedDir: path.join(SETUP_DIR, 'vc-signed'),
  keysDir: path.join(SETUP_DIR, 'keys'),
  output: path.join(SETUP_DIR, 'bulk-register.json'),
  didTemplate: 'did:nebula:{trainerId}',
  jwtTemplate: '{trainerId}',
  force: false,
};

function parseArgs(argv) {
  const opts = { ...DEFAULTS };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--nodes':
        opts.nodesDir = path.resolve(argv[++i]);
        break;
      case '--signed':
        opts.signedDir = path.resolve(argv[++i]);
        break;
      case '--keys':
        opts.keysDir = path.resolve(argv[++i]);
        break;
      case '--output':
        opts.output = path.resolve(argv[++i]);
        break;
      case '--did-template':
        opts.didTemplate = argv[++i];
        break;
      case '--jwt-template':
        opts.jwtTemplate = argv[++i];
        break;
      case '--force':
        opts.force = true;
        break;
      default:
        throw new Error(`Unknown flag: ${arg}`);
    }
  }
  return opts;
}

function readNodes(nodesDir) {
  const files = fs.readdirSync(nodesDir).filter((f) => f.endsWith('.json')).sort();
  if (!files.length) {
    throw new Error(`No node definition files found in ${nodesDir}`);
  }
  return files.map((file, idx) => {
    const full = path.join(nodesDir, file);
    const data = JSON.parse(fs.readFileSync(full, 'utf8'));
    return { file, full, index: idx, data };
  });
}

function deriveTrainerId(nodeId, index) {
  const name = String(nodeId || '');
  const match = name.match(/(\d+)(?!.*\d)/);
  if (match) {
    const seq = parseInt(match[1], 10) + 1;
    return `trainer-node-${String(seq).padStart(3, '0')}`;
  }
  const fallback = name || `node-${index + 1}`;
  return `trainer-${fallback.replace(/[^a-z0-9]+/gi, '-').replace(/^-+|-+$/g, '') || String(index + 1)}`;
}

function template(str, ctx) {
  return str
    .replace(/{trainerId}/g, ctx.trainerId)
    .replace(/{nodeId}/g, ctx.nodeId)
    .replace(/{index}/g, String(ctx.index + 1))
    .replace(/{trainerSeq}/g, ctx.trainerSeq);
}

function loadPublicKey(trainerId, keysDir) {
  const file = path.join(keysDir, `${trainerId}_public_key.b64`);
  return fs.readFileSync(file, 'utf8').trim();
}

function loadSignedVC(trainerId, signedDir) {
  const file = path.join(signedDir, `${trainerId}_vc.json`);
  const raw = fs.readFileSync(file, 'utf8');
  return JSON.parse(raw);
}

function main() {
  try {
    const opts = parseArgs(process.argv);
    const nodes = readNodes(opts.nodesDir);
    const payload = [];
    nodes.forEach(({ data, index }) => {
      const nodeIdRaw = data.node_id || data.nodeId || `node_${index + 1}`;
      const trainerId = deriveTrainerId(nodeIdRaw, index);
      const match = trainerId.match(/(\d+)(?!.*\d)/);
      const seq = match ? match[1] : String(index + 1).padStart(3, '0');
      const ctx = { trainerId, nodeId: nodeIdRaw, index, trainerSeq: seq };
      const vcPayload = loadSignedVC(trainerId, opts.signedDir);
      let did = data.did ? String(data.did).trim() : '';
      if (!did && opts.didTemplate) {
        did = template(opts.didTemplate, ctx);
      }
      if (!did && typeof vcPayload.subject === 'string') {
        did = vcPayload.subject;
      }
      if (!did) {
        throw new Error(`Unable to determine DID for ${trainerId}`);
      }
      const jwtSub = template(opts.jwtTemplate, ctx);
      const entry = {
        did,
        nodeId: trainerId,
        public_key: loadPublicKey(trainerId, opts.keysDir),
        vc: vcPayload,
        jwt_sub: jwtSub,
      };
      payload.push(entry);
    });
    const output = JSON.stringify(payload, null, 2);
    if (!opts.force && fs.existsSync(opts.output)) {
      throw new Error(`Output file ${opts.output} exists. Use --force to overwrite.`);
    }
    fs.writeFileSync(opts.output, `${output}\n`);
    console.log(`Bulk registration payload written to ${opts.output}`);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();
