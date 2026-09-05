import fs from 'node:fs';
import path from 'node:path';
import { DEFAULT_LITE_MODEL, DEFAULT_MAIN_MODEL } from './constants.mjs';
import { CliError } from './errors.mjs';
import { atomicWrite, jsonBytes, readOptional, restoreOptional, sha256 } from './fs-atomic.mjs';

function parseObject(bytes, file) {
  if (bytes === null) return {};
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); } catch {
    throw new CliError('INVALID_ZCODE_CONFIG', `${file} is not valid JSON`);
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new CliError('INVALID_ZCODE_CONFIG', `${file} must contain a JSON object`);
  }
  return value;
}

function modelEntry(existing, id) {
  return { ...(existing && typeof existing === 'object' ? existing : {}), name: existing?.name || id };
}

export function desiredCatalog(config, { mainModel = DEFAULT_MAIN_MODEL, liteModel = DEFAULT_LITE_MODEL } = {}) {
  if (!/^[A-Za-z0-9._-]+$/.test(mainModel) || !/^[A-Za-z0-9._-]+$/.test(liteModel)) {
    throw new CliError('INVALID_MODEL', 'model IDs may contain only letters, numbers, dot, underscore, and dash');
  }
  const next = structuredClone(config);
  next.provider ??= {};
  next.provider.zai ??= {};
  next.provider.zai.models ??= {};
  next.provider.zai.models[mainModel] = modelEntry(next.provider.zai.models[mainModel], mainModel);
  next.provider.zai.models[liteModel] = modelEntry(next.provider.zai.models[liteModel], liteModel);
  next.model ??= {};
  next.model.main = `zai/${mainModel}`;
  next.model.lite = `zai/${liteModel}`;
  return next;
}

export function verifyCatalog(config, { mainModel = DEFAULT_MAIN_MODEL, liteModel = DEFAULT_LITE_MODEL } = {}) {
  return Boolean(config?.provider?.zai?.models?.[mainModel])
    && Boolean(config?.provider?.zai?.models?.[liteModel])
    && config?.model?.main === `zai/${mainModel}`
    && config?.model?.lite === `zai/${liteModel}`;
}

export function patchCatalog(configPath, provenancePath, options = {}) {
  const originalConfig = readOptional(configPath);
  const originalProvenance = readOptional(provenancePath);
  const next = desiredCatalog(parseObject(originalConfig, configPath), options);
  const nextBytes = jsonBytes(next);
  const record = {
    schema_version: 1,
    config_path: path.resolve(configPath),
    original_exists: originalConfig !== null,
    original_sha256: originalConfig === null ? null : sha256(originalConfig),
    original_bytes_base64: originalConfig === null ? null : originalConfig.toString('base64'),
    installed_sha256: sha256(nextBytes),
    main_model: options.mainModel || DEFAULT_MAIN_MODEL,
    lite_model: options.liteModel || DEFAULT_LITE_MODEL,
  };
  try {
    atomicWrite(configPath, nextBytes);
    if (typeof options._afterConfigWrite === 'function') options._afterConfigWrite();
    const installed = fs.readFileSync(configPath);
    if (sha256(installed) !== record.installed_sha256 || !verifyCatalog(parseObject(installed, configPath), options)) {
      throw new CliError('MODEL_CONFIG_VERIFY_FAILED', 'model catalog verification failed');
    }
    atomicWrite(provenancePath, jsonBytes(record));
  } catch (error) {
    restoreOptional(configPath, originalConfig);
    restoreOptional(provenancePath, originalProvenance);
    throw error;
  }
  return record;
}

export function restoreCatalog(configPath, provenancePath) {
  const provenanceBytes = readOptional(provenancePath);
  if (provenanceBytes === null) throw new CliError('BACKUP_NOT_FOUND', 'model catalog provenance does not exist');
  const provenance = parseObject(provenanceBytes, provenancePath);
  const current = readOptional(configPath);
  if (current === null || sha256(current) !== provenance.installed_sha256) {
    throw new CliError('CONFIG_CHANGED', 'current model config does not match installed provenance');
  }
  const original = provenance.original_exists
    ? Buffer.from(provenance.original_bytes_base64, 'base64')
    : null;
  if (original !== null && sha256(original) !== provenance.original_sha256) {
    throw new CliError('BACKUP_CORRUPT', 'catalog backup bytes do not match provenance');
  }
  restoreOptional(configPath, original);
  fs.unlinkSync(provenancePath);
  return { restored_sha256: original === null ? null : sha256(original), removed_created_config: original === null };
}
