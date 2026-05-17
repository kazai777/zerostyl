import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { CliError, parseCli, runCli } from '../src/cli.js';

const here = dirname(fileURLToPath(import.meta.url));
const abiPath = resolve(here, '../../../examples/zk_private_demo/abi.json');

describe('parseCli', () => {
  it('parses generate --abi <path>', () => {
    const opts = parseCli(['generate', '--abi', '/some/abi.json']);
    expect(opts).toEqual({ command: 'generate', abi: '/some/abi.json', out: undefined });
  });

  it('parses --out alongside --abi', () => {
    const opts = parseCli(['generate', '--abi', '/a', '--out', '/o']);
    expect(opts.out).toBe('/o');
  });

  it('accepts short flags -a and -o', () => {
    const opts = parseCli(['generate', '-a', '/a', '-o', '/o']);
    expect(opts.abi).toBe('/a');
    expect(opts.out).toBe('/o');
  });

  it('rejects an unknown command', () => {
    expect(() => parseCli(['build'])).toThrow(CliError);
    expect(() => parseCli([])).toThrow(/expected 'generate'/);
  });

  it('rejects missing --abi', () => {
    expect(() => parseCli(['generate'])).toThrow(/missing required --abi/);
  });

  it('rejects unknown flags in strict mode', () => {
    expect(() => parseCli(['generate', '--abi', '/a', '--rogue'])).toThrow();
  });
});

describe('runCli', () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'zs-sdk-cli-'));
  });
  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it('returns generated TS when --out is omitted', () => {
    const out = runCli(['generate', '--abi', abiPath]);
    expect(out).toBeDefined();
    expect(out).toContain('export const DepositCircuit');
    expect(out).toContain('export interface DepositWitness');
    expect(out).toContain('export interface DepositPublicInputs');
  });

  it('writes to file and returns undefined when --out is provided', () => {
    const outFile = join(tmpDir, 'generated.ts');
    const ret = runCli(['generate', '--abi', abiPath, '--out', outFile]);
    expect(ret).toBeUndefined();
    const written = readFileSync(outFile, 'utf8');
    expect(written).toContain('export const DepositCircuit');
  });

  it('throws when the abi file does not exist', () => {
    expect(() => runCli(['generate', '--abi', join(tmpDir, 'nonexistent.json')])).toThrow();
  });
});
