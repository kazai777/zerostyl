import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const here = dirname(fileURLToPath(import.meta.url));
const binPath = resolve(here, '../bin/zerostyl-sdk.js');
const distCliPath = resolve(here, '../dist/cli.js');
const abiPath = resolve(here, '../../../examples/zk_private_demo/abi.json');

const distAvailable = existsSync(distCliPath);

describe('bin/zerostyl-sdk (requires pnpm build)', () => {
  it.skipIf(!distAvailable)('prints generated TS to stdout via generate --abi', () => {
    const stdout = execFileSync(process.execPath, [binPath, 'generate', '--abi', abiPath], {
      encoding: 'utf8',
    });
    expect(stdout).toContain('export const DepositCircuit');
    expect(stdout).toContain('export interface DepositWitness');
    expect(stdout).toContain('export interface DepositPublicInputs');
  });

  it.skipIf(!distAvailable)('exits 1 with a clear error on unknown command', () => {
    try {
      execFileSync(process.execPath, [binPath, 'unknown'], { encoding: 'utf8' });
      throw new Error('expected non-zero exit');
    } catch (err) {
      const e = err as { status?: number; stderr?: string };
      expect(e.status).toBe(1);
      expect(e.stderr ?? '').toContain("expected 'generate'");
    }
  });
});
