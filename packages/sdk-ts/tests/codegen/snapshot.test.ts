import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { generateBindings } from '../../src/codegen/generator.js';
import { parseAbiSchema } from '../../src/types.js';

const here = dirname(fileURLToPath(import.meta.url));
const abiPath = resolve(here, '../../../../examples/zk_private_demo/abi.json');
const snapshotPath = resolve(here, 'snapshots/zk_private_demo.snap.ts');

function normalize(s: string): string {
  return s.replace(/\r\n/g, '\n');
}

describe('codegen snapshot vs zk_private_demo/abi.json', () => {
  it('generates the committed reference bindings', () => {
    const abi = parseAbiSchema(readFileSync(abiPath, 'utf8'));
    const generated = generateBindings(abi);

    if (process.env.REGEN_SDK_TS_SNAPSHOTS) {
      writeFileSync(snapshotPath, generated);
      return;
    }

    const expected = readFileSync(snapshotPath, 'utf8');
    expect(normalize(generated)).toBe(normalize(expected));
  });
});
