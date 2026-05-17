import { describe, expect, it } from 'vitest';
import { fieldTypeToTs } from '../../src/codegen/type-mapping.js';

describe('fieldTypeToTs', () => {
  it.each([
    ['u64', 'bigint'],
    ['u128', 'bigint'],
    ['bool', 'boolean'],
    ['fp', 'Hex'],
    ['bytes32', 'Hex'],
    ['address', 'Hex'],
  ] as const)('maps %s to %s', (type, expected) => {
    expect(fieldTypeToTs({ type })).toBe(expected);
  });

  it('wraps array of scalar in ReadonlyArray', () => {
    expect(fieldTypeToTs({ type: 'array', kind: { type: 'fp' }, len: 32 })).toBe(
      'ReadonlyArray<Hex>',
    );
    expect(fieldTypeToTs({ type: 'array', kind: { type: 'u64' }, len: 4 })).toBe(
      'ReadonlyArray<bigint>',
    );
    expect(fieldTypeToTs({ type: 'array', kind: { type: 'bool' }, len: 32 })).toBe(
      'ReadonlyArray<boolean>',
    );
  });

  it('recurses into nested arrays', () => {
    expect(
      fieldTypeToTs({
        type: 'array',
        kind: { type: 'array', kind: { type: 'bool' }, len: 8 },
        len: 4,
      }),
    ).toBe('ReadonlyArray<ReadonlyArray<boolean>>');
  });
});
