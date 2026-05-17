import { describe, expect, expectTypeOf, it } from 'vitest';
import {
  type AbiSchema,
  type ArrayFieldType,
  type FieldType,
  type Hex,
  isArrayFieldType,
  isScalarFieldType,
  parseAbiSchema,
} from '../src/types.js';

const sample: AbiSchema = {
  abi_version: 1,
  circuit: {
    name: 'demo',
    version: '1.0.0',
    description: 'test fixture',
    default_k: 10,
    num_public_inputs: 1,
    num_private_witnesses: 2,
  },
  witness: {
    fields: [
      { name: 'a', kind: { type: 'u64' }, visibility: 'private' },
      { name: 'a_nonce', kind: { type: 'fp' }, visibility: 'private' },
    ],
  },
  public_inputs: {
    fields: [{ name: 'a_commitment', kind: { type: 'fp' } }],
  },
  proof: {
    format_version: 1,
    proving_system: 'halo2_ipa',
  },
};

describe('Hex template literal type', () => {
  it('accepts 0x-prefixed strings at compile time', () => {
    const valid: Hex = '0xdeadbeef';
    expect(valid).toBe('0xdeadbeef');
    expectTypeOf<Hex>().toMatchTypeOf<`0x${string}`>();
  });
});

describe('FieldType guards', () => {
  it('isScalarFieldType matches every non-array variant', () => {
    expect(isScalarFieldType({ type: 'u64' })).toBe(true);
    expect(isScalarFieldType({ type: 'u128' })).toBe(true);
    expect(isScalarFieldType({ type: 'bool' })).toBe(true);
    expect(isScalarFieldType({ type: 'bytes32' })).toBe(true);
    expect(isScalarFieldType({ type: 'address' })).toBe(true);
    expect(isScalarFieldType({ type: 'fp' })).toBe(true);
    expect(isScalarFieldType({ type: 'array', kind: { type: 'fp' }, len: 32 })).toBe(false);
  });

  it('isArrayFieldType narrows the discriminant and exposes kind/len', () => {
    const t: FieldType = { type: 'array', kind: { type: 'fp' }, len: 32 };
    if (isArrayFieldType(t)) {
      expectTypeOf(t).toEqualTypeOf<ArrayFieldType>();
      expectTypeOf(t.len).toBeNumber();
      expectTypeOf(t.kind).toEqualTypeOf<FieldType>();
      expect(t.len).toBe(32);
      expect(t.kind).toEqual({ type: 'fp' });
    } else {
      throw new Error('isArrayFieldType should have matched');
    }
  });

  it('supports nested arrays (array of arrays)', () => {
    const nested: FieldType = {
      type: 'array',
      kind: { type: 'array', kind: { type: 'bool' }, len: 8 },
      len: 4,
    };
    expect(isArrayFieldType(nested)).toBe(true);
    if (isArrayFieldType(nested) && isArrayFieldType(nested.kind)) {
      expect(nested.kind.len).toBe(8);
      expect(nested.kind.kind).toEqual({ type: 'bool' });
    }
  });
});

describe('parseAbiSchema', () => {
  it('roundtrips a minimal schema through JSON', () => {
    const back = parseAbiSchema(JSON.stringify(sample));
    expect(back).toEqual(sample);
  });

  it('accepts an on_chain binding when present', () => {
    const withChain: AbiSchema = {
      ...sample,
      on_chain: {
        chain_id: 421614,
        contract_address: '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
    };
    const back = parseAbiSchema(JSON.stringify(withChain));
    expect(back.on_chain?.chain_id).toBe(421614);
    expect(back.on_chain?.contract_address).toBe('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  });

  it('preserves merkle-shaped array witnesses', () => {
    const merkle: AbiSchema = {
      ...sample,
      witness: {
        fields: [
          { name: 'leaf', kind: { type: 'fp' }, visibility: 'private' },
          {
            name: 'siblings',
            kind: { type: 'array', kind: { type: 'fp' }, len: 32 },
            visibility: 'private',
          },
          {
            name: 'indices',
            kind: { type: 'array', kind: { type: 'bool' }, len: 32 },
            visibility: 'private',
          },
        ],
      },
    };
    const back = parseAbiSchema(JSON.stringify(merkle));
    expect(back.witness.fields).toHaveLength(3);
    expect(back.witness.fields[1]?.kind).toEqual({
      type: 'array',
      kind: { type: 'fp' },
      len: 32,
    });
    expect(back.witness.fields[2]?.kind).toEqual({
      type: 'array',
      kind: { type: 'bool' },
      len: 32,
    });
  });

  it('accepts every documented proving system literal', () => {
    const systems = ['halo2_ipa', 'halo2_kzg_groth16_wrap', 'halo2_kzg', 'stark_fri'] as const;
    for (const ps of systems) {
      const back = parseAbiSchema(
        JSON.stringify({ ...sample, proof: { ...sample.proof, proving_system: ps } }),
      );
      expect(back.proof.proving_system).toBe(ps);
    }
  });
});
