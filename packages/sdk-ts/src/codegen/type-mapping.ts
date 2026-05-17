import type { FieldType } from '../types.js';

export function fieldTypeToTs(t: FieldType): string {
  switch (t.type) {
    case 'u64':
    case 'u128':
      return 'bigint';
    case 'bool':
      return 'boolean';
    case 'fp':
    case 'bytes32':
    case 'address':
      return 'Hex';
    case 'array':
      return `ReadonlyArray<${fieldTypeToTs(t.kind)}>`;
  }
}
