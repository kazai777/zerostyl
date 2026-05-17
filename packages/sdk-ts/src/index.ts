export const SDK_VERSION = '0.1.0';

export type {
  AbiSchema,
  ArrayFieldType,
  CircuitMetadata,
  FieldType,
  FieldVisibility,
  Hex,
  OnChainBinding,
  ProofMetadata,
  ProvingSystem,
  PublicInputField,
  PublicInputsSchema,
  ScalarFieldType,
  WitnessField,
  WitnessSchema,
} from './types.js';

export { isArrayFieldType, isScalarFieldType, parseAbiSchema } from './types.js';
