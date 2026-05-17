export type Hex = `0x${string}`;

export type FieldType =
  | { type: 'u64' }
  | { type: 'u128' }
  | { type: 'bool' }
  | { type: 'bytes32' }
  | { type: 'address' }
  | { type: 'fp' }
  | { type: 'array'; kind: FieldType; len: number };

export type FieldVisibility = 'private' | 'public';

export interface WitnessField {
  name: string;
  kind: FieldType;
  visibility: FieldVisibility;
  description?: string;
}

export interface WitnessSchema {
  fields: WitnessField[];
}

export interface PublicInputField {
  name: string;
  kind: FieldType;
  description?: string;
}

export interface PublicInputsSchema {
  fields: PublicInputField[];
}

export type ProvingSystem = 'halo2_ipa' | 'halo2_kzg_groth16_wrap' | 'halo2_kzg' | 'stark_fri';

export interface ProofMetadata {
  format_version: number;
  approx_size_bytes?: number;
  proving_system: ProvingSystem;
}

export interface OnChainBinding {
  chain_id: number;
  contract_address: Hex;
}

export interface CircuitMetadata {
  name: string;
  version: string;
  description: string;
  default_k: number;
  num_public_inputs: number;
  num_private_witnesses: number;
}

export interface AbiSchema {
  abi_version: number;
  circuit: CircuitMetadata;
  witness: WitnessSchema;
  public_inputs: PublicInputsSchema;
  proof: ProofMetadata;
  on_chain?: OnChainBinding;
}

export type ArrayFieldType = Extract<FieldType, { type: 'array' }>;
export type ScalarFieldType = Exclude<FieldType, { type: 'array' }>;

export function isArrayFieldType(t: FieldType): t is ArrayFieldType {
  return t.type === 'array';
}

export function isScalarFieldType(t: FieldType): t is ScalarFieldType {
  return t.type !== 'array';
}

export function parseAbiSchema(json: string): AbiSchema {
  return JSON.parse(json) as AbiSchema;
}
