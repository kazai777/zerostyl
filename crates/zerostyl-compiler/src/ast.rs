//! AST transformation for zk-SNARK circuit generation
//!
//! This module transforms parsed Rust structs into an intermediate representation (IR)
//! suitable for generating halo2 zk-SNARK circuits. It validates type compatibility
//! and extracts metadata needed for circuit construction.

use crate::error::{CompilerError, Result};
use crate::parser::{ParsedContract, PrivateField};
use zerostyl_runtime::CircuitConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkField {
    pub name: String,
    pub field_type: ZkType,
    pub constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZkType {
    U8,
    U16,
    U32,
    U64,
    U128,
    I64,
    Bool,
    Field,
    Bytes32,
    Array { element_type: Box<ZkType>, size: usize },
    Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    /// Bit-decomposition range proof: value ∈ [0, 2^num_bits). Uses RangeProofChip.
    Range {
        num_bits: usize,
    },
    /// Boolean constraint: value ∈ {0, 1}. Uses RangeProofChip with 1 bit.
    Boolean,
    /// Legacy range proof with explicit min/max bounds (for types without a gadget, e.g. u128).
    RangeProof {
        min: u128,
        max: u128,
    },
    Comparison {
        operator: ComparisonOp,
        value: u64,
    },
    Commitment {
        hash_type: HashType,
    },
    ArithmeticRelation {
        lhs_field: String,
        operator: ArithOp,
        rhs_fields: Vec<(String, ArithOp)>,
    },
    MerkleProof {
        leaf_field: String,
        path_field: String,
        root_field: String,
        tree_depth: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparisonOp {
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Equal,
    NotEqual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashType {
    Pedersen,
    Poseidon,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CircuitIR {
    pub name: String,
    pub public_inputs: Vec<ZkField>,
    pub private_witnesses: Vec<ZkField>,
    pub inter_field_constraints: Vec<InterFieldConstraint>,
    pub circuit_config: CircuitConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterFieldConstraint {
    ArithmeticRelation {
        result_field: String,
        operation: ArithOp,
        operands: Vec<String>,
    },
    MerkleVerification {
        leaf: String,
        path: String,
        root: String,
    },
    CommitmentVerification {
        commitment: String,
        value: String,
        randomness: String,
        hash_type: HashType,
    },
    ComparisonCheck {
        left_field: String,
        right_field: String,
        op: ComparisonOp,
    },
}

impl CircuitIR {
    /// Estimates the number of rows this circuit requires.
    ///
    /// Accounts for witness assignments, public inputs, per-field constraints,
    /// and inter-field constraints. Includes a 2x safety factor.
    pub fn estimate_rows(&self) -> usize {
        let witness_rows = self.private_witnesses.len();
        let public_rows = self.public_inputs.len();

        let constraint_rows: usize = self
            .private_witnesses
            .iter()
            .chain(&self.public_inputs)
            .flat_map(|f| &f.constraints)
            .map(estimate_constraint_rows)
            .sum();

        let inter_field_rows: usize =
            self.inter_field_constraints.iter().map(estimate_inter_field_rows).sum();

        (witness_rows + public_rows + constraint_rows + inter_field_rows) * 2
    }

    /// Adds a public input field to the circuit.
    pub fn add_public_input(&mut self, field: ZkField) {
        self.public_inputs.push(field);
    }

    /// Recomputes the circuit config (k parameter) from current fields and constraints.
    pub fn recompute_config(&mut self) -> Result<()> {
        let k = compute_k(self.estimate_rows());
        self.circuit_config = CircuitConfig::minimal(k)
            .map_err(|e| CompilerError::Other(format!("Failed to create circuit config: {}", e)))?;
        Ok(())
    }
}

fn estimate_constraint_rows(constraint: &Constraint) -> usize {
    match constraint {
        Constraint::Range { num_bits } => num_bits + 2,
        Constraint::Boolean => 3,
        Constraint::RangeProof { .. } => 128,
        Constraint::Comparison { .. } => 68,
        Constraint::Commitment { .. } => 64,
        Constraint::MerkleProof { tree_depth, .. } => tree_depth * 64,
        Constraint::ArithmeticRelation { rhs_fields, .. } => 1 + rhs_fields.len(),
    }
}

fn estimate_inter_field_rows(constraint: &InterFieldConstraint) -> usize {
    match constraint {
        InterFieldConstraint::ArithmeticRelation { operands, .. } => 1 + operands.len(),
        InterFieldConstraint::MerkleVerification { .. } => 32 * 64,
        InterFieldConstraint::CommitmentVerification { .. } => 64,
        InterFieldConstraint::ComparisonCheck { .. } => 68,
    }
}

/// Computes the minimum k parameter to fit the given number of rows.
///
/// The k parameter determines circuit size: 2^k rows.
/// Clamped to [`CircuitConfig::MIN_K`], [`CircuitConfig::MAX_K`].
pub fn compute_k(estimated_rows: usize) -> u32 {
    if estimated_rows <= 1 {
        return CircuitConfig::MIN_K;
    }
    let k = (estimated_rows as f64).log2().ceil() as u32;
    k.clamp(CircuitConfig::MIN_K, CircuitConfig::MAX_K)
}

pub fn transform_to_ir(parsed: ParsedContract) -> Result<CircuitIR> {
    validate_zk_types(&parsed.private_fields)?;

    let private_witnesses: Result<Vec<ZkField>> = parsed
        .private_fields
        .into_iter()
        .map(|field| {
            let field_type = parse_zk_type(&field.field_type)?;
            let constraints = default_constraints(&field_type);

            Ok(ZkField { name: field.name, field_type, constraints })
        })
        .collect();

    let private_witnesses = private_witnesses?;

    // Compute k dynamically from estimated row count
    let constraint_rows: usize =
        private_witnesses.iter().flat_map(|f| &f.constraints).map(estimate_constraint_rows).sum();
    let estimated_rows = (private_witnesses.len() + constraint_rows) * 2;
    let k = compute_k(estimated_rows);

    Ok(CircuitIR {
        name: parsed.contract_name,
        public_inputs: vec![],
        private_witnesses,
        inter_field_constraints: vec![],
        circuit_config: CircuitConfig::minimal(k)
            .map_err(|e| CompilerError::Other(format!("Failed to create circuit config: {}", e)))?,
    })
}

pub fn validate_zk_types(fields: &[PrivateField]) -> Result<()> {
    for field in fields {
        parse_zk_type(&field.field_type)?;
    }
    Ok(())
}

fn parse_zk_type(type_str: &str) -> Result<ZkType> {
    match type_str {
        "u8" => Ok(ZkType::U8),
        "u16" => Ok(ZkType::U16),
        "u32" => Ok(ZkType::U32),
        "u64" => Ok(ZkType::U64),
        "u128" => Ok(ZkType::U128),
        "i64" => Ok(ZkType::I64),
        "bool" => Ok(ZkType::Bool),
        "Field" => Ok(ZkType::Field),
        "[u8;32]" => Ok(ZkType::Bytes32),
        "Address" => Ok(ZkType::Address),
        _ => {
            if type_str.starts_with('[') && type_str.ends_with(']') {
                return Err(CompilerError::UnsupportedZkType(format!(
                    "Array type '{}' parsing not yet fully implemented. Currently only [u8;32] is supported.",
                    type_str
                )));
            }

            Err(CompilerError::UnsupportedZkType(format!(
                "Type '{}' is not supported for zk-SNARK circuits. Supported types: u8, u16, u32, u64, u128, i64, bool, Field, [u8;32], Address",
                type_str
            )))
        }
    }
}

fn default_constraints(zk_type: &ZkType) -> Vec<Constraint> {
    match zk_type {
        ZkType::U8 => vec![Constraint::Range { num_bits: 8 }],
        ZkType::U16 => vec![Constraint::Range { num_bits: 16 }],
        ZkType::U32 => vec![Constraint::Range { num_bits: 32 }],
        ZkType::U64 => vec![Constraint::Range { num_bits: 64 }],
        ZkType::U128 => vec![Constraint::RangeProof { min: 0, max: u128::MAX }],
        ZkType::I64 => vec![],
        ZkType::Bool => vec![Constraint::Boolean],
        ZkType::Field => vec![],
        ZkType::Bytes32 => vec![],
        ZkType::Array { .. } => vec![],
        ZkType::Address => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_zk_type_u64() {
        let result = parse_zk_type("u64");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ZkType::U64);
    }

    #[test]
    fn test_parse_zk_type_u128() {
        let result = parse_zk_type("u128");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ZkType::U128);
    }

    #[test]
    fn test_parse_zk_type_bytes32() {
        let result = parse_zk_type("[u8;32]");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ZkType::Bytes32);
    }

    #[test]
    fn test_parse_zk_type_unsupported() {
        let result = parse_zk_type("String");
        assert!(result.is_err());
    }

    #[test]
    fn test_default_constraints_u64() {
        let constraints = default_constraints(&ZkType::U64);
        assert_eq!(constraints.len(), 1);
        assert!(matches!(constraints[0], Constraint::Range { num_bits: 64 }));
    }

    #[test]
    fn test_default_constraints_u128() {
        let constraints = default_constraints(&ZkType::U128);
        assert_eq!(constraints.len(), 1);
        if let Constraint::RangeProof { min, max } = constraints[0] {
            assert_eq!(min, 0);
            assert_eq!(max, u128::MAX);
        } else {
            panic!("Expected RangeProof constraint");
        }
    }

    #[test]
    fn test_default_constraints_bool() {
        let constraints = default_constraints(&ZkType::Bool);
        assert_eq!(constraints.len(), 1);
        assert!(matches!(constraints[0], Constraint::Boolean));
    }

    #[test]
    fn test_all_zk_types_parseable() {
        let types = vec![
            ("u8", ZkType::U8),
            ("u16", ZkType::U16),
            ("u32", ZkType::U32),
            ("u64", ZkType::U64),
            ("u128", ZkType::U128),
            ("i64", ZkType::I64),
            ("bool", ZkType::Bool),
            ("Field", ZkType::Field),
            ("[u8;32]", ZkType::Bytes32),
            ("Address", ZkType::Address),
        ];

        for (type_str, expected) in types {
            let result = parse_zk_type(type_str).unwrap();
            assert_eq!(result, expected, "Failed for type: {}", type_str);
        }
    }

    #[test]
    fn test_default_constraints_array_type() {
        let array_type = ZkType::Array { element_type: Box::new(ZkType::U64), size: 10 };
        let constraints = default_constraints(&array_type);
        assert_eq!(constraints.len(), 0);
    }

    #[test]
    fn test_default_constraints_all_integer_types() {
        let constraints = default_constraints(&ZkType::U8);
        assert_eq!(constraints.len(), 1);

        let constraints = default_constraints(&ZkType::U16);
        assert_eq!(constraints.len(), 1);

        let constraints = default_constraints(&ZkType::U32);
        assert_eq!(constraints.len(), 1);

        let constraints = default_constraints(&ZkType::I64);
        assert_eq!(constraints.len(), 0);
    }

    #[test]
    fn test_default_constraints_special_types() {
        let constraints = default_constraints(&ZkType::Field);
        assert_eq!(constraints.len(), 0);

        let constraints = default_constraints(&ZkType::Bytes32);
        assert_eq!(constraints.len(), 0);

        let constraints = default_constraints(&ZkType::Address);
        assert_eq!(constraints.len(), 0);
    }

    #[test]
    fn test_default_constraints_range_variants() {
        assert!(matches!(default_constraints(&ZkType::U8)[0], Constraint::Range { num_bits: 8 }));
        assert!(matches!(default_constraints(&ZkType::U16)[0], Constraint::Range { num_bits: 16 }));
        assert!(matches!(default_constraints(&ZkType::U32)[0], Constraint::Range { num_bits: 32 }));
        assert!(matches!(default_constraints(&ZkType::U64)[0], Constraint::Range { num_bits: 64 }));
    }

    #[test]
    fn test_compute_k_basic() {
        assert_eq!(compute_k(0), 4); // MIN_K
        assert_eq!(compute_k(1), 4); // MIN_K
        assert_eq!(compute_k(16), 4); // 2^4 = 16
        assert_eq!(compute_k(17), 5); // needs 2^5 = 32
        assert_eq!(compute_k(134), 8); // single u64 field
        assert_eq!(compute_k(256), 8); // exactly 2^8
        assert_eq!(compute_k(257), 9); // needs 2^9
    }

    #[test]
    fn test_estimate_rows_single_u64() {
        let ir = CircuitIR {
            name: "Test".to_string(),
            public_inputs: vec![],
            private_witnesses: vec![ZkField {
                name: "val".to_string(),
                field_type: ZkType::U64,
                constraints: vec![Constraint::Range { num_bits: 64 }],
            }],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(4).unwrap(),
        };
        // (1 witness + 66 constraint_rows) * 2 = 134
        assert_eq!(ir.estimate_rows(), 134);
    }

    #[test]
    fn test_estimate_rows_with_inter_field() {
        let ir = CircuitIR {
            name: "Test".to_string(),
            public_inputs: vec![],
            private_witnesses: vec![ZkField {
                name: "val".to_string(),
                field_type: ZkType::U64,
                constraints: vec![Constraint::Range { num_bits: 64 }],
            }],
            inter_field_constraints: vec![InterFieldConstraint::ComparisonCheck {
                left_field: "a".to_string(),
                right_field: "b".to_string(),
                op: ComparisonOp::GreaterThan,
            }],
            circuit_config: CircuitConfig::minimal(4).unwrap(),
        };
        // (1 + 66 + 68) * 2 = 270
        assert_eq!(ir.estimate_rows(), 270);
    }

    #[test]
    fn test_circuit_ir_add_public_input() {
        let mut ir = CircuitIR {
            name: "Test".to_string(),
            public_inputs: vec![],
            private_witnesses: vec![],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(4).unwrap(),
        };
        assert_eq!(ir.public_inputs.len(), 0);
        ir.add_public_input(ZkField {
            name: "pub1".to_string(),
            field_type: ZkType::U64,
            constraints: vec![],
        });
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "pub1");
    }

    #[test]
    fn test_circuit_ir_recompute_config() {
        let mut ir = CircuitIR {
            name: "Test".to_string(),
            public_inputs: vec![],
            private_witnesses: vec![ZkField {
                name: "val".to_string(),
                field_type: ZkType::U64,
                constraints: vec![Constraint::Range { num_bits: 64 }],
            }],
            inter_field_constraints: vec![],
            circuit_config: CircuitConfig::minimal(4).unwrap(),
        };
        assert_eq!(ir.circuit_config.k(), 4);
        ir.recompute_config().unwrap();
        // (1 + 66) * 2 = 134 → k=8
        assert_eq!(ir.circuit_config.k(), 8);
    }

    #[test]
    fn test_comparison_op_new_variants() {
        let gte = ComparisonOp::GreaterThanOrEqual;
        let lte = ComparisonOp::LessThanOrEqual;
        assert_ne!(gte, lte);
        assert_eq!(gte, ComparisonOp::GreaterThanOrEqual);
        assert_eq!(lte, ComparisonOp::LessThanOrEqual);
    }

    #[test]
    fn test_inter_field_comparison_check() {
        let check = InterFieldConstraint::ComparisonCheck {
            left_field: "balance".to_string(),
            right_field: "threshold".to_string(),
            op: ComparisonOp::GreaterThan,
        };
        assert!(matches!(check, InterFieldConstraint::ComparisonCheck { .. }));
    }

    #[test]
    fn test_transform_computes_k_dynamically() {
        let parsed = ParsedContract {
            contract_name: "DynK".to_string(),
            private_fields: vec![PrivateField {
                name: "val".to_string(),
                field_type: "u64".to_string(),
            }],
        };
        let ir = transform_to_ir(parsed).unwrap();
        // 1 u64 → Range{64} → (1 + 66) * 2 = 134 → k=8
        assert_eq!(ir.circuit_config.k(), 8);
    }
}
