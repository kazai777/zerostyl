//! Parser for extracting `#[zk_private]` annotations from Rust code

use crate::error::{CompilerError, Result};
use syn::{Attribute, Field, Fields, Item, ItemStruct};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateField {
    pub name: String,
    pub field_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedContract {
    pub contract_name: String,
    pub private_fields: Vec<PrivateField>,
}

pub fn parse_contract(input: &str) -> Result<ParsedContract> {
    let ast: syn::File = syn::parse_str(input)?;

    let item_struct = ast
        .items
        .iter()
        .find_map(|item| match item {
            Item::Struct(s) => Some(s),
            _ => None,
        })
        .ok_or_else(|| CompilerError::ParseError("No struct found in input".to_string()))?;

    parse_struct(item_struct)
}

fn parse_struct(item_struct: &ItemStruct) -> Result<ParsedContract> {
    let contract_name = item_struct.ident.to_string();
    let mut private_fields = Vec::new();

    if let Fields::Named(fields) = &item_struct.fields {
        for field in &fields.named {
            if has_zk_private_attribute(&field.attrs) {
                let field_name = field
                    .ident
                    .as_ref()
                    .ok_or_else(|| CompilerError::ParseError("Field has no name".to_string()))?
                    .to_string();

                let field_type = extract_type_name(field)?;

                private_fields.push(PrivateField { name: field_name, field_type });
            }
        }
    }

    Ok(ParsedContract { contract_name, private_fields })
}

fn has_zk_private_attribute(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| attr.path().segments.iter().any(|seg| seg.ident == "zk_private"))
}

fn extract_type_name(field: &Field) -> Result<String> {
    use quote::ToTokens;

    let type_tokens = field.ty.to_token_stream().to_string();

    Ok(type_tokens.replace(' ', ""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_zk_private_attribute() {
        let input = r#"
            struct Test {
                #[zk_private]
                field1: u64,
            }
        "#;

        let ast: syn::File = syn::parse_str(input).unwrap();
        if let Item::Struct(s) = &ast.items[0] {
            if let Fields::Named(fields) = &s.fields {
                let field = &fields.named[0];
                assert!(has_zk_private_attribute(&field.attrs));
            }
        }
    }

    #[test]
    fn test_extract_type_name_simple() {
        let input = r#"
            struct Test {
                field1: u64,
            }
        "#;

        let ast: syn::File = syn::parse_str(input).unwrap();
        if let Item::Struct(s) = &ast.items[0] {
            if let Fields::Named(fields) = &s.fields {
                let field = &fields.named[0];
                let type_name = extract_type_name(field).unwrap();
                assert_eq!(type_name, "u64");
            }
        }
    }
}
