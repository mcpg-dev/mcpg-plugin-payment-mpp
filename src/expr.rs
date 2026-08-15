//! Minimal CEL expression engine for dynamic charge configuration.
//!
//! Extracted subset of the gateway's expression engine — just enough for payment
//! charge resolution. Supports literal strings and `${...}` CEL expressions
//! that reference `$arguments` and `$tool_name`.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context as AnyhowContext, Result};
use cel::{
    Context as CelContext, Program, Value as CelValue,
    objects::{Key as CelKey, Map as CelMap},
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// DynamicValue
// ---------------------------------------------------------------------------

/// A configuration value that may be literal or a compiled CEL expression.
#[derive(Debug)]
pub(crate) enum DynamicValue<T: std::fmt::Debug> {
    Literal(T),
    Expression { source: String, program: Program },
}

impl DynamicValue<String> {
    /// Parse a string into either a literal or CEL expression.
    ///
    /// Strings containing `${...}` are treated as CEL expressions.
    pub fn parse(input: &str) -> Result<Self> {
        if let Some(inner) = extract_expression(input) {
            let normalized = normalize_variable_refs(inner);
            let program = Program::compile(&normalized)
                .map_err(|e| anyhow::anyhow!("CEL compilation failed for '{}': {}", inner, e))?;
            Ok(Self::Expression {
                source: input.to_owned(),
                program,
            })
        } else {
            Ok(Self::Literal(input.to_owned()))
        }
    }

    /// Resolve the value against a request context.
    pub fn resolve(&self, ctx: &ExprContext) -> Result<String> {
        match self {
            Self::Literal(v) => Ok(v.clone()),
            Self::Expression { source, program } => {
                let cel_ctx = ctx
                    .to_cel_context()
                    .context("failed to build CEL context")?;
                let result = program.execute(&cel_ctx).map_err(|e| {
                    anyhow::anyhow!("CEL execution failed for '{}': {:?}", source, e)
                })?;
                Ok(cel_value_to_string(&result))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ExprContext
// ---------------------------------------------------------------------------

/// Runtime context for expression evaluation.
#[derive(Debug, Default)]
pub(crate) struct ExprContext {
    pub arguments: Value,
    pub tool_name: String,
}

impl ExprContext {
    fn to_cel_context(&self) -> Result<CelContext<'_>> {
        let mut ctx = CelContext::default();
        ctx.add_variable("arguments", json_to_cel(&self.arguments))
            .map_err(|e| anyhow::anyhow!("failed to add $arguments: {:?}", e))?;
        ctx.add_variable(
            "tool_name",
            CelValue::String(Arc::new(self.tool_name.clone())),
        )
        .map_err(|e| anyhow::anyhow!("failed to add $tool_name: {:?}", e))?;
        Ok(ctx)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the expression body from `${...}` markers.
fn extract_expression(input: &str) -> Option<&str> {
    let trimmed = input.trim();
    if trimmed.starts_with("${") && trimmed.ends_with('}') {
        Some(&trimmed[2..trimmed.len() - 1])
    } else {
        None
    }
}

/// Replace `$variable` references with just `variable` for CEL.
fn normalize_variable_refs(input: &str) -> String {
    input
        .replace("$arguments", "arguments")
        .replace("$tool_name", "tool_name")
}

/// Convert a JSON value to a CEL value.
fn json_to_cel(value: &Value) -> CelValue {
    match value {
        Value::Null => CelValue::Null,
        Value::Bool(b) => CelValue::Bool(*b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                CelValue::Int(i)
            } else if let Some(u) = n.as_u64() {
                CelValue::UInt(u)
            } else if let Some(f) = n.as_f64() {
                CelValue::Float(f)
            } else {
                CelValue::Null
            }
        }
        Value::String(s) => CelValue::String(Arc::new(s.clone())),
        Value::Array(arr) => CelValue::List(Arc::new(arr.iter().map(json_to_cel).collect())),
        Value::Object(obj) => {
            let map: HashMap<CelKey, CelValue> = obj
                .iter()
                .map(|(k, v)| (CelKey::String(Arc::new(k.clone())), json_to_cel(v)))
                .collect();
            CelValue::Map(CelMap { map: Arc::new(map) })
        }
    }
}

/// Convert a CEL value to a string for charge resolution.
fn cel_value_to_string(value: &CelValue) -> String {
    match value {
        CelValue::String(s) => s.to_string(),
        CelValue::Int(i) => i.to_string(),
        CelValue::UInt(u) => u.to_string(),
        CelValue::Float(f) => f.to_string(),
        CelValue::Bool(b) => b.to_string(),
        CelValue::Null => "null".to_owned(),
        other => format!("{:?}", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_parse_and_resolve() {
        let dv = DynamicValue::parse("0.10").unwrap();
        assert!(matches!(dv, DynamicValue::Literal(_)));
        let ctx = ExprContext::default();
        assert_eq!(dv.resolve(&ctx).unwrap(), "0.10");
    }

    #[test]
    fn expression_parse_and_resolve() {
        let dv = DynamicValue::parse("${arguments.count > 10 ? \"1.00\" : \"0.10\"}").unwrap();
        assert!(matches!(dv, DynamicValue::Expression { .. }));

        let ctx = ExprContext {
            arguments: serde_json::json!({"count": 5}),
            tool_name: "test".into(),
        };
        assert_eq!(dv.resolve(&ctx).unwrap(), "0.10");

        let ctx2 = ExprContext {
            arguments: serde_json::json!({"count": 20}),
            tool_name: "test".into(),
        };
        assert_eq!(dv.resolve(&ctx2).unwrap(), "1.00");
    }

    #[test]
    fn extract_expression_works() {
        assert_eq!(extract_expression("${foo}"), Some("foo"));
        assert_eq!(extract_expression("plain"), None);
        assert_eq!(extract_expression("${a + b}"), Some("a + b"));
    }

    #[test]
    fn normalize_refs() {
        assert_eq!(
            normalize_variable_refs("$arguments.x > 5"),
            "arguments.x > 5"
        );
    }
}
