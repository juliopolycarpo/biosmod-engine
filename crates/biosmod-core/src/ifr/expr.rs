//! Rendering of IFR condition expressions (reverse Polish) as readable infix text.
//!
//! `SuppressIf`, `GrayOutIf` and `DisableIf` carry their condition as the expression
//! opcodes that follow them. Operands render like `ideqval 0x9 == 1`; combinations
//! like `(ideqval 0x9 == 1) or (ideqval 0xa == 0)`. The renderer never fails: a
//! missing operand shows as `<missing>` so a damaged expression stays visible.

use crate::util::{Guid, le16, le32, le64};

/// Opcodes that can appear inside a condition expression.
pub fn is_expression_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x12..=0x17 | 0x20 | 0x21 | 0x22 | 0x28 | 0x2A..=0x59 | 0x5E | 0x60 | 0x64
    )
}

struct Node {
    text: String,
    /// True when the text needs no parentheses as an operand.
    atomic: bool,
}

impl Node {
    fn atom(text: impl Into<String>) -> Node {
        Node {
            text: text.into(),
            atomic: true,
        }
    }

    fn compound(text: String) -> Node {
        Node {
            text,
            atomic: false,
        }
    }

    fn operand(&self) -> String {
        if self.atomic {
            self.text.clone()
        } else {
            format!("({})", self.text)
        }
    }
}

/// Accumulates expression opcodes and renders the final stack.
#[derive(Default)]
pub struct ExpressionBuilder {
    stack: Vec<Node>,
}

fn binary_symbol(opcode: u8) -> Option<&'static str> {
    Some(match opcode {
        0x15 => "and",
        0x16 => "or",
        0x2F => "==",
        0x30 => "!=",
        0x31 => ">",
        0x32 => ">=",
        0x33 => "<",
        0x34 => "<=",
        0x35 => "&",
        0x36 => "|",
        0x38 => "<<",
        0x39 => ">>",
        0x3A => "+",
        0x3B => "-",
        0x3C => "*",
        0x3D => "/",
        0x3E => "%",
        _ => return None,
    })
}

/// Function-style operators: name and operand count.
fn function(opcode: u8) -> Option<(&'static str, usize)> {
    Some(match opcode {
        0x20 => ("tolower", 1),
        0x21 => ("toupper", 1),
        0x2A => ("match", 2),
        0x48 => ("touint", 1),
        0x49 => ("tostring", 1),
        0x4A => ("toboolean", 1),
        0x4B => ("mid", 3),
        0x4C => ("find", 3),
        0x4D => ("token", 3),
        0x4F => ("stringref", 1),
        0x50 => ("cond", 3),
        0x51 => ("questionref3", 1),
        0x56 => ("length", 1),
        0x59 => ("span", 3),
        0x5E => ("cat", 2),
        0x41 => ("questionref2", 1),
        0x64 => ("match2", 2),
        _ => return None,
    })
}

impl ExpressionBuilder {
    fn pop(&mut self) -> Node {
        self.stack.pop().unwrap_or_else(|| Node::atom("<missing>"))
    }

    /// Feed one expression opcode; `payload` is the bytes after the 2-byte header.
    /// `string` resolves a string id to its text for `StringRef1`.
    pub fn push(&mut self, opcode: u8, payload: &[u8], string: &dyn Fn(u16) -> String) {
        let u16_at = |at: usize| le16(payload, at, "").unwrap_or(0);
        if let Some(symbol) = binary_symbol(opcode) {
            let right = self.pop();
            let left = self.pop();
            self.stack.push(Node::compound(format!(
                "{} {symbol} {}",
                left.operand(),
                right.operand()
            )));
            return;
        }
        if let Some((name, arity)) = function(opcode) {
            let mut args: Vec<String> = (0..arity).map(|_| self.pop().text).collect();
            args.reverse();
            self.stack
                .push(Node::atom(format!("{name}({})", args.join(", "))));
            return;
        }
        let node = match opcode {
            0x12 => Node::compound(format!("ideqval {:#x} == {}", u16_at(0), u16_at(2))),
            0x13 => Node::compound(format!("ideqid {:#x} == {:#x}", u16_at(0), u16_at(2))),
            0x14 => {
                let count = usize::from(u16_at(2));
                let values: Vec<String> = (0..count)
                    .map_while(|i| le16(payload, 4 + i * 2, "").ok())
                    .map(|v| v.to_string())
                    .collect();
                Node::compound(format!(
                    "ideqvallist {:#x} in [{}]",
                    u16_at(0),
                    values.join(", ")
                ))
            }
            0x17 => {
                let value = self.pop();
                Node::compound(format!("not {}", value.operand()))
            }
            0x37 => {
                let value = self.pop();
                Node::compound(format!("~{}", value.operand()))
            }
            0x3F => Node::atom(format!("rule({})", payload.first().copied().unwrap_or(0))),
            0x40 => Node::atom(format!("questionref({:#x})", u16_at(0))),
            0x42 => Node::atom(payload.first().copied().unwrap_or(0).to_string()),
            0x43 => Node::atom(u16_at(0).to_string()),
            0x44 => Node::atom(le32(payload, 0, "").unwrap_or(0).to_string()),
            0x45 => Node::atom(le64(payload, 0, "").unwrap_or(0).to_string()),
            0x46 => Node::atom("true"),
            0x47 => Node::atom("false"),
            0x4E => Node::atom(format!("{:?}", string(u16_at(0)))),
            0x52 => Node::atom("0"),
            0x53 => Node::atom("1"),
            0x54 => Node::atom("ones"),
            0x55 => Node::atom("undefined"),
            0x28 => Node::atom("version"),
            0x57 => Node::atom("dup"),
            0x58 => Node::atom("this"),
            0x60 => Node::atom(match payload.get(..16) {
                Some(raw) => format!("security({})", Guid::from_slice(raw)),
                None => "security(<short>)".to_string(),
            }),
            other => Node::atom(format!("opcode_{other:#04x}")),
        };
        self.stack.push(node);
    }

    /// Render the expression; several leftover values are joined with `; `.
    pub fn finish(self) -> String {
        match self.stack.len() {
            0 => "<empty>".to_string(),
            _ => self
                .stack
                .into_iter()
                .map(|node| node.text)
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(ops: &[(u8, &[u8])]) -> String {
        let mut builder = ExpressionBuilder::default();
        for (opcode, payload) in ops {
            builder.push(*opcode, payload, &|id| format!("s{id}"));
        }
        builder.finish()
    }

    #[test]
    fn ideqval_renders_hex_id_and_decimal_value() {
        assert_eq!(render(&[(0x12, &[9, 0, 1, 0])]), "ideqval 0x9 == 1");
    }

    #[test]
    fn combined_conditions_parenthesize_compound_operands() {
        let text = render(&[
            (0x12, &[9, 0, 1, 0]),
            (0x14, &[0xA, 0, 2, 0, 1, 0, 2, 0]),
            (0x16, &[]),
            (0x17, &[]),
        ]);
        assert_eq!(
            text,
            "not ((ideqval 0x9 == 1) or (ideqvallist 0xa in [1, 2]))"
        );
    }

    #[test]
    fn literal_comparison_and_underflow_render_without_failing() {
        let one = 1u64.to_le_bytes();
        let zero = 0u64.to_le_bytes();
        assert_eq!(
            render(&[(0x45, &one), (0x45, &zero), (0x2F, &[])]),
            "1 == 0"
        );
        assert_eq!(render(&[(0x15, &[])]), "<missing> and <missing>");
        assert_eq!(render(&[]), "<empty>");
        assert_eq!(render(&[(0x46, &[])]), "true");
    }

    #[test]
    fn expression_opcode_set_excludes_statements_and_conditions() {
        for opcode in [0x0A, 0x19, 0x1E, 0x05, 0x5B, 0x29] {
            assert!(!is_expression_opcode(opcode), "{opcode:#04x}");
        }
        for opcode in [0x12, 0x46, 0x45, 0x2F, 0x17] {
            assert!(is_expression_opcode(opcode), "{opcode:#04x}");
        }
    }
}
