// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded secure storage-trie lookup with explicit terminal absence proofs.
//! Exhausting supplied nodes while a child is still referenced is an error.

use crate::{ethereum_header_ancestry as rlp, merkle::keccak256};

type Check<T> = Result<T, &'static str>;
pub const MAX_NODES: usize = 65;
pub const MAX_NODE_BYTES: usize = 1024;

fn require(ok: bool, message: &'static str) -> Check<()> {
    if ok {
        Ok(())
    } else {
        Err(message)
    }
}

#[derive(Clone, Copy)]
struct Field<'a> {
    list: bool,
    payload: &'a [u8],
    raw: &'a [u8],
}

fn fields(raw: &[u8]) -> Check<Vec<Field<'_>>> {
    let (list, mut rest, used) = rlp::item(raw)?;
    require(
        list && used == raw.len(),
        "one complete storage trie node required",
    )?;
    let mut result = Vec::new();
    while !rest.is_empty() {
        require(result.len() < 17, "storage trie field count")?;
        let (list, payload, used) = rlp::item(rest)?;
        result.push(Field {
            list,
            payload,
            raw: &rest[..used],
        });
        rest = &rest[used..];
    }
    require(matches!(result.len(), 2 | 17), "storage trie node shape")?;
    Ok(result)
}

enum Reference<'a> {
    Empty,
    Hash([u8; 32]),
    Inline(&'a [u8]),
}

fn reference(field: Field<'_>) -> Check<Reference<'_>> {
    if field.list {
        require(field.raw.len() < 32, "oversized inline trie node")?;
        Ok(Reference::Inline(field.raw))
    } else if field.payload.is_empty() {
        Ok(Reference::Empty)
    } else {
        Ok(Reference::Hash(
            field.payload.try_into().map_err(|_| "child hash width")?,
        ))
    }
}

fn compact(field: Field<'_>) -> Check<(bool, Vec<u8>)> {
    require(
        !field.list && !field.payload.is_empty() && field.payload.len() <= 33,
        "compact path bound",
    )?;
    let flags = field.payload[0] >> 4;
    require(
        flags <= 3 && (flags & 1 == 1 || field.payload[0] & 15 == 0),
        "noncanonical compact path",
    )?;
    let mut path = Vec::with_capacity(64);
    if flags & 1 == 1 {
        path.push(field.payload[0] & 15);
    }
    for byte in &field.payload[1..] {
        path.extend_from_slice(&[byte >> 4, byte & 15]);
    }
    require(path.len() <= 64, "secure trie path bound")?;
    Ok((flags & 2 != 0, path))
}

fn stored_value(field: Field<'_>) -> Check<[u8; 32]> {
    require(!field.list, "storage leaf must contain encoded integer")?;
    let (list, bytes, used) = rlp::item(field.payload)?;
    require(
        !list
            && used == field.payload.len()
            && !bytes.is_empty()
            && bytes.len() <= 32
            && bytes[0] != 0,
        "nonzero canonical storage integer required",
    )?;
    let mut result = [0; 32];
    result[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(result)
}

/// Proof nodes are ordered root-to-leaf hashed nodes. Inline children are read
/// from their parent, never omitted by treating a missing hash as an empty slot.
pub fn verify_storage(
    root: [u8; 32],
    slot: [u8; 32],
    value: [u8; 32],
    proof: &[String],
) -> Check<()> {
    require(proof.len() <= MAX_NODES, "storage proof node bound")?;
    let nodes: Vec<Vec<u8>> = proof
        .iter()
        .map(|node| rlp::hex_bytes(node, MAX_NODE_BYTES))
        .collect::<Check<_>>()?;
    if root == keccak256(&[0x80]) {
        require(
            value == [0; 32] && (nodes.is_empty() || nodes == [vec![0x80]]),
            "empty root proof mismatch",
        )?;
        return Ok(());
    }
    let hashed = keccak256(&slot);
    let key: Vec<u8> = hashed.iter().flat_map(|b| [b >> 4, b & 15]).collect();
    let mut next = Reference::Hash(root);
    let mut cursor = 0;
    let mut depth = 0;
    let mut branch_required = false;
    for step in 0..MAX_NODES {
        let raw = match next {
            Reference::Empty => {
                return require(
                    cursor == nodes.len() && value == [0; 32],
                    "terminal absence/value mismatch",
                );
            }
            Reference::Hash(expected) => {
                let raw = nodes
                    .get(cursor)
                    .ok_or("incomplete storage proof: referenced child missing")?;
                require(
                    keccak256(raw) == expected && (step == 0 || raw.len() >= 32),
                    "storage child hash/reference mismatch",
                )?;
                cursor += 1;
                raw.as_slice()
            }
            Reference::Inline(raw) => raw,
        };
        let node = fields(raw)?;
        require(
            !branch_required || node.len() == 17,
            "extension must lead to a branch",
        )?;
        branch_required = false;
        if node.len() == 17 {
            require(
                depth < 64 && !node[16].list && node[16].payload.is_empty(),
                "fixed-length secure trie branch required",
            )?;
            let mut children = Vec::with_capacity(16);
            for field in &node[..16] {
                children.push(reference(*field)?);
            }
            require(
                children
                    .iter()
                    .filter(|c| !matches!(c, Reference::Empty))
                    .count()
                    >= 2,
                "noncanonical single-child branch",
            )?;
            next = reference(node[usize::from(key[depth])])?;
            depth += 1;
        } else {
            let (leaf, path) = compact(node[0])?;
            require(depth + path.len() <= 64, "compact path exceeds secure key")?;
            let terminal = if leaf {
                require(depth + path.len() == 64, "storage leaf key width")?;
                Some(stored_value(node[1])?)
            } else {
                require(
                    !path.is_empty() && depth + path.len() < 64,
                    "invalid extension length",
                )?;
                require(
                    !matches!(reference(node[1])?, Reference::Empty),
                    "empty extension child",
                )?;
                None
            };
            if path != key[depth..depth + path.len()] {
                return require(
                    cursor == nodes.len() && value == [0; 32],
                    "divergent path/value mismatch",
                );
            }
            depth += path.len();
            if let Some(actual) = terminal {
                return require(
                    cursor == nodes.len() && value == actual,
                    "terminal storage value mismatch",
                );
            }
            next = reference(node[1])?;
            branch_required = true;
        }
    }
    Err("storage trie traversal bound")
}
