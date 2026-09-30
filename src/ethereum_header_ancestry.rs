// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bounded Ethereum execution-header links, not consensus or source authentication.
//!
//! Hashes are Keccak-256 of the exact canonical RLP bytes. Parent linkage and
//! caller-selected anchors do not authenticate those anchors or prove finality.

use crate::{hex, merkle::keccak256};
use serde::Deserialize;
use std::collections::BTreeSet;

pub const MAX_HEADERS: usize = 256;
pub const MAX_HEADER_BYTES: usize = 1024;
pub const MAX_REQUEST_BYTES: usize = 1024 * 1024;
pub const REQUEST_DOMAIN: &[u8] = b"BLOCH-ETHEREUM-HEADER-ANCESTRY-v2\0";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Anchor {
    pub block_number: String,
    pub block_hash: String,
    pub parent_hash: Option<String>,
    pub timestamp: Option<String>,
    pub state_root: String,
    pub transactions_root: String,
    pub receipts_root: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Evidence {
    pub schema: String,
    pub manifest_canonical_sha256: String,
    pub comparison_canonical_sha256: String,
    pub anchors: Vec<Anchor>,
    pub headers: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub timestamp: u64,
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
}

type Check<T> = Result<T, &'static str>;

fn require(condition: bool, message: &'static str) -> Check<()> {
    if condition {
        Ok(())
    } else {
        Err(message)
    }
}

fn hex_bytes(value: &str, maximum: usize) -> Check<Vec<u8>> {
    require(
        value.starts_with("0x")
            && value.len() >= 4
            && value.len() <= 2 + maximum * 2
            && value.len().is_multiple_of(2)
            && value.as_bytes()[2..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "canonical bounded lowercase hex required",
    )?;
    hex::decode(value).map_err(|_| "invalid hex")
}

fn hash_bytes(value: &str) -> Check<[u8; 32]> {
    let bytes: [u8; 32] = hex_bytes(value, 32)?
        .try_into()
        .map_err(|_| "hash length")?;
    Ok(bytes)
}

fn hash(value: &str) -> Check<[u8; 32]> {
    let bytes = hash_bytes(value)?;
    require(bytes.iter().any(|b| *b != 0), "zero hash")?;
    Ok(bytes)
}

fn decimal(value: &str) -> Check<u64> {
    require(
        !value.is_empty()
            && value.len() <= 20
            && value.bytes().all(|b| b.is_ascii_digit())
            && (value == "0" || !value.starts_with('0')),
        "canonical uint64 required",
    )?;
    value.parse().map_err(|_| "uint64 overflow")
}

fn length(bytes: &[u8]) -> Check<usize> {
    require(
        !bytes.is_empty() && bytes.len() <= 8 && bytes[0] != 0,
        "noncanonical RLP length",
    )?;
    bytes.iter().try_fold(0usize, |value, byte| {
        value
            .checked_mul(256)
            .and_then(|v| v.checked_add(*byte as usize))
            .ok_or("RLP length overflow")
    })
}

// One nonrecursive item. Header fields must be scalars, so nested lists are
// rejected by the caller rather than traversed or allocated.
fn item(bytes: &[u8]) -> Check<(bool, &[u8], usize)> {
    let tag = *bytes.first().ok_or("truncated RLP")?;
    if tag < 0x80 {
        return Ok((false, &bytes[..1], 1));
    }
    let (list, offset, size) = match tag {
        0x80..=0xb7 => (false, 1, usize::from(tag - 0x80)),
        0xb8..=0xbf | 0xf8..=0xff => {
            let list = tag >= 0xf8;
            let count = usize::from(tag - if list { 0xf7 } else { 0xb7 });
            let encoded_length = bytes.get(1..1 + count).ok_or("truncated RLP length")?;
            let size = length(encoded_length)?;
            require(size >= 56, "nonminimal RLP length form")?;
            (list, 1 + count, size)
        }
        0xc0..=0xf7 => (true, 1, usize::from(tag - 0xc0)),
        _ => unreachable!(),
    };
    let end = offset.checked_add(size).ok_or("RLP length overflow")?;
    let payload = bytes.get(offset..end).ok_or("truncated RLP payload")?;
    require(
        list || size != 1 || payload[0] >= 0x80,
        "nonminimal RLP single byte",
    )?;
    Ok((list, payload, end))
}

fn integer(bytes: &[u8], maximum: usize) -> Check<()> {
    require(
        bytes.len() <= maximum && bytes.first() != Some(&0),
        "noncanonical RLP integer",
    )
}

fn uint64(bytes: &[u8]) -> Check<u64> {
    integer(bytes, 8)?;
    Ok(bytes
        .iter()
        .fold(0u64, |value, byte| value * 256 + u64::from(*byte)))
}

/// Parse the supported execution-header layouts without enforcing fork rules.
/// Accepted field counts: 15, 16, 17, 20, 21 and 23. In particular partial
/// Cancun extensions and a lone block-access-list extension are refused.
pub fn decode_header(raw: &[u8]) -> Check<Header> {
    require(
        !raw.is_empty() && raw.len() <= MAX_HEADER_BYTES,
        "header byte bound",
    )?;
    let (list, payload, consumed) = item(raw)?;
    require(
        list && consumed == raw.len(),
        "one complete RLP header list required",
    )?;
    let mut fields = Vec::with_capacity(23);
    let mut remaining = payload;
    while !remaining.is_empty() {
        require(fields.len() < 23, "unsupported header field count")?;
        let (nested, value, used) = item(remaining)?;
        require(!nested, "nested header field")?;
        fields.push(value);
        remaining = &remaining[used..];
    }
    require(
        matches!(fields.len(), 15 | 16 | 17 | 20 | 21 | 23),
        "unsupported header layout",
    )?;
    for index in [0, 1, 3, 4, 5, 13] {
        require(fields[index].len() == 32, "header hash field width")?;
    }
    require(
        fields[2].len() == 20
            && fields[6].len() == 256
            && fields[12].len() <= 32
            && fields[14].len() == 8,
        "header field width",
    )?;
    integer(fields[7], 32)?;
    let number = uint64(fields[8])?;
    let gas_limit = uint64(fields[9])?;
    let gas_used = uint64(fields[10])?;
    let timestamp = uint64(fields[11])?;
    require(gas_used <= gas_limit, "gas used exceeds limit")?;
    if fields.len() >= 16 {
        integer(fields[15], 32)?;
    }
    if fields.len() >= 17 {
        require(fields[16].len() == 32, "withdrawals root width")?;
    }
    if fields.len() >= 20 {
        uint64(fields[17])?;
        uint64(fields[18])?;
        require(fields[19].len() == 32, "parent beacon root width")?;
    }
    if fields.len() >= 21 {
        require(fields[20].len() == 32, "requests hash width")?;
    }
    if fields.len() == 23 {
        require(fields[21].len() == 32, "block access list hash width")?;
        uint64(fields[22])?;
    }
    Ok(Header {
        number,
        hash: keccak256(raw),
        parent_hash: fields[0].try_into().unwrap(),
        timestamp,
        state_root: fields[3].try_into().unwrap(),
        transactions_root: fields[4].try_into().unwrap(),
        receipts_root: fields[5].try_into().unwrap(),
    })
}

/// Verify exact endpoint and intermediate anchors along one contiguous chain.
/// This only proves ancestry conditional on the supplied hashes being genuine.
pub fn verify(evidence: &Evidence) -> Check<Vec<Header>> {
    require(
        evidence.schema == "postern.custody-deployment-ancestry.v2",
        "unsupported ancestry schema",
    )?;
    hash(&evidence.manifest_canonical_sha256)?;
    hash(&evidence.comparison_canonical_sha256)?;
    require(
        !evidence.anchors.is_empty() && evidence.anchors.len() <= 9,
        "anchor count bound",
    )?;
    require(
        !evidence.headers.is_empty() && evidence.headers.len() <= MAX_HEADERS,
        "header count bound",
    )?;
    let mut anchors = Vec::with_capacity(evidence.anchors.len());
    let mut last = None;
    for anchor in &evidence.anchors {
        let number = decimal(&anchor.block_number)?;
        require(
            last.is_none_or(|prior| number > prior),
            "anchors must have distinct ascending heights",
        )?;
        let parent_hash = anchor.parent_hash.as_deref().map(hash_bytes).transpose()?;
        require(
            number == 0 || parent_hash.is_none_or(|parent| parent.iter().any(|b| *b != 0)),
            "zero captured parent hash above genesis",
        )?;
        let timestamp = anchor.timestamp.as_deref().map(decimal).transpose()?;
        anchors.push((
            number,
            hash(&anchor.block_hash)?,
            parent_hash,
            timestamp,
            hash(&anchor.state_root)?,
            hash(&anchor.transactions_root)?,
            hash(&anchor.receipts_root)?,
        ));
        last = Some(number);
    }
    let expected_count = anchors
        .last()
        .unwrap()
        .0
        .checked_sub(anchors[0].0)
        .and_then(|span| span.checked_add(1))
        .ok_or("anchor span overflow")?;
    require(
        expected_count == evidence.headers.len() as u64,
        "complete exact anchor range required",
    )?;
    let mut headers: Vec<Header> = Vec::with_capacity(evidence.headers.len());
    let mut seen = BTreeSet::new();
    for encoded in &evidence.headers {
        let header = decode_header(&hex_bytes(encoded, MAX_HEADER_BYTES)?)?;
        require(seen.insert(header.hash), "repeated header hash")?;
        if let Some(previous) = headers.last() {
            require(
                previous.number.checked_add(1) == Some(header.number)
                    && header.parent_hash == previous.hash,
                "broken header ancestry",
            )?;
            require(
                header.timestamp > previous.timestamp,
                "nonincreasing header time",
            )?;
        } else {
            require(header.number == anchors[0].0, "wrong first header height")?;
        }
        headers.push(header);
    }
    for (
        number,
        expected_hash,
        parent_hash,
        timestamp,
        state_root,
        transactions_root,
        receipts_root,
    ) in anchors
    {
        let index =
            usize::try_from(number - headers[0].number).map_err(|_| "anchor index overflow")?;
        require(
            headers
                .get(index)
                .is_some_and(|header| header.number == number && header.hash == expected_hash),
            "header anchor mismatch",
        )?;
        let header = &headers[index];
        require(
            header.state_root == state_root
                && header.transactions_root == transactions_root
                && header.receipts_root == receipts_root,
            "captured header roots mismatch",
        )?;
        require(
            parent_hash.is_none_or(|parent| parent == header.parent_hash)
                && timestamp.is_none_or(|time| time == header.timestamp),
            "captured header metadata mismatch",
        )?;
    }
    Ok(headers)
}

/// Decode a bounded, domain-separated request; unknown and duplicate fields fail.
pub fn verify_request(request: &[u8]) -> Check<Vec<Header>> {
    require(request.len() <= MAX_REQUEST_BYTES, "ancestry request bound")?;
    let json = request
        .strip_prefix(REQUEST_DOMAIN)
        .ok_or("ancestry request domain")?;
    let evidence: Evidence = serde_json::from_slice(json).map_err(|_| "invalid ancestry JSON")?;
    verify(&evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rlp(bytes: &[u8], list: bool) -> Vec<u8> {
        if !list && bytes.len() == 1 && bytes[0] < 0x80 {
            return bytes.to_vec();
        }
        let mut out = vec![];
        let base = if list { 0xc0 } else { 0x80 };
        if bytes.len() < 56 {
            out.push(base + bytes.len() as u8);
        } else {
            let length = bytes.len().to_be_bytes();
            let encoded = &length[length.iter().position(|b| *b != 0).unwrap()..];
            out.push(base + 55 + encoded.len() as u8);
            out.extend_from_slice(encoded);
        }
        out.extend_from_slice(bytes);
        out
    }

    fn number(value: u64) -> Vec<u8> {
        let bytes = value.to_be_bytes();
        bytes[bytes.iter().position(|b| *b != 0).unwrap_or(8)..].to_vec()
    }

    fn fields(height: u64, parent: [u8; 32], count: usize) -> Vec<Vec<u8>> {
        let mut values = vec![
            parent.to_vec(),
            vec![1; 32],
            vec![2; 20],
            vec![3; 32],
            vec![4; 32],
            vec![5; 32],
            vec![0; 256],
            vec![],
            number(height),
            number(30_000_000),
            vec![],
            number(height + 1),
            vec![],
            vec![6; 32],
            vec![0; 8],
        ];
        values.extend([
            vec![1],
            vec![7; 32],
            vec![],
            vec![],
            vec![8; 32],
            vec![9; 32],
            vec![10; 32],
            number(height),
        ]);
        values.truncate(count);
        values
    }

    fn encode_fields(values: &[Vec<u8>]) -> Vec<u8> {
        rlp(
            &values
                .iter()
                .flat_map(|field| rlp(field, false))
                .collect::<Vec<_>>(),
            true,
        )
    }

    fn proof(count: usize) -> Evidence {
        let mut headers = vec![];
        let mut parent = [11; 32];
        for height in 100..100 + count {
            let raw = encode_fields(&fields(height as u64, parent, 21));
            parent = keccak256(&raw);
            headers.push(hex::encode_prefixed(&raw));
        }
        let anchor = |index: usize| Anchor {
            block_number: (100 + index).to_string(),
            block_hash: hex::encode_prefixed(&keccak256(&hex::decode(&headers[index]).unwrap())),
            parent_hash: None,
            timestamp: None,
            state_root: hex::encode_prefixed(&[3; 32]),
            transactions_root: hex::encode_prefixed(&[4; 32]),
            receipts_root: hex::encode_prefixed(&[5; 32]),
        };
        let anchors = if count == 1 {
            vec![anchor(0)]
        } else {
            vec![anchor(0), anchor(count - 1)]
        };
        Evidence {
            schema: "postern.custody-deployment-ancestry.v2".into(),
            manifest_canonical_sha256: hex::encode_prefixed(&[12; 32]),
            comparison_canonical_sha256: hex::encode_prefixed(&[13; 32]),
            anchors,
            headers,
        }
    }

    #[test]
    fn every_captured_root_is_bound_and_v1_cannot_be_promoted() {
        let original = proof(3);
        for anchor in 0..original.anchors.len() {
            for field in 0..3 {
                let mut evidence = original.clone();
                let value = hex::encode_prefixed(&[99; 32]);
                match field {
                    0 => evidence.anchors[anchor].state_root = value,
                    1 => evidence.anchors[anchor].transactions_root = value,
                    _ => evidence.anchors[anchor].receipts_root = value,
                }
                assert_eq!(
                    verify(&evidence).unwrap_err(),
                    "captured header roots mismatch"
                );
            }
        }
        let mut legacy = original;
        legacy.schema = "postern.custody-deployment-ancestry.v1".into();
        assert_eq!(verify(&legacy).unwrap_err(), "unsupported ancestry schema");
    }

    #[test]
    fn contiguous_raw_headers_bind_endpoints_and_intermediate_anchor() {
        let mut evidence = proof(4);
        let middle = decode_header(&hex::decode(&evidence.headers[1]).unwrap()).unwrap();
        evidence.anchors.insert(
            1,
            Anchor {
                block_number: "101".into(),
                block_hash: hex::encode_prefixed(&middle.hash),
                parent_hash: Some(hex::encode_prefixed(&middle.parent_hash)),
                timestamp: Some(middle.timestamp.to_string()),
                state_root: hex::encode_prefixed(&[3; 32]),
                transactions_root: hex::encode_prefixed(&[4; 32]),
                receipts_root: hex::encode_prefixed(&[5; 32]),
            },
        );
        assert_eq!(verify(&evidence).unwrap().len(), 4);
        assert_eq!(verify(&proof(1)).unwrap().len(), 1);
    }

    #[test]
    fn exact_supported_layouts_and_integer_widths() {
        for count in [15, 16, 17, 20, 21, 23] {
            assert!(decode_header(&encode_fields(&fields(0, [0; 32], count))).is_ok());
        }
        for count in [0, 14, 18, 19, 22] {
            assert!(decode_header(&encode_fields(&fields(1, [1; 32], count))).is_err());
        }
        for (index, width) in [
            (0, 31),
            (2, 19),
            (6, 255),
            (8, 9),
            (12, 33),
            (14, 7),
            (15, 33),
            (16, 31),
            (17, 9),
            (18, 9),
            (19, 31),
            (20, 31),
            (21, 31),
            (22, 9),
        ] {
            let mut values = fields(1, [1; 32], 23);
            values[index] = vec![1; width];
            assert!(
                decode_header(&encode_fields(&values)).is_err(),
                "field {index}"
            );
        }
        for index in [7, 8, 9, 10, 11, 15, 17, 18, 22] {
            let mut values = fields(1, [1; 32], 23);
            values[index] = vec![0];
            assert!(
                decode_header(&encode_fields(&values)).is_err(),
                "integer {index}"
            );
        }
    }

    #[test]
    fn noncanonical_truncated_nested_and_trailing_rlp_are_refused() {
        for bytes in [
            vec![],
            vec![0xb8, 1, 0x80],
            vec![0xb9, 0, 56],
            vec![0x81, 1],
            vec![0xf8, 1, 0x80],
            vec![0xff; 9],
            vec![0xf8, 56],
        ] {
            assert!(decode_header(&bytes).is_err());
        }
        let valid = encode_fields(&fields(1, [1; 32], 15));
        assert!(decode_header(&[valid.clone(), vec![0]].concat()).is_err());
        assert!(decode_header(&valid[..valid.len() - 1]).is_err());
        let nested = rlp(
            &[
                vec![0xc0],
                fields(1, [1; 32], 15)[1..]
                    .iter()
                    .flat_map(|v| rlp(v, false))
                    .collect(),
            ]
            .concat(),
            true,
        );
        assert!(decode_header(&nested).is_err());
    }

    #[test]
    fn mutated_links_heights_timestamps_anchors_and_order_are_refused() {
        for mutation in 0..8 {
            let mut evidence = proof(3);
            match mutation {
                0 => {
                    evidence.headers.swap(0, 1);
                }
                1 => {
                    evidence.headers[1] = evidence.headers[0].clone();
                }
                2 => {
                    evidence.headers.remove(1);
                }
                3 => {
                    evidence.anchors[0].block_hash = hex::encode_prefixed(&[99; 32]);
                }
                4 => {
                    evidence.anchors[0].block_number = "0100".into();
                }
                5 => {
                    evidence.anchors.reverse();
                }
                6 => {
                    evidence.headers[1] =
                        hex::encode_prefixed(&encode_fields(&fields(101, [99; 32], 21)));
                }
                7 => {
                    let mut raw_fields = fields(
                        101,
                        decode_header(&hex::decode(&evidence.headers[0]).unwrap())
                            .unwrap()
                            .hash,
                        21,
                    );
                    raw_fields[11] = number(100);
                    evidence.headers[1] = hex::encode_prefixed(&encode_fields(&raw_fields));
                }
                _ => unreachable!(),
            }
            assert!(verify(&evidence).is_err(), "mutation {mutation}");
        }
    }

    #[test]
    fn bounds_are_enforced_before_header_decoding() {
        assert!(verify(&proof(MAX_HEADERS)).is_ok());
        assert!(verify(&proof(MAX_HEADERS + 1)).is_err());
        let mut evidence = proof(1);
        evidence.headers[0] = format!("0x{}", "00".repeat(MAX_HEADER_BYTES + 1));
        assert!(verify(&evidence).is_err());
        let mut evidence = proof(1);
        evidence.anchors.push(Anchor {
            block_number: u64::MAX.to_string(),
            block_hash: hex::encode_prefixed(&[99; 32]),
            parent_hash: None,
            timestamp: None,
            state_root: hex::encode_prefixed(&[3; 32]),
            transactions_root: hex::encode_prefixed(&[4; 32]),
            receipts_root: hex::encode_prefixed(&[5; 32]),
        });
        assert!(verify(&evidence).is_err());
    }

    #[test]
    fn request_domain_json_duplicates_unknown_fields_and_byte_bound() {
        assert!(verify_request(b"{} ").is_err());
        assert!(
            verify_request(&[REQUEST_DOMAIN, br#"{"schema":"x","schema":"y"}"#].concat()).is_err()
        );
        assert!(verify_request(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
        assert!(verify_request(&[REQUEST_DOMAIN, br#"{"unknown":true}"#].concat()).is_err());
    }
}
