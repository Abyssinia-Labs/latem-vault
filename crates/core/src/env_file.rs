//! The `NAME=value` files `pinkvault import-env` and the Mac app's import read.
//!
//! The format is latem's `secrets.env` (latem `internal/secrets/file.go`), so each value comes
//! across byte for byte as latem reads it today:
//!
//! - Each line is trimmed of whitespace. Blank lines and lines starting with `#` are skipped.
//! - Every other line is `NAME=value`. The name is letters, digits and `_`, not starting with a
//!   digit.
//! - An unquoted value is taken as it is, `#` and `$` included.
//! - `'…'` is literal, from the first quote to the last.
//! - `"…"` understands `\n`, `\r`, `\t`, `\\` and `\"`. Any other escape is an error, because
//!   other readers disagree about what it means.
//! - There is no `export`, no `${…}` expansion and no value spanning lines.
//! - A value can't hold a NUL byte, which no environment variable can.
//!
//! A name set twice is an error rather than last-wins: which value was meant is for the person
//! who wrote the file to say. Errors give line numbers, never line content, since a line that
//! doesn't parse is likely someone's secret.

use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::names::is_env_name;

/// Why a file didn't parse: a line number and what's wrong with it, never the line itself.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ParseError(String);

type Result<T> = std::result::Result<T, ParseError>;

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err(ParseError(format!($($arg)*)))
    };
}

/// The largest file read, the same limit latem puts on `secrets.env`.
pub const MAX_LEN: usize = 1 << 20;

/// One `NAME=value` line.
pub struct Line {
    pub name: String,
    pub value: Zeroizing<Vec<u8>>,
    pub number: usize,
}

/// The file's `NAME=value` lines, in order.
pub fn parse(file: &[u8]) -> Result<Vec<Line>> {
    let mut lines = Vec::new();
    let mut seen = HashMap::new();
    for (i, line) in file.split(|&b| b == b'\n').enumerate() {
        let number = i + 1;
        let line = trim_space(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let Some(eq) = line.iter().position(|&b| b == b'=') else {
            bail!("line {number}: expected NAME=value");
        };
        let name = trim_space(&line[..eq]);
        if name
            .strip_prefix(b"export")
            .is_some_and(|rest| rest.first().is_some_and(u8::is_ascii_whitespace))
        {
            bail!("line {number}: remove `export`; the file is read, not run by a shell");
        }
        let name = match std::str::from_utf8(name) {
            Ok(name) if is_env_name(name) => name,
            _ => bail!(
                "line {number}: the name must be letters, digits and '_', not starting with a digit"
            ),
        };
        if let Some(first) = seen.insert(name.to_owned(), number) {
            bail!("{name} is set on lines {first} and {number}; keep one");
        }
        let value = &line[eq + 1..];
        let value = &value[value
            .iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count()..];
        let value = parse_value(value, number)?;
        // `run` couldn't pass it on, so refuse it now rather than then.
        if value.contains(&0) {
            bail!(
                "line {number}: the value has a NUL byte, which an environment variable can't hold"
            );
        }
        lines.push(Line {
            name: name.to_owned(),
            value,
            number,
        });
    }
    Ok(lines)
}

/// Trims what Go's `bytes.TrimSpace` trims, Unicode spaces included, so a line reads as it does
/// in latem. Like Go, it stops at bytes that aren't UTF-8.
fn trim_space(line: &[u8]) -> &[u8] {
    let start = line.utf8_chunks().next().map_or(0, |chunk| {
        chunk.valid().len() - chunk.valid().trim_start().len()
    });
    let line = &line[start..];
    let end = match line.utf8_chunks().last() {
        Some(chunk) if chunk.invalid().is_empty() => {
            chunk.valid().len() - chunk.valid().trim_end().len()
        }
        _ => 0,
    };
    &line[..line.len() - end]
}

fn parse_value(value: &[u8], number: usize) -> Result<Zeroizing<Vec<u8>>> {
    match value.first() {
        Some(b'\'') => {
            let end = value.iter().rposition(|&b| b == b'\'').unwrap_or(0);
            if end == 0 {
                bail!("line {number}: unterminated single quote");
            }
            if end != value.len() - 1 {
                bail!("line {number}: characters after the closing quote");
            }
            Ok(Zeroizing::new(value[1..end].to_vec()))
        }
        Some(b'"') => unquote_double(value, number),
        _ => Ok(Zeroizing::new(value.to_vec())),
    }
}

fn unquote_double(value: &[u8], number: usize) -> Result<Zeroizing<Vec<u8>>> {
    // Never longer than the input, so it doesn't reallocate and leave copies behind.
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value[1..].iter().enumerate();
    while let Some((i, &b)) = bytes.next() {
        match b {
            b'"' => {
                if i + 2 != value.len() {
                    bail!("line {number}: characters after the closing quote");
                }
                return Ok(out);
            }
            b'\\' => out.push(match bytes.next() {
                Some((_, b'n')) => b'\n',
                Some((_, b'r')) => b'\r',
                Some((_, b't')) => b'\t',
                Some((_, b'\\')) => b'\\',
                Some((_, b'"')) => b'"',
                Some(_) => bail!("line {number}: unknown escape in a double-quoted value"),
                None => break,
            }),
            b => out.push(b),
        }
    }
    bail!("line {number}: unterminated double quote")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(file: &str) -> Vec<(String, Vec<u8>)> {
        parse(file.as_bytes())
            .unwrap()
            .into_iter()
            .map(|line| (line.name, line.value.to_vec()))
            .collect()
    }

    fn error(file: &str) -> String {
        match parse(file.as_bytes()) {
            Ok(_) => panic!("{file:?} parsed"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn reads_latem_values() {
        let file = "\
# comment

PLAIN=a b # not a comment $HOME
  SPACED =   x y  \r
EMPTY=
SINGLE='it''s \\n $HOME'
DOUBLE=\"line\\none\\t\\\"q\\\" \\\\ $HOME\"
EMPTY_QUOTES=\"\"
EQUALS=a=b=
_lower9=1";
        let expected: Vec<(&str, &[u8])> = vec![
            ("PLAIN", b"a b # not a comment $HOME"),
            ("SPACED", b"x y"),
            ("EMPTY", b""),
            ("SINGLE", b"it''s \\n $HOME"),
            ("DOUBLE", b"line\none\t\"q\" \\ $HOME"),
            ("EMPTY_QUOTES", b""),
            ("EQUALS", b"a=b="),
            ("_lower9", b"1"),
        ];
        let expected: Vec<(String, Vec<u8>)> = expected
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value.to_vec()))
            .collect();
        assert_eq!(values(file), expected);
        assert_eq!(parse(b"A=1\nB=2").unwrap()[1].number, 2);

        // Go's TrimSpace: Unicode spaces at either end go, and bytes that aren't UTF-8 stop it.
        assert_eq!(
            values("A=\u{a0}x\u{a0}\u{2003}"),
            [("A".into(), b"\xc2\xa0x".to_vec())]
        );
        assert_eq!(parse(b"A=x \xff ").unwrap()[0].value.as_slice(), b"x \xff");
        assert_eq!(parse(b"A=\x0bx\x0b").unwrap()[0].value.as_slice(), b"\x0bx");
        assert!(values("\n# only comments\n").is_empty());
    }

    #[test]
    fn errors_give_lines_not_content() {
        let cases = [
            ("A=1\nhunter2\n", "line 2: expected NAME=value"),
            ("export A=1", "line 1: remove `export`"),
            ("1A=x", "line 1: the name must be"),
            ("A B=hunter2", "line 1: the name must be"),
            ("A='hunter2", "line 1: unterminated single quote"),
            ("A='hunter'2", "line 1: characters after the closing quote"),
            ("A=\"hunter2", "line 1: unterminated double quote"),
            ("A=\"hunter2\\", "line 1: unterminated double quote"),
            (
                "A=\"hunter\"2",
                "line 1: characters after the closing quote",
            ),
            ("A=\"hunter\\x2\"", "line 1: unknown escape"),
            (
                "A=\"-----BEGIN KEY\nabc\n-----END KEY\"",
                "line 1: unterminated",
            ),
            ("A=1\n\nA=hunter2", "A is set on lines 1 and 3; keep one"),
            ("A=hunter\u{0}2", "line 1: the value has a NUL byte"),
        ];
        for (file, expected) in cases {
            let error = error(file);
            assert!(error.starts_with(expected), "{file:?}: {error}");
            assert!(!error.contains("hunter"), "{file:?}: {error}");
        }
    }
}
