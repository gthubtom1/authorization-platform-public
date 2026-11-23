//! Dependency-free JSON value, parser and shared codec helpers.

use std::collections::BTreeMap;

use super::contract::ContractError;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JsonValue {
    Null,
    Bool(bool),
    Number(u64),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

pub(crate) fn json_object<'a>(
    value: &'a JsonValue,
    field: &str,
) -> Result<&'a BTreeMap<String, JsonValue>, ContractError> {
    match value {
        JsonValue::Object(object) => Ok(object),
        _ => Err(ContractError::InvalidManifest(format!(
            "{field} must be an object"
        ))),
    }
}

pub(crate) fn json_array<'a>(
    value: &'a JsonValue,
    field: &str,
) -> Result<&'a [JsonValue], ContractError> {
    match value {
        JsonValue::Array(array) => Ok(array),
        _ => Err(ContractError::InvalidManifest(format!(
            "{field} must be an array"
        ))),
    }
}

pub(crate) fn json_string<'a>(value: &'a JsonValue, field: &str) -> Result<&'a str, ContractError> {
    match value {
        JsonValue::String(string) => Ok(string),
        _ => Err(ContractError::InvalidManifest(format!(
            "{field} must be a string"
        ))),
    }
}

pub(crate) fn json_required<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
) -> Result<&'a JsonValue, ContractError> {
    object
        .get(key)
        .ok_or_else(|| ContractError::InvalidManifest(format!("{field} is required")))
}

pub(crate) fn json_required_string<'a>(
    object: &'a BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
) -> Result<&'a str, ContractError> {
    json_string(json_required(object, key, field)?, field)
}

pub(crate) fn json_required_bool(
    object: &BTreeMap<String, JsonValue>,
    key: &str,
    field: &str,
) -> Result<bool, ContractError> {
    match json_required(object, key, field)? {
        JsonValue::Bool(value) => Ok(*value),
        _ => Err(ContractError::InvalidManifest(format!(
            "{field} must be a boolean"
        ))),
    }
}

pub(crate) fn ensure_known_fields(
    object: &BTreeMap<String, JsonValue>,
    known_fields: &[&str],
    field: &str,
) -> Result<(), ContractError> {
    if let Some(unknown) = object
        .keys()
        .find(|key| !known_fields.contains(&key.as_str()))
    {
        return Err(ContractError::InvalidManifest(format!(
            "{field} contains unknown field: {unknown}"
        )));
    }
    Ok(())
}

pub(crate) fn serialize_json(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(value) => value.to_string(),
        JsonValue::Number(value) => value.to_string(),
        JsonValue::String(value) => quote_json_string(value),
        JsonValue::Array(values) => {
            let values = values
                .iter()
                .map(serialize_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{values}]")
        }
        JsonValue::Object(object) => {
            let fields = object
                .iter()
                .map(|(key, value)| format!("{}:{}", quote_json_string(key), serialize_json(value)))
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{fields}}}")
        }
    }
}

fn quote_json_string(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\u{08}' => quoted.push_str("\\b"),
            '\u{0C}' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            character if character.is_control() => {
                quoted.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    quoted
}

pub(crate) struct JsonParser<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> JsonParser<'a> {
    pub(crate) fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            position: 0,
        }
    }

    pub(crate) fn parse(mut self) -> Result<JsonValue, String> {
        self.skip_whitespace();
        let value = self.parse_value()?;
        self.skip_whitespace();
        if self.position != self.input.len() {
            return Err("trailing data after the root value".to_string());
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<JsonValue, String> {
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't') => {
                self.consume_literal(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.consume_literal(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'n') => {
                self.consume_literal(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(character @ b'0'..=b'9') => self.parse_number(character),
            Some(_) => Err(format!("unexpected character at byte {}", self.position)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, String> {
        self.expect_byte(b'{')?;
        let mut object = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(JsonValue::Object(object));
        }

        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect_byte(b':')?;
            self.skip_whitespace();
            let value = self.parse_value()?;
            if object.insert(key.clone(), value).is_some() {
                return Err(format!("duplicate object field: {key}"));
            }
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.position += 1;
                }
                Some(b'}') => {
                    self.position += 1;
                    return Ok(JsonValue::Object(object));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.position)),
            }
        }
    }

    fn parse_array(&mut self) -> Result<JsonValue, String> {
        self.expect_byte(b'[')?;
        let mut array = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(JsonValue::Array(array));
        }

        loop {
            self.skip_whitespace();
            array.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.position += 1;
                }
                Some(b']') => {
                    self.position += 1;
                    return Ok(JsonValue::Array(array));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.position)),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect_byte(b'"')?;
        let mut value = String::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| "unterminated string".to_string())?;
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(value);
                }
                b'\\' => {
                    self.position += 1;
                    value.push(self.parse_escape()?);
                }
                byte if byte < 0x20 => {
                    return Err(format!(
                        "control character in string at byte {}",
                        self.position
                    ));
                }
                byte if byte.is_ascii() => {
                    value.push(byte as char);
                    self.position += 1;
                }
                _ => {
                    let tail = std::str::from_utf8(&self.input[self.position..])
                        .map_err(|_| format!("invalid UTF-8 at byte {}", self.position))?;
                    let character = tail
                        .chars()
                        .next()
                        .ok_or_else(|| "unterminated string".to_string())?;
                    value.push(character);
                    self.position += character.len_utf8();
                }
            }
        }
    }

    fn parse_escape(&mut self) -> Result<char, String> {
        match self.take_byte() {
            Some(b'"') => Ok('"'),
            Some(b'\\') => Ok('\\'),
            Some(b'/') => Ok('/'),
            Some(b'b') => Ok('\u{08}'),
            Some(b'f') => Ok('\u{0C}'),
            Some(b'n') => Ok('\n'),
            Some(b'r') => Ok('\r'),
            Some(b't') => Ok('\t'),
            Some(b'u') => {
                let mut code = 0u32;
                for _ in 0..4 {
                    let digit = self
                        .take_byte()
                        .and_then(hex_digit)
                        .ok_or_else(|| "invalid unicode escape".to_string())?;
                    code = code * 16 + u32::from(digit);
                }
                if (0xD800..=0xDFFF).contains(&code) {
                    return Err("surrogate unicode escapes are not supported".to_string());
                }
                char::from_u32(code).ok_or_else(|| "invalid unicode scalar".to_string())
            }
            Some(_) => Err(format!("invalid escape at byte {}", self.position - 1)),
            None => Err("unterminated escape".to_string()),
        }
    }

    fn parse_number(&mut self, first: u8) -> Result<JsonValue, String> {
        let start = self.position;
        if first == b'0' {
            self.position += 1;
            if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                return Err("numbers cannot contain leading zeroes".to_string());
            }
        } else {
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
        }
        let text = std::str::from_utf8(&self.input[start..self.position])
            .map_err(|_| "invalid number encoding".to_string())?;
        let number = text
            .parse::<u64>()
            .map_err(|_| "number is outside the supported unsigned range".to_string())?;
        Ok(JsonValue::Number(number))
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), String> {
        if self.input.get(self.position..self.position + literal.len()) == Some(literal) {
            self.position += literal.len();
            Ok(())
        } else {
            Err(format!("invalid literal at byte {}", self.position))
        }
    }

    fn expect_byte(&mut self, expected: u8) -> Result<(), String> {
        if self.take_byte() == Some(expected) {
            Ok(())
        } else {
            Err(format!(
                "expected '{}' at byte {}",
                expected as char, self.position
            ))
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }

    fn take_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.position += 1;
        Some(byte)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
