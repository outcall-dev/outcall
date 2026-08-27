pub(super) const MAX_TLS_RECORD_PAYLOAD: usize = 16 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum ClientHelloError {
    #[error("invalid TLS ClientHello")]
    Invalid,
    #[error("TLS record exceeds the maximum supported size")]
    TooLarge,
}

pub(super) fn record_payload_length(header: &[u8; 5]) -> Result<usize, ClientHelloError> {
    if header[0] != 0x16 || header[1] != 0x03 {
        return Err(ClientHelloError::Invalid);
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if !(4..=MAX_TLS_RECORD_PAYLOAD).contains(&length) {
        return Err(if length > MAX_TLS_RECORD_PAYLOAD {
            ClientHelloError::TooLarge
        } else {
            ClientHelloError::Invalid
        });
    }
    Ok(length)
}

pub(super) fn extract_sni(record: &[u8]) -> Result<Option<String>, ClientHelloError> {
    let header: &[u8; 5] = record
        .get(..5)
        .and_then(|header| header.try_into().ok())
        .ok_or(ClientHelloError::Invalid)?;
    let payload_length = record_payload_length(header)?;
    if record.len() != payload_length + 5 || record[5] != 0x01 {
        return Err(ClientHelloError::Invalid);
    }

    let handshake_length =
        ((record[6] as usize) << 16) | ((record[7] as usize) << 8) | record[8] as usize;
    let hello_end = 9usize
        .checked_add(handshake_length)
        .ok_or(ClientHelloError::Invalid)?;
    if hello_end > record.len() {
        // Fail closed when a ClientHello is split across multiple TLS records.
        return Err(ClientHelloError::Invalid);
    }

    let mut cursor = Cursor::new(record, 9, hello_end);
    cursor.skip(2)?; // legacy_version
    cursor.skip(32)?; // random
    let session_id_length = cursor.read_u8()? as usize;
    cursor.skip(session_id_length)?;
    let cipher_suites_length = cursor.read_u16()? as usize;
    if cipher_suites_length == 0 || !cipher_suites_length.is_multiple_of(2) {
        return Err(ClientHelloError::Invalid);
    }
    cursor.skip(cipher_suites_length)?;
    let compression_methods_length = cursor.read_u8()? as usize;
    if compression_methods_length == 0 {
        return Err(ClientHelloError::Invalid);
    }
    cursor.skip(compression_methods_length)?;

    if cursor.position == hello_end {
        return Ok(None);
    }
    let extensions_length = cursor.read_u16()? as usize;
    let extensions_end = cursor
        .position
        .checked_add(extensions_length)
        .ok_or(ClientHelloError::Invalid)?;
    if extensions_end != hello_end {
        return Err(ClientHelloError::Invalid);
    }

    while cursor.position < extensions_end {
        let extension_type = cursor.read_u16()?;
        let extension_length = cursor.read_u16()? as usize;
        let extension_end = cursor
            .position
            .checked_add(extension_length)
            .ok_or(ClientHelloError::Invalid)?;
        if extension_end > extensions_end {
            return Err(ClientHelloError::Invalid);
        }
        if extension_type == 0 {
            return parse_server_name_extension(record, cursor.position, extension_end).map(Some);
        }
        cursor.position = extension_end;
    }
    Ok(None)
}

fn parse_server_name_extension(
    record: &[u8],
    start: usize,
    end: usize,
) -> Result<String, ClientHelloError> {
    let mut cursor = Cursor::new(record, start, end);
    let list_length = cursor.read_u16()? as usize;
    if cursor.position.checked_add(list_length) != Some(end) {
        return Err(ClientHelloError::Invalid);
    }
    while cursor.position < end {
        let name_type = cursor.read_u8()?;
        let name_length = cursor.read_u16()? as usize;
        let name = cursor.read_bytes(name_length)?;
        if name_type != 0 {
            continue;
        }
        let name = std::str::from_utf8(name).map_err(|_| ClientHelloError::Invalid)?;
        if name.is_empty()
            || !name.is_ascii()
            || name.contains('*')
            || name.chars().any(char::is_control)
        {
            return Err(ClientHelloError::Invalid);
        }
        let normalized = name.trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty()
            || !matches!(url::Host::parse(&normalized), Ok(url::Host::Domain(_)))
        {
            return Err(ClientHelloError::Invalid);
        }
        return Ok(normalized);
    }
    Err(ClientHelloError::Invalid)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8], position: usize, end: usize) -> Self {
        Self {
            bytes,
            position,
            end,
        }
    }

    fn read_u8(&mut self) -> Result<u8, ClientHelloError> {
        let byte = *self
            .bytes
            .get(self.position)
            .filter(|_| self.position < self.end)
            .ok_or(ClientHelloError::Invalid)?;
        self.position += 1;
        Ok(byte)
    }

    fn read_u16(&mut self) -> Result<u16, ClientHelloError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ClientHelloError> {
        let next = self
            .position
            .checked_add(length)
            .ok_or(ClientHelloError::Invalid)?;
        if next > self.end || next > self.bytes.len() {
            return Err(ClientHelloError::Invalid);
        }
        let bytes = &self.bytes[self.position..next];
        self.position = next;
        Ok(bytes)
    }

    fn skip(&mut self, length: usize) -> Result<(), ClientHelloError> {
        self.read_bytes(length).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0; 32]);
        body.push(0); // session ID length
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        if let Some(sni) = sni {
            let mut extension = Vec::new();
            let list_length = 3 + sni.len();
            extension.extend_from_slice(&(list_length as u16).to_be_bytes());
            extension.push(0);
            extension.extend_from_slice(&(sni.len() as u16).to_be_bytes());
            extension.extend_from_slice(sni.as_bytes());

            let mut extensions = Vec::new();
            extensions.extend_from_slice(&[0, 0]);
            extensions.extend_from_slice(&(extension.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&extension);
            body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            body.extend_from_slice(&extensions);
        }

        let mut handshake = vec![
            0x01,
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ];
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn extracts_and_normalizes_sni() {
        assert_eq!(
            extract_sni(&client_hello(Some("API.Example.COM."))).unwrap(),
            Some("api.example.com".to_string())
        );
        assert_eq!(extract_sni(&client_hello(None)).unwrap(), None);
    }

    #[test]
    fn rejects_non_tls_and_truncated_records() {
        assert_eq!(
            extract_sni(b"GET / HTTP/1.1"),
            Err(ClientHelloError::Invalid)
        );
        let mut hello = client_hello(Some("example.com"));
        hello.pop();
        assert_eq!(extract_sni(&hello), Err(ClientHelloError::Invalid));
    }

    #[test]
    fn rejects_client_hello_split_across_records() {
        let mut hello = client_hello(Some("example.com"));
        let record_length = u16::from_be_bytes([hello[3], hello[4]]);
        hello[3..5].copy_from_slice(&(record_length - 1).to_be_bytes());
        hello.pop();

        assert_eq!(extract_sni(&hello), Err(ClientHelloError::Invalid));
    }

    #[test]
    fn bounds_tls_record_size() {
        assert_eq!(
            record_payload_length(&[0x16, 0x03, 0x01, 0xff, 0xff]),
            Err(ClientHelloError::TooLarge)
        );
    }
}
