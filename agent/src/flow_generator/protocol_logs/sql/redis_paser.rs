use crate::common::{enums::IpProtocol, l7_protocol_log::ParseParam};

const MIN_LEN: usize = 2;
const PARSE_ERR: u8 = 1;
const RESP_ERR: u8 = 1 << 1;
const RESP_MUL: u8 = 1 << 2;
const MAX_LEN: usize = 32;
const MAX_COUNT: usize = 20;

#[derive(Debug, Default)]
pub struct RedisParser {
    lines: Vec<u8>,
    err_lines: Vec<u8>,
    status: u8,
    count: usize,
}

impl RedisParser {
    fn set_resp_err(&mut self) {
        self.status |= RESP_ERR;
    }
    fn set_parse_err(&mut self) {
        self.status |= PARSE_ERR;
    }
    fn set_resp_mul(&mut self) {
        self.status |= RESP_MUL;
    }

    pub fn is_resp_err(&self) -> bool {
        self.status & RESP_ERR > 0
    }
    pub fn is_parse_err(&self) -> bool {
        self.status & PARSE_ERR > 0
    }
    pub fn is_resp_mul(&self) -> bool {
        self.status & RESP_MUL > 0
    }
    pub fn is_data_err(&self, original_payload_len: u32, payload: &[u8]) -> bool {
        if !self.is_resp_err() {
            return false;
        }
        if original_payload_len == payload.len() as u32 {
            return true;
        }
        if self.is_resp_mul() {
            return false;
        }
        return match payload[0] {
            b'+' | b'-' | b':' | b'*' | b'$' => false,
            _ => true,
        };
    }
    pub fn get_content_str(&self) -> &str {
        std::str::from_utf8(self.lines.as_slice()).unwrap_or("")
    }
    pub fn get_content(&self) -> &[u8] {
        self.lines.as_slice()
    }
    pub fn get_err(&self) -> &[u8] {
        self.err_lines.as_slice()
    }
    pub fn parse(&mut self, payload: &[u8]) {
        self.dispatcher(payload, 0);
        if self.lines.len() < 1 {
            self.set_parse_err();
        }
    }

    fn dispatcher(&mut self, payload: &[u8], offset: usize) {
        if MIN_LEN + offset > payload.len() {
            return;
        }
        if let Some(offset) = match payload[offset] {
            b'*' => self.read_star(payload, offset),
            b'$' => self.read_dollar(payload, offset),
            b'+' | b'-' | b':' => self.read_str(payload, offset),
            _ => None,
        } {
            if offset < payload.len() && self.count < MAX_COUNT {
                self.dispatcher(payload, offset);
            }
            return;
        }
        self.set_parse_err();
    }

    pub fn get_req_type(&self) -> &[u8] {
        if self.is_resp_mul(){
            return b"pipeline";
        }
        &self.lines[..self.lines
            .iter()
            .position(|&x| x == b' ')
            .unwrap_or(self.lines.len())]
    }

    fn read_star(&mut self, payload: &[u8], offset: usize) -> Option<usize> {
        self.add_line();
        match Self::read_len(payload, offset + 1) {
            Some((len, offset)) => {
                if offset >= payload.len() {
                    return None;
                }
                let mut offset = offset;
                for _i in 0..len {
                    if let Some(o) = self.read_dollar(payload, offset) {
                        offset = o;
                    } else {
                        return None;
                    }
                }
                return Some(offset);
            }
            _ => None,
        }
    }

    fn read_dollar(&mut self, payload: &[u8], offset: usize) -> Option<usize> {
        if let Some((len, offset)) = Self::read_len(payload, offset + 1) {
            if offset + len >= payload.len() {
                return None;
            }
            self.push(&payload[offset..offset + len]);
            return Some(offset + len + 2);
        }
        None
    }

    fn read_str(&mut self, payload: &[u8], offset: usize) -> Option<usize> {
        self.add_line();
        if let Some(end) = Self::read_line_end(payload, offset) {
            let sub_payload = &payload[offset..end];
            if payload[0] == b'-' {
                self.push_err(sub_payload);
            }
            self.push(sub_payload);
            return Some(end + 2);
        }
        None
    }

    fn add_line(&mut self) {
        if self.lines.len() > 0 {
            self.lines.push(b'\n');
            self.set_resp_mul()
        }
        self.count += 1;
    }

    fn push(&mut self, payload: &[u8]) {
        if self.lines.len() > 0 {
            self.lines.push(b' ');
        }
        self.lines.extend_from_slice(match payload.len() < MAX_LEN {
            true => payload,
            _ => &payload[0..MAX_LEN],
        });
    }

    fn push_err(&mut self, payload: &[u8]) {
        self.set_resp_err();
        if self.err_lines.len() > 0 {
            self.err_lines.push(b'\n');
        }
        self.err_lines
            .extend_from_slice(match payload.len() < MAX_LEN {
                true => payload,
                _ => &payload[0..MAX_LEN],
            });
    }

    pub fn read_len(payload: &[u8], offset: usize) -> Option<(usize, usize)> {
        if let Some(idx) = Self::read_line_end(payload, offset) {
            return match std::str::from_utf8(&payload[offset..idx]).unwrap().parse() {
                Ok(len) => Some((len, idx + 2)),
                Err(_) => None,
            };
        }
        return None;
    }

    pub fn read_line_end(payload: &[u8], offset: usize) -> Option<usize> {
        let len = payload.len();
        for i in offset..len - 1 {
            if payload[i] == b'\r' && payload[i + 1] == b'\n' {
                return Some(i);
            }
        }
        return None;
    }

    pub fn check(payload: &[u8], param: &ParseParam) -> bool {
        if !param.ebpf_type.is_raw_protocol() {
            return false;
        }
        if param.l4_protocol != IpProtocol::Tcp {
            return false;
        }
        if payload[0] != b'*' {
            return false;
        }
        if let Some((_, idx)) = Self::read_len(payload, 1) {
            return match payload[idx] {
                b'+' | b'-' | b':' | b'*' | b'$' => true,
                _ => false,
            };
        }
        false
    }
}
