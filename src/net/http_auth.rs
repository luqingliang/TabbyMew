const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn basic_value(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64_encode(format!("{username}:{password}").as_bytes())
    )
}

pub fn matches_basic_value(value: &str, username: &str, password: &str) -> bool {
    let Some((scheme, token)) = value.trim().split_once(' ') else {
        return false;
    };
    let expected = basic_value(username, password);
    let Some((_, expected_token)) = expected.split_once(' ') else {
        return false;
    };
    scheme.eq_ignore_ascii_case("basic") && token == expected_token
}

fn base64_encode(input: &[u8]) -> String {
    let mut encoded = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | b2 as u32;

        encoded.push(BASE64_TABLE[((n >> 18) & 0x3f) as usize] as char);
        encoded.push(BASE64_TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            encoded.push(BASE64_TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
        if chunk.len() > 2 {
            encoded.push(BASE64_TABLE[(n & 0x3f) as usize] as char);
        } else {
            encoded.push('=');
        }
    }

    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_matches_basic_auth_value() {
        assert_eq!(
            basic_value("user", "example-password"),
            "Basic dXNlcjpleGFtcGxlLXBhc3N3b3Jk"
        );
        assert!(matches_basic_value(
            "basic dXNlcjpleGFtcGxlLXBhc3N3b3Jk",
            "user",
            "example-password"
        ));
    }
}
