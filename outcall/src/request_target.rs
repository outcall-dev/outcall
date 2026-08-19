//! Encoding helpers for HTTP request-target components.

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

fn encode_component(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

/// Encode one dynamic path segment without allowing it to alter route structure.
pub fn path_segment(value: &str) -> String {
    encode_component(value)
}

/// Encode one dynamic query value without allowing it to add query parameters.
pub fn query_value(value: &str) -> String {
    encode_component(value)
}

#[cfg(test)]
mod tests {
    use super::{path_segment, query_value};

    #[test]
    fn path_segment_encodes_route_delimiters_and_utf8() {
        assert_eq!(
            path_segment("agent/a b?c#d%é"),
            "agent%2Fa%20b%3Fc%23d%25%C3%A9"
        );
    }

    #[test]
    fn query_value_cannot_inject_another_parameter() {
        assert_eq!(
            query_value("name&force=true=value+more"),
            "name%26force%3Dtrue%3Dvalue%2Bmore"
        );
    }
}
