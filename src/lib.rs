extern crate base64; // TODO(gardell): Find in crypto
extern crate crypto;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

mod jwt {

    #[derive(PartialEq, Eq, Serialize, Deserialize, Debug)]
    pub struct Header {
        pub alg: String,
        pub typ: String,
    }

    #[derive(Debug)]
    pub enum Error {
        Json(::serde_json::error::Error),
        Signature,
        Format,
    }

    type Result<T> = ::std::result::Result<T, Error>;

    fn validate_header(header: Header) -> Result<()> {
        try!(if header.alg == "HS256" { Ok(()) } else { Err(Error::Format) });
        try!(if header.typ == "JWT" { Ok(()) } else { Err(Error::Format) });
        Ok(())
    }

    fn base64_decode(message: &str) -> Result<Vec<u8>> {
        ::base64::decode(message).map_err(|_|Error::Format)
    }

    fn parse_json<T: ::serde::de::Deserialize>(v: &[u8]) -> Result<T> {
        ::serde_json::from_slice(v).map_err(|e| Error::Json(e))
    }

    pub fn parse<T: ::serde::de::Deserialize>(json: &str, key: &[u8])
            -> Result<T> {

        let mut rparts = json.rsplitn(2, |c| c == '.');
        try!(match (
            rparts.next().ok_or(Error::Format).and_then(base64_decode),
            rparts.next()) {
                (Ok(signature), Some(message)) => {
                    let hmac_equals = hmac_sha256_equals(
                        message.as_bytes(),
                        key,
                        signature.as_slice());
                    if hmac_equals { Ok(()) } else { Err(Error::Signature) }
                },
                _ => Err(Error::Format)
            });

        let mut parts = json.splitn(3, |c| c == '.');
        match (
            parts.next().ok_or(Error::Format).and_then(base64_decode),
            parts.next().ok_or(Error::Format).and_then(base64_decode)) {
                (Ok(header), Ok(payload)) => {
                    try!(parse_json(header.as_slice())
                        .and_then(validate_header));
                    parse_json(payload.as_slice())
                },
                _ => Err(Error::Format)
            }
    }

    fn hmac_sha256_equals(input: &[u8], key: &[u8], hash: &[u8]) -> bool {
        use ::crypto::mac::Mac;

        let mut hmac = ::crypto::hmac::Hmac::new(
            ::crypto::sha2::Sha256::new(),
            key
        );
        hmac.input(input);
        hmac.result().code() == hash
    }
}

#[derive(PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Payload {
    pub string: String,
    pub integer: i64,
}

#[cfg(test)]
mod tests {

    static ALG: &'static str = "Yoda";
    static TYP: &'static str = "Jedi";

    #[test]
    fn serialize_header() {
        let header = ::jwt::Header{ alg: ALG.to_string(), typ: TYP.to_string() };
        let serialized = ::serde_json::to_string(&header).unwrap();

        let deserialized = match ::serde_json::from_str(&serialized) {
            Ok(::serde_json::Value::Object(deserialized)) => deserialized,
            _ => panic!("unable to deserialize")
        };

        assert_eq!(deserialized.len(), 2);
        assert_eq!(
            deserialized.get("alg"),
            Some(&::serde_json::Value::String(ALG.to_string()))
        );
        assert_eq!(
            deserialized.get("typ"),
            Some(&::serde_json::Value::String(TYP.to_string()))
        );
    }

    #[test]
    fn deserialize_header() {
        let serialized = br#"{ "typ": "Jedi", "alg": "Yoda" }"#;

        let deserialized : ::jwt::Header =
            match ::serde_json::from_slice(serialized) {
                Ok(header) => header,
                _ => panic!("unable to deserialize")
        };

        assert_eq!(
            deserialized,
            ::jwt::Header{
                alg: ALG.to_string(),
                typ: TYP.to_string(),
            }
        );
    }

    #[test]
    fn deserialize_header_unknown_field() {
        let serialized =
            br#"{ "unknown": "value", "typ": "Jedi", "alg": "Yoda" }"#;

        let deserialized : ::jwt::Header =
            match ::serde_json::from_slice(serialized) {
                Ok(header) => header,
                _ => panic!("unable to deserialize")
        };

        assert_eq!(
            deserialized,
            ::jwt::Header{
                alg: ALG.to_string(),
                typ: TYP.to_string(),
            }
        );
    }

    #[test]
    fn deserialize_header_missing_field() {
        let serialized = br#"{ "alg": "Yoda" }"#;

        assert!(::serde_json::from_slice::<::jwt::Header>(serialized).is_err());
    }

    #[test]
    fn parse_valid() {
        let payload: ::Payload = ::jwt::parse(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdHJpbmciOiJCaWxibyBCYWdnaW5zIiwiaW50ZWdlciI6MTMzN30.hKRaWXYKNMRdxicE23jPHyH6W7mt4G491YXgf4LWHKs",
            "secret".as_bytes()
        ).unwrap();
        assert_eq!(payload.string, "Bilbo Baggins");
        assert_eq!(payload.integer, 1337);
    }
}
