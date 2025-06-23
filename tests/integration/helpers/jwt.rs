use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde_json::Value;
use std::collections::HashMap;
use texas::identity_provider::IntrospectResponse;

pub type TokenClaims = HashMap<String, Value>;

pub struct Token {
    header: jwt::Header,
    claims: TokenClaims,
}

impl Token {
    /// Matches signing key used in mock-oauth2-server
    const SIGNING_KEY: &'static str = r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#;

    fn new(claims: TokenClaims) -> Self {
        Self {
            header: jwt::Header::new(jwt::Algorithm::RS256),
            claims,
        }
    }

    pub fn sign(claims: TokenClaims) -> String {
        Self::new(claims).encode()
    }

    pub fn sign_with_kid(claims: TokenClaims, kid: &str) -> String {
        let mut token = Self::new(claims);
        token.header.kid = Some(kid.to_string());
        token.encode()
    }

    fn encode(&self) -> String {
        let key = Self::get_signing_key();
        jwt::encode(&self.header, &self.claims, &key.key.to_encoding_key()).unwrap()
    }

    fn get_signing_key() -> jwk::JsonWebKey {
        Self::SIGNING_KEY.parse().unwrap()
    }
}

pub fn has_claims(introspect_response: &IntrospectResponse) -> bool {
    !introspect_response.extra.is_empty()
}

pub fn subject(introspect_response: &IntrospectResponse) -> Option<String> {
    get_string_claim(introspect_response, "sub")
}

pub fn issuer(introspect_response: &IntrospectResponse) -> Option<String> {
    get_string_claim(introspect_response, "iss")
}

pub fn jwt_id(introspect_response: &IntrospectResponse) -> Option<String> {
    get_string_claim(introspect_response, "jti")
}

fn get_string_claim(introspect_response: &IntrospectResponse, claim: &str) -> Option<String> {
    introspect_response
        .extra
        .get(claim)
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}
