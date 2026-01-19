use jsonwebkey as jwk;
use jsonwebtoken as jwt;
use serde_json::Value;
use std::collections::HashMap;
use texas::oauth::identity_provider::{AuthorizationDetails, IntrospectResponse};

/// Matches signing key used in mock-oauth2-server
const SIGNING_KEY: &str = r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#;

pub type TokenClaims = HashMap<String, Value>;

pub struct Token {
    header: jwt::Header,
    claims: TokenClaims,
    signing_key: jwt::EncodingKey,
}

impl Token {
    fn new(claims: TokenClaims) -> Self {
        Self {
            header: jwt::Header::new(jwt::Algorithm::RS256),
            claims,
            signing_key: SIGNING_KEY.parse::<jwk::JsonWebKey>().unwrap().key.to_encoding_key(),
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
        jwt::encode(&self.header, &self.claims, &self.signing_key).unwrap()
    }
}

pub trait IntrospectClaims {
    fn has_claims(&self) -> bool;
    fn get_claim(&self, claim: &str) -> Option<&Value>;

    fn get_string_claim(&self, claim: &str) -> String {
        self.get_claim(claim)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or("".to_string())
    }
    fn get_authorization_details(&self) -> AuthorizationDetails {
        self.get_claim("authorization_details")
            .and_then(|v| {
                serde_json::from_value(v.clone())
                    .inspect_err(|e| {
                        tracing::error!("Failed to parse authorization_details: {}", e)
                    })
                    .ok()
            })
            .unwrap_or(AuthorizationDetails::from(vec![]))
    }
    fn subject(&self) -> String {
        self.get_string_claim("sub")
    }
    fn issuer(&self) -> String {
        self.get_string_claim("iss")
    }
    fn jwt_id(&self) -> String {
        self.get_string_claim("jti")
    }
}

impl IntrospectClaims for IntrospectResponse {
    fn has_claims(&self) -> bool {
        !self.extra.is_empty()
    }
    fn get_claim(&self, claim: &str) -> Option<&Value> {
        self.extra.get(claim)
    }
}
