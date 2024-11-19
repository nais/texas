use crate::config::Error::{MissingEnv, ParseBool};
use log::info;
use serde::Serialize;
use std::str::ParseBoolError;
use thiserror::Error;

#[derive(Serialize, Debug, Clone)]
pub struct Config {
    pub bind_address: String,
    pub maskinporten: Option<Provider>,
    pub azure_ad: Option<Provider>,
    pub token_x: Option<Provider>,
    pub idporten: Option<Provider>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Provider {
    pub client_id: String,
    pub client_jwk: Option<String>,
    pub jwks_uri: String,
    pub issuer: String,
    pub token_endpoint: Option<String>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("missing required environment variable '{0}'")]
    MissingEnv(String),

    #[error("parse boolean option '{0}': {1}")]
    ParseBool(String, ParseBoolError),
}

impl Provider {
    fn is_provider_enabled(prefix: &str) -> Result<bool, Error> {
        let key = format!("{prefix}_ENABLED");
        let Ok(envvar) = std::env::var(&key) else { return Ok(false) };

        envvar.parse().map_err(|err| ParseBool(key, err))
    }

    fn new_from_env_with_prefix(prefix: &str) -> Result<Option<Self>, Error> {
        if !Self::is_provider_enabled(prefix)? {
            return Ok(None);
        }
        Ok(Some(Self {
            client_id: Self::must_read_env(&format!("{prefix}_CLIENT_ID"))?,
            client_jwk: Some(Self::must_read_env(&format!("{prefix}_CLIENT_JWK"))?),
            jwks_uri: Self::must_read_env(&format!("{prefix}_JWKS_URI"))?,
            issuer: Self::must_read_env(&format!("{prefix}_ISSUER"))?,
            token_endpoint: Some(Self::must_read_env(&format!("{prefix}_TOKEN_ENDPOINT"))?),
        }))
    }

    fn new_from_azure_env() -> Result<Option<Self>, Error> {
        if !Self::is_provider_enabled("AZURE")? {
            return Ok(None);
        }
        Ok(Some(Self {
            client_id: Self::must_read_env("AZURE_APP_CLIENT_ID")?,
            client_jwk: Some(Self::must_read_env("AZURE_APP_JWK")?),
            jwks_uri: Self::must_read_env("AZURE_OPENID_CONFIG_JWKS_URI")?,
            issuer: Self::must_read_env("AZURE_OPENID_CONFIG_ISSUER")?,
            token_endpoint: Some(Self::must_read_env("AZURE_OPENID_CONFIG_TOKEN_ENDPOINT")?),
        }))
    }

    fn new_from_idporten_env() -> Result<Option<Self>, Error> {
        if !Self::is_provider_enabled("IDPORTEN")? {
            return Ok(None);
        }
        Ok(Some(Self {
            client_id: Self::must_read_env("IDPORTEN_AUDIENCE")?,
            client_jwk: None,
            jwks_uri: Self::must_read_env("IDPORTEN_JWKS_URI")?,
            issuer: Self::must_read_env("IDPORTEN_ISSUER")?,
            token_endpoint: None,
        }))
    }

    fn must_read_env(env: &str) -> Result<String, Error> {
        std::env::var(env).map_err(|_| MissingEnv(env.to_string()))
    }
}

pub fn print_texas_logo() {
    info!(r#"      ____"#);
    info!(r#"           !"#);
    info!(r#"     !     !"#);
    info!(r#"     !      `-  _ _    _ "#);
    info!(r#"     |              ```  !      _"#);
    info!(r#"_____!                   !     | |"#);
    info!(r#"\,                        \    | |_ _____  ____ _ ___"#);
    info!(r#"  l    _                  ;    | __/ _ \ \/ / _` / __|"#);
    info!(r#"   \ _/  \.              /     | ||  __/>  < (_| \__ \"#);
    info!(r#"           \           .’       \__\___/_/\_\__,_|___/"#);
    info!(r#"            .       ./’"#);
    info!(r#"             `.    ,"#);
    info!(r#"               \   ;"#);
    info!(r#"                 ``’"#);
}

impl Config {
    pub fn new_from_env() -> Result<Self, Error> {
        Ok(Self {
            bind_address: std::env::var("BIND_ADDRESS").unwrap_or("127.0.0.1:3000".to_string()),
            azure_ad: Provider::new_from_azure_env()?,
            maskinporten: Provider::new_from_env_with_prefix("MASKINPORTEN")?,
            token_x: Provider::new_from_env_with_prefix("TOKEN_X")?,
            idporten: Provider::new_from_idporten_env()?,
        })
    }
}

#[cfg(test)]
impl Config {
    pub fn mock(host: String, port: u16) -> Self {
        let url_base = format!("http://{host}:{port}");
        Self {
            bind_address: "127.0.0.1:0".to_string(),
            maskinporten: Some(Provider {
                client_id: "client-id".to_string(),
                client_jwk: Some(r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#.to_string()),
                jwks_uri: format!("{url_base}/maskinporten/jwks"),
                issuer: format!("{url_base}/maskinporten"),
                token_endpoint: Some(format!("{url_base}/maskinporten/token")),
            }),
            azure_ad: Some(Provider {
                client_id: "client-id".to_string(),
                client_jwk: Some(r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#.to_string()),
                jwks_uri: format!("{url_base}/azuread/jwks"),
                issuer: format!("{url_base}/azuread"),
                token_endpoint: Some(format!("{url_base}/azuread/token")),
            }),
            token_x: Some( Provider {
                client_id: "client-id".to_string(),
                client_jwk: Some(r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#.to_string()),
                jwks_uri: format!("{url_base}/tokenx/jwks"),
                issuer: format!("{url_base}/tokenx"),
                token_endpoint: Some(format!("{url_base}/tokenx/token")),
            }),
            idporten: Some( Provider {
                client_id: "default".to_string(), // expected audience for tokens returned by mock-oauth2-server
                client_jwk: None,
                jwks_uri: format!("{url_base}/idporten/jwks"),
                issuer: format!("{url_base}/idporten"),
                token_endpoint: None,
            }),
        }
    }
}
