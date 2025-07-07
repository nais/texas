use serde::{Deserialize, Serialize};
use testcontainers::{ContainerAsync, GenericImage};

pub struct RuntimeParams {
    pub container: Option<ContainerAsync<GenericImage>>,
    pub host: String,
    pub port: u16,
}

impl RuntimeParams {
    /// Runs Docker from Rust, no external setup needed
    #[cfg(feature = "docker")]
    pub async fn init() -> RuntimeParams {
        use reqwest::StatusCode;
        use testcontainers::core::wait::HttpWaitStrategy;
        use testcontainers::core::{ImageExt, IntoContainerPort, WaitFor};
        use testcontainers::runners::AsyncRunner;

        fn wait_for_provider(identity_provider: &str) -> WaitFor {
            WaitFor::Http(Box::new(
                HttpWaitStrategy::new(format!(
                    "/{identity_provider}/.well-known/openid-configuration"
                ))
                .with_expected_status_code(StatusCode::OK),
            ))
        }

        let container = GenericImage::new("ghcr.io/navikt/mock-oauth2-server", "2.2.1")
            .with_exposed_port(8080.tcp())
            .with_wait_for(wait_for_provider("azuread"))
            .with_wait_for(wait_for_provider("idporten"))
            .with_wait_for(wait_for_provider("maskinporten"))
            .with_wait_for(wait_for_provider("tokenx"))
            .with_env_var("JSON_CONFIG", MockOAuthServerConfig::new().to_json())
            .start()
            .await
            .unwrap();
        let host = container.get_host().await.unwrap().to_string();
        let port = container.get_host_port_ipv4(8080).await.unwrap();
        Self {
            container: Some(container),
            host,
            port,
        }
    }

    /// Requires docker-compose up to be running.
    #[cfg(not(feature = "docker"))]
    pub async fn init() -> RuntimeParams {
        Self {
            container: None,
            host: "localhost".to_string(),
            port: 8080,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MockOAuthServerConfig {
    #[serde(rename = "tokenProvider")]
    token_provider: TokenProvider,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenProvider {
    #[serde(rename = "keyProvider")]
    key_provider: KeyProvider,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyProvider {
    #[serde(rename = "initialKeys")]
    initial_keys: String,
    algorithm: String,
}

impl MockOAuthServerConfig {
    pub fn new() -> Self {
        Self {
            token_provider: TokenProvider {
                key_provider: KeyProvider {
                    initial_keys: r#"{"p":"_LNnIjBshCrFuxtjUC2KKzg_NTVv26UZh5j12_9r5mYTxb8yW047jOYFEGvIdMkTRLGOBig6fLWzgd62lnLainzV35J6K6zr4jQfTldLondlkldMR6nQrp1KfnNUuRbKvzpNKkhl12-f1l91l0tCx3s4blztvWgdzN2xBfvWV68","kty":"RSA","q":"9MIWsbIA3WjiR_Ful5FM8NCgb6JdS2D6ySHVepoNI-iAPilcltF_J2orjfLqAxeztTskPi45wtF_-eV4GIYSzvMo-gFiXLMrvEa7WaWizMi_7Bu9tEk3m_f3IDLN9lwULYoebkDbiXx6GOiuj0VkuKz8ckYFNKLCMP9QRLFff-0","d":"J6UX848X8tNz-09PFvcFDUVqak32GXzoPjnuDjBsxNUvG7LxenLmM_i8tvYl0EW9Ztn4AiCqJUoHw5cX3jz_mSqGl7ciaDedpKm_AetcZwHiEuT1EpSKRPMmOMQSqcJqXrdbbWB8gdUrnTKZIlJCfj7yqgT16ypC43TnwjA0UwxhG5pHaYjKI3pPdoHg2BzA-iubHjVn15Sz7-pnjBmeGDbEFa7ADY-1yPHCmqqvPKTNhoCNW6RpG34Id9hXslPa3X-7pAhJrDBd0_NPlktSA2rUkifYiZURhHR5ijhe0v3uw6kYP8f_foVm_C8O1ExkxXh9Dg8KDZ89dbsSOtBc0Q","e":"AQAB","use":"sig","kid":"l7C_WJgbZ_6e59vPrFETAehX7Dsp7fIyvSV4XhotsGs","qi":"cQFN5q5WhYkzgd1RS0rGqvpX1AkmZMrLv2MW04gSfu0dDwpbsSAu8EUCQW9oA4pr6V7R9CBSu9kdN2iY5SR-hZvEad5nDKPV1F3TMQYv5KpRiS_0XhfV5PcolUJVO_4p3h8d-mo2hh1Sw2fairAKOzvnwJCQ6DFkiY7H1cqwA54","dp":"YTql9AGtvyy158gh7jeXcgmySEbHQzvDFulDr-IXIg8kjHGEbp0rTIs0Z50RA95aC5RFkRjpaBKBfvaySjDm5WIi6GLzntpp6B8l7H6qG1jVO_la4Df2kzjx8LVvY8fhOrKz_hDdHodUeKdCF3RdvWMr00ruLnJhBPJHqoW7cwE","alg":"RS256","dq":"IZA4AngRbEtEtG7kJn6zWVaSmZxfRMXwvgIYvy4-3Qy2AVA0tS3XTPVfMaD8_B2U9CY_CxPVseR-sysHc_12uNBZbycfcOzU84WTjXCMSZ7BysPnGMDtkkLHra-p1L29upz1HVNhh5H9QEswHM98R2LZX2ZAsn4bORLZ1AGqweU","n":"8ZqUp5Cs90XpNn8tJBdUUxdGH4bjqKjFj8lyB3x50RpTuECuwzX1NpVqyFENDiEtMja5fdmJl6SErjnhj6kbhcmfmFibANuG-0WlV5yMysdSbocd75C1JQbiPdpHdXrijmVFMfDnoZTQ-ErNsqqngTNkn5SXBcPenli6Cf9MTSchZuh_qFj_B7Fp3CWKehTiyBcLlNOIjYsXX8WQjZkWKGpQ23AWjZulngWRektLcRWuEKTWaRBtbAr3XAfSmcqTICrebaD3IMWKHDtvzHAt_pt4wnZ06clgeO2Wbc980usnpsF7g8k9p81RcbS4JEZmuuA9NCmOmbyADXwgA9_-Aw"}"#.to_string(),
                    algorithm: "RS256".to_string(),
                },
            },
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap().to_string()
    }
}
