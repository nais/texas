use crate::helpers::{config, docker};
use log::info;
use texas::config::Config;
use texas::http::server::Server;

pub struct TestServer {
    server: Server,
    cfg: Config,
    docker: Option<docker::RuntimeParams>,
}

impl TestServer {
    pub async fn new() -> Self {
        let docker = docker::RuntimeParams::init().await;

        match docker.container {
            None => {
                info!("Expecting mock-oauth2-server natively in docker-compose on localhost:8080")
            }
            Some(_) => info!(
                "Running mock-oauth2-server on {}:{}",
                docker.host, docker.port,
            ),
        }

        // Set up Texas
        let cfg = config::mock(docker.host.clone(), docker.port);
        let server = Server::new_from_config(cfg.clone()).await.unwrap();

        Self {
            server,
            cfg,
            docker: Some(docker),
        }
    }

    pub async fn new_no_providers() -> Self {
        // Set up Texas
        let cfg = config::mock_no_providers();
        let server = Server::new_from_config(cfg.clone()).await.unwrap();

        Self {
            server,
            cfg,
            docker: None,
        }
    }

    pub fn address(&self) -> String {
        self.server.listener.local_addr().map(|addr| addr.to_string()).unwrap()
    }

    pub fn probe_address(&self) -> Option<String> {
        self.server.probe_listener.as_ref()?.local_addr().map(|addr| addr.to_string()).ok()
    }

    pub fn identity_provider_address(&self) -> String {
        if let Some(docker) = &self.docker {
            format!("{}:{}", docker.host, docker.port)
        } else {
            "localhost:8080".to_string()
        }
    }

    pub fn azure_issuer(&self) -> String {
        self.cfg.entra_id.clone().unwrap().issuer
    }

    pub fn azure_client_id(&self) -> String {
        self.cfg.entra_id.clone().unwrap().client_id
    }

    pub fn idporten_issuer(&self) -> String {
        self.cfg.idporten.clone().unwrap().issuer
    }

    pub fn maskinporten_issuer(&self) -> String {
        self.cfg.maskinporten.clone().unwrap().issuer
    }

    pub fn token_x_issuer(&self) -> String {
        self.cfg.token_x.clone().unwrap().issuer
    }

    pub fn token_x_client_id(&self) -> String {
        self.cfg.token_x.clone().unwrap().client_id
    }

    pub async fn run(self) {
        self.server.run().await;
    }
}
