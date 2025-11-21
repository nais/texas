use crate::config::Config;
use crate::http::router;
use crate::{config, handler};
use axum::Router;
use tokio::net::TcpListener;
use tokio::signal;
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(info(
    title = "Token Exchange as a Service (Texas)",
    description = "Texas implements OAuth token fetch, exchange, and validation, so that you don't have to.",
    contact(name = "Nais", url = "https://nais.io")
))]
pub struct Server {
    router: Router,
    pub listener: TcpListener,
    pub probe_listener: Option<TcpListener>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("set up listening socket: {0}")]
    BindAddress(std::io::Error),
    #[error("describe socket local address: {0}")]
    LocalAddress(std::io::Error),
    #[error("{0}")]
    InitHandler(handler::InitError),
    #[error("invalid configuration: {0}")]
    Configuration(config::Error),
}

impl Server {
    pub async fn new_from_env() -> Result<Self, Error> {
        let cfg = Config::new_from_env().map_err(Error::Configuration)?;
        Self::new_from_config(cfg).await
    }

    pub async fn new_from_config(cfg: Config) -> Result<Self, Error> {
        let bind_address = cfg.bind_address.clone();
        let listener = TcpListener::bind(bind_address).await.map_err(Error::BindAddress)?;
        let api_address = listener.local_addr().map_err(Error::LocalAddress)?;
        log::info!("Serving API on http://{api_address:?}");
        #[cfg(feature = "openapi")]
        log::info!(
            "Swagger API documentation: http://{:?}/swagger-ui",
            api_address
        );

        let probe_listener = if let Some(addr) = cfg.probe_bind_address.as_ref() {
            let listener = TcpListener::bind(addr).await.map_err(Error::BindAddress)?;
            let probe_address = listener.local_addr().map_err(Error::LocalAddress)?;
            log::debug!("Serving probes on http://{probe_address:?}");
            Some(listener)
        } else {
            None
        };

        let state = handler::State::from_config(cfg).await.map_err(Error::InitHandler)?;

        #[cfg(not(feature = "openapi"))]
        let router = || -> Router {
            let (router, _) = router::api(state);
            router
        };
        #[cfg(feature = "openapi")]
        let router = || -> Router {
            use utoipa_swagger_ui::SwaggerUi;

            let (router, openapi) = router::api(state);
            let swagger =
                SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", openapi.clone());
            router.merge(swagger)
        };

        Ok(Self {
            router: router(),
            listener,
            probe_listener,
        })
    }

    pub async fn run(self) {
        if let Some(probe_listener) = self.probe_listener {
            let api_handler = tokio::task::spawn(async move {
                serve(self.listener, self.router).await;
            });
            let probe_handler = tokio::task::spawn(async move {
                serve(probe_listener, router::probe()).await;
            });
            let _ = tokio::try_join!(api_handler, probe_handler);
        } else {
            serve(self.listener, self.router).await;
        }

        log::debug!("Texas shut down gracefully");
    }
}

async fn serve(listener: TcpListener, router: Router) {
    // from axum::serve:
    // > Although this future resolves to io::Result<()>,
    // > it will never actually complete or return an error.
    // > Errors on the TCP socket will be handled by sleeping for a short while (currently, one second).
    //
    // from axum::serve::with_graceful_shutdown:
    // > Similarly to serve, although this future resolves to io::Result<()>, it will never error.
    // > It returns Ok(()) only after the signal future completes.
    //
    // Therefore, we can safely unwrap the result of the await.
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("axum::serve::with_graceful_shutdown() should not error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => log::debug!{"Received Ctrl+C / SIGINT"},
        () = terminate => log::debug!{"Received SIGTERM"},
    }
}
