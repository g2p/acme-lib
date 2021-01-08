use crate::api::ApiProblem;

use hyper::body::HttpBody;
use hyper::client::HttpConnector;
use hyper::header::HeaderValue;
use hyper::{Body, Client, Request, Response};
use hyper_rustls::HttpsConnector;
use hyper_timeout::TimeoutConnector;
use once_cell::sync::Lazy;
use std::time::Duration;

// Note: currently using 5s timeouts, previous ACME used 30s, shorter is better until proven otherwise
static HTTP_CLIENT: Lazy<Client<TimeoutConnector<HttpsConnector<HttpConnector>>>> =
    Lazy::new(|| {
        let https = HttpsConnector::with_webpki_roots();
        let mut connector = TimeoutConnector::new(https);
        connector.set_connect_timeout(Some(Duration::from_secs(5)));
        connector.set_read_timeout(Some(Duration::from_secs(5)));
        connector.set_write_timeout(Some(Duration::from_secs(5)));
        Client::builder().build::<_, Body>(connector)
    });

static PROBLEM_CONTENT_TYPE: Lazy<HeaderValue> =
    Lazy::new(|| HeaderValue::from_static("application/problem+json"));

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

pub(crate) async fn req_get(url: &str) -> hyper::Result<Response<Body>> {
    let req = Request::get(url).body(Body::empty()).unwrap();

    trace!("{:?}", req);
    HTTP_CLIENT.request(req).await
}

pub(crate) async fn req_head(url: &str) -> hyper::Result<Response<Body>> {
    let req = Request::head(url).body(Body::empty()).unwrap();
    trace!("{:?}", req);
    HTTP_CLIENT.request(req).await
}

pub(crate) async fn req_post(url: &str, body: String) -> hyper::Result<Response<Body>> {
    let req = Request::post(url)
        .header("content-type", "application/jose+json")
        .body(body.into())
        .unwrap();
    trace!("{:?}", req);
    HTTP_CLIENT.request(req).await
}

pub(crate) async fn req_handle_error(res: Response<Body>) -> ReqResult<Response<Body>> {
    let status = res.status();

    if status.is_success() {
        Ok(res)
    } else {
        let problem = if res.headers().get("content-type") == Some(&PROBLEM_CONTENT_TYPE) {
            // if we were sent a problem+json, deserialize it
            let body = req_safe_read_body(res).await;
            serde_json::from_str(&body).unwrap_or_else(|e| ApiProblem {
                _type: "problemJsonFail".into(),
                detail: Some(format!(
                    "Failed to deserialize application/problem+json ({}) body: {}",
                    e.to_string(),
                    body
                )),
                subproblems: None,
            })
        } else {
            // some other problem
            let body = req_safe_read_body(res).await;
            ApiProblem {
                _type: "httpReqError".into(),
                detail: Some(format!("{} body: {}", status, body)),
                subproblems: None,
            }
        };
        Err(problem)
    }
}

pub(crate) fn req_expect_header(res: &Response<Body>, name: &str) -> ReqResult<String> {
    if let Some(val) = res.headers().get(name) {
        if let Ok(val) = val.to_str() {
            Ok(val.to_owned())
        } else {
            Err(ApiProblem {
                _type: format!("Missing header: {}", name),
                detail: None,
                subproblems: None,
            })
        }
    } else {
        Err(ApiProblem {
            _type: format!("Missing header: {}", name),
            detail: None,
            subproblems: None,
        })
    }
}

pub(crate) async fn req_safe_read_body(res: Response<Body>) -> String {
    let mut body_str = String::new();
    let mut body = res.into_body();
    // letsencrypt sometimes closes the TLS abruptly causing io error
    // even though we did capture the body.
    while let Some(chunk) = body.data().await {
        body_str.push_str(std::str::from_utf8(&chunk.unwrap()).unwrap());
    }
    body_str
}
