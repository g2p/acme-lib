use hyper::{Body, Response};
use serde::de::DeserializeOwned;

use crate::req::req_safe_read_body;
use crate::Result;

const BASE64_CONFIG: base64::Config = base64::Config::new(base64::CharacterSet::UrlSafe, false);

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    base64::encode_config(input, BASE64_CONFIG)
}

pub(crate) async fn read_json<T: DeserializeOwned>(res: Response<Body>) -> Result<T> {
    let res_body = req_safe_read_body(res).await;
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}
