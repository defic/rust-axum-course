use crate::ctx::Ctx;
use crate::model::ModelController;
use crate::web::AUTH_TOKEN;
use crate::{Error, Result};
use async_trait::async_trait;
use axum::extract::{FromRequestParts, State};
use axum::http::request::Parts;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use lazy_regex::regex_captures;
use tower_cookies::{Cookie, Cookies};

pub async fn mw_ctx_resolver<B>(
	_mc: State<ModelController>,
	cookies: Cookies,
	mut req: Request<B>,
	next: Next<B>,
) -> Result<Response> {
	println!("->> {:<12} - mw_ctx_resolver", "MIDDLEWARE");

	let auth_token = cookies.get(AUTH_TOKEN).map(|c| c.value().to_string());
	let Some(auth_token) = auth_token else {
		return Err(Error::AuthFailNoAuthTokenCookie);
	};
	let (user_id, _exp, _sign) = parse_token(auth_token).map_err(|error| {
		cookies.remove(Cookie::named(AUTH_TOKEN));
		error
	})?;
	
	let ctx = Ctx::new(user_id);
	req.extensions_mut().insert(ctx.clone());

	// add ctx to response so it can be captured by main_req_response_mapper
	let mut res = next.run(req).await;
	res.extensions_mut().insert(ctx);
	Ok(res)
}

/// Parse a token of format `user-[user-id].[expiration].[signature]`
/// Returns (user_id, expiration, signature)
fn parse_token(token: String) -> Result<(u64, String, String)> {
	let (_whole, user_id, exp, sign) = regex_captures!(
		r#"^user-(\d+)\.(.+)\.(.+)"#, // a literal regex
		&token
	)
	.ok_or(Error::AuthFailTokenWrongFormat)?;

	let user_id: u64 = user_id
		.parse()
		.map_err(|_| Error::AuthFailTokenWrongFormat)?;

	Ok((user_id, exp.to_string(), sign.to_string()))
}
