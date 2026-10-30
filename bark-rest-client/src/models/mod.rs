pub use bark_json::cli::*;
pub use bark_json::cli::onchain::*;
pub use bark_json::exit::states::*;
pub use bark_json::exit::error::*;
pub use bark_json::movements::*;
pub use bark_json::primitives::*;
pub use bark_json::web::*;
pub use bark_rest::error::*;
pub use bark_rest::api::v1::notifications::*;

#[cfg(test)]
mod tests {
	use crate::apis::lightning_api::{GenerateInvoiceForAddressError, PayError};
	use crate::apis::wallet_api::{Bip321UriError, OffboardVtxosError,
		RefreshDelegatedError, RefreshVtxosError, SendError};
	use serde_json::json;

	#[test]
	fn generated_errors_preserve_refusal_codes_before_generic_bad_requests() {
		macro_rules! check {
			($error:ident) => {
				for code in ["decided_for_fallback", "future_refusal"] {
					let response = json!({"code": code, "message": "operation refused"});
					match serde_json::from_value::<$error>(response).unwrap() {
						$error::Status409(refusal) => {
							assert_eq!(refusal.code, code);
							assert_eq!(refusal.message, "operation refused");
						},
						other => panic!("refusal lost its typed code: {other:?}"),
					}
				}
				let response = json!({"message": "invalid request"});
				assert!(matches!(serde_json::from_value::<$error>(response).unwrap(),
					$error::Status400(error) if error.message == "invalid request"));
				for response in [json!({"code": 1, "message": "invalid code"}),
					json!({"code": null, "message": "missing code"}),
					json!({"code": "decided_for_fallback", "message": 1}),
					json!({"code": "decided_for_fallback"})] {
					assert!(!matches!(serde_json::from_value::<$error>(response),
						Ok($error::Status409(_))));
				}
			};
		}
		check!(GenerateInvoiceForAddressError);
		check!(PayError);
		check!(Bip321UriError);
		check!(OffboardVtxosError);
		check!(RefreshDelegatedError);
		check!(RefreshVtxosError);
		check!(SendError);
	}
}
