// Copyright 2022-2025 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::multiple_crate_versions)]

use std::{fs::File, io::Read, path::PathBuf};

use ciborium::Value as CborValue;
use mediatype::{MediaType, Name, Value, WriteParams};
use reqwest::{Certificate, ClientBuilder};

use coserv_rs::coserv::{Coserv, CoservProfile};
use uritemplate::UriTemplate;
use url::Url;

use crate::Error;

const UNSIGNED_COSERV_MEDIA_SUBTYPE: &str = "coserv+cbor";

// TODO(paulhowardarm): Support signed queries
// const SIGNED_COSERV_MEDIA_SUBTYPE: &str = "coserv+cose";

struct ConciseProblemDetails {
    pub title: String,
    pub detail: String,
}

impl ConciseProblemDetails {
    fn from_cbor(bytes: &[u8]) -> Self {
        // Start with degenerate strings for the error title and detail.
        // Hopefully, we decode something better from the CBOR data.
        let mut title = String::from("UNKNOWN ERROR");
        let mut detail = String::from("The problem details could not be obtained from the server");
        let d: Result<CborValue, ciborium::de::Error<std::io::Error>> =
            ciborium::from_reader(bytes);
        if let Ok(CborValue::Map(map)) = d {
            for (k, v) in map {
                if let CborValue::Integer(intkey) = k {
                    match intkey.into() {
                        -1 => title = v.as_text().unwrap_or(&title).to_string(),
                        -2 => detail = v.as_text().unwrap_or(&detail).to_string(),
                        _ => {}
                    }
                }
            }
        }

        ConciseProblemDetails { title, detail }
    }
}

/// A builder for [QueryRunner] objects
pub struct QueryRunnerBuilder {
    request_response_url: Option<String>,
    root_certificate: Option<PathBuf>,
}

impl QueryRunnerBuilder {
    /// default constructor
    pub fn new() -> Self {
        Self {
            request_response_url: None,
            root_certificate: None,
        }
    }

    /// Use this method to supply the URL of the CoSERV request-response endpoint that will create
    /// new challenge-response sessions, e.g.:
    /// "https://veraison.example/endorsement-distribution/v1/coserv".
    pub fn with_request_response_url(mut self, v: String) -> QueryRunnerBuilder {
        self.request_response_url = Some(v);
        self
    }

    /// Use this method to add a custom root certificate.  For example, this can
    /// be used to connect to a server that has a self-signed certificate which
    /// is not present in (and does not need to be added to) the system's trust
    /// anchor store.
    pub fn with_root_certificate(mut self, v: PathBuf) -> QueryRunnerBuilder {
        self.root_certificate = Some(v);
        self
    }

    /// Instantiate a valid [QueryRunner] object, or fail with an error.
    pub fn build(self) -> Result<QueryRunner, Error> {
        let request_response_url_str = self.request_response_url.ok_or_else(|| {
            Error::ConfigError("missing CoSERV request-response API endpoint".to_string())
        })?;

        // Make sure the URL can be parsed
        let _url =
            Url::parse(&request_response_url_str).map_err(|e| Error::ConfigError(e.to_string()))?;

        // Make sure the URL ends with the "/{query}" template parameter as required by the spec
        if !request_response_url_str.ends_with("/{query}") {
            return Err(Error::ConfigError(format!(
                "The given CoSERV query endpoint '{0}' does not end with '/{{query}}'",
                request_response_url_str
            )));
        }

        let mut http_client_builder: ClientBuilder = reqwest::ClientBuilder::new();

        if self.root_certificate.is_some() {
            let mut buf = Vec::new();
            File::open(self.root_certificate.unwrap())?.read_to_end(&mut buf)?;
            let cert = Certificate::from_pem(&buf)?;
            http_client_builder = http_client_builder.add_root_certificate(cert);
        }

        let http_client = http_client_builder.use_rustls_tls().build()?;

        Ok(QueryRunner {
            request_response_url_template: request_response_url_str.to_string(),
            http_client,
        })
    }
}

impl Default for QueryRunnerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// This object can be used to execute one or more CoSERV queries using the
/// transactional request-response API.  Always use the [QueryRunnerBuilder] to instantiate it.
pub struct QueryRunner {
    request_response_url_template: String,
    http_client: reqwest::Client,
}

impl<'a> QueryRunner {
    /// Execute a single CoSERV query and return an unsigned result.
    ///
    /// On success, the returned [Coserv] object will contain the same query as the input,
    /// but the results will also be populated based on the data provided by the server.
    ///
    /// The semantics of this operation are as defined in the
    /// [CoSERV IETF Draft](https://www.ietf.org/archive/id/draft-ietf-rats-coserv-02.html#name-execute-query).
    ///
    /// It is the caller's responsibility to check that the server supports unsigned CoSERV output.
    /// To do this, consult the [crate::DiscoveryDocument].
    pub async fn execute_query_unsigned(&self, query: &Coserv<'a>) -> Result<Coserv<'a>, Error> {
        let coserv_b64 = query
            .to_b64_url()
            .map_err(|e| Error::DataConversionError(e.to_string()))?;

        // Instantiate the query by substituting the URL template variable
        let coserv_url = UriTemplate::new(&self.request_response_url_template)
            .set("query", coserv_b64)
            .build();

        // Construct the base media type, which is either "application/coserv+cose"
        // or "application/coserv+cbor" depending on whether the caller is requesting signed data.
        let mut media_type = MediaType::new(
            mediatype::names::APPLICATION,
            Name::new_unchecked(UNSIGNED_COSERV_MEDIA_SUBTYPE),
        );

        // Parameterise the base media type with the quoted profile string.
        let mut profile = String::new();
        profile.push('"');
        match &query.profile {
            CoservProfile::Oid(oid) => profile.push_str(&oid.to_string()),
            CoservProfile::Uri(uri) => profile.push_str(uri),
        }
        profile.push('"');

        let value = Value::new(&profile);

        if let Some(v) = value {
            media_type.set_param(Name::new_unchecked("profile"), v)
        } else {
            return Err(Error::DataConversionError(format!(
                "could not parse profile {} to CoSERV media type parameter",
                profile
            )));
        }

        // Now run the actual HTTP GET operation
        let response = self
            .http_client
            .get(coserv_url.as_str())
            .header(reqwest::header::ACCEPT, media_type.to_string())
            .send()
            .await?;

        match response.status() {
            reqwest::StatusCode::OK => {
                let response_body_bytes = response.bytes().await?;
                let coserv_out = Coserv::from_cbor(response_body_bytes.as_ref())
                    .map_err(|e| Error::DataConversionError(e.to_string()))?;
                Ok(coserv_out)
            }
            // These two are in-protocol errors. If we receive them, they should be accompanied by Concise Problem Details (RFC9290)
            // in the response body.
            reqwest::StatusCode::BAD_REQUEST | reqwest::StatusCode::NOT_ACCEPTABLE => {
                let response_body_bytes = response.bytes().await?;
                let concise_problem_details =
                    ConciseProblemDetails::from_cbor(response_body_bytes.as_ref());
                Err(Error::ApiError(format!(
                    "{0}: {1}",
                    concise_problem_details.title, concise_problem_details.detail
                )))
            }
            // Some other HTTP status code that's out-of-protocol (e.g. Internal Server Error)
            // Don't expect any CBOR error details here, just report the code as an ApiError.
            n => Err(Error::ApiError(format!("http error status {0}", n))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use coserv_rs::coserv::{ArtifactTypeChoice, ResultSetTypeChoice, ResultTypeChoice};
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn deserialize_concise_problem_details() {
        let problem_details_bytes =
            include_bytes!("../test/coserv/problem_details_bad_request.cbor");
        let problem_details = ConciseProblemDetails::from_cbor(problem_details_bytes);
        assert_eq!("Query validation failed", &problem_details.title);
        assert_eq!(
            "The query payload is not in CBOR format",
            &problem_details.detail
        );
    }

    #[async_std::test]
    async fn execute_query_unsigned_okay() {
        let query_bytes = include_bytes!("../test/coserv/example_query.cbor");
        let query = Coserv::from_cbor(query_bytes.as_slice()).unwrap();
        let query_string = query.to_b64_url().unwrap();

        let result_bytes = include_bytes!("../test/coserv/example_result.cbor");

        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(200).set_body_bytes(result_bytes);

        Mock::given(method("GET"))
            .and(path("/".to_string() + &query_string))
            .and(header_exists("Accept")) // Ideally we would fully match the header, but WireMock barfs on complex parameterised media types
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = QueryRunnerBuilder::new()
            .with_request_response_url(mock_server.uri() + "/{query}")
            .build()
            .unwrap();

        let coserv_out = cr.execute_query_unsigned(&query).await.unwrap();

        // Test some characteristics of the result
        // (This is deliberately not exhaustive, because this crate doesn't implement CoSERV deserialisation)
        assert_eq!(
            CoservProfile::Uri("tag:example.com,2025:cc-platform#1.0.0".to_string()),
            coserv_out.profile
        );
        assert_eq!(
            ArtifactTypeChoice::ReferenceValues,
            coserv_out.query.artifact_type
        );
        assert_eq!(
            ResultTypeChoice::CollectedArtifacts,
            coserv_out.query.result_type
        );

        let results = coserv_out.results.unwrap();
        assert_eq!(None, results.source_artifacts);

        let result_set = results.result_set.unwrap();
        if let ResultSetTypeChoice::ReferenceValues(rv) = result_set {
            assert_eq!(1, rv.rv_quads.len());

            let quad = &rv.rv_quads[0];
            assert_eq!(1, quad.authorities.len());
        } else {
            panic!("Wrong type of result set (not reference values).");
        }
    }

    #[async_std::test]
    async fn execute_query_not_acceptable() {
        let query_bytes = include_bytes!("../test/coserv/example_query.cbor");
        let query = Coserv::from_cbor(query_bytes.as_slice()).unwrap();
        let query_string = query.to_b64_url().unwrap();

        let result_bytes = include_bytes!("../test/coserv/problem_details_not_acceptable.cbor");

        let mock_server = MockServer::start().await;

        let response = ResponseTemplate::new(406).set_body_bytes(result_bytes);

        Mock::given(method("GET"))
            .and(path("/".to_string() + &query_string))
            .and(header_exists("Accept")) // Ideally we would fully match the header, but WireMock barfs on complex parameterised media types
            .respond_with(response)
            .mount(&mock_server)
            .await;

        let cr = QueryRunnerBuilder::new()
            .with_request_response_url(mock_server.uri() + "/{query}")
            .build()
            .unwrap();

        let e = cr
            .execute_query_unsigned(&query)
            .await
            .expect_err("Should have resulted in an error.");
        assert_eq!("API error: Content negotiation failed: The given CoSERV profile is not supported by this server", e.to_string());
    }
}
