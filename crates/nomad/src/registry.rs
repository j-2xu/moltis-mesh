//! Container registry client for checking image existence.
//!
//! Used to verify that sandbox images are available in a registry before
//! submitting Nomad jobs (since Nomad cannot build images locally).

use crate::error::{NomadError, Result};

/// Check if an image exists in a container registry via the v2 manifest API.
///
/// Sends a HEAD request to `<registry>/v2/<name>/manifests/<tag>`.
/// Returns `true` if the image exists (200), `false` if not (404).
#[cfg_attr(feature = "tracing", tracing::instrument)]
pub async fn image_exists(registry: &str, image: &str) -> Result<bool> {
    let (name, tag) = parse_image_ref(image);
    let url = format!(
        "{}/v2/{}/manifests/{}",
        registry.trim_end_matches('/'),
        name,
        tag
    );

    let client = reqwest::Client::new();
    let resp = client
        .head(&url)
        .header(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .send()
        .await
        .map_err(|e| NomadError::Config(format!("registry check failed: {e}")))?;

    match resp.status().as_u16() {
        200 => Ok(true),
        404 => Ok(false),
        status => Err(NomadError::Http {
            status,
            message: format!("registry returned unexpected status for {image}"),
        }),
    }
}

/// Parse an image reference into (name, tag).
///
/// Examples:
/// - `"ubuntu:22.04"` → `("ubuntu", "22.04")`
/// - `"myregistry.com/myimage"` → `("myregistry.com/myimage", "latest")`
/// - `"myimage:v1"` → `("myimage", "v1")`
fn parse_image_ref(image: &str) -> (&str, &str) {
    // Handle images with a digest (sha256).
    if let Some((name, _digest)) = image.split_once('@') {
        return (name, "latest");
    }
    // Handle tag after last colon (but not in registry host:port).
    if let Some((name, tag)) = image.rsplit_once(':') {
        // If the colon is before a slash, it's a port, not a tag.
        if !tag.contains('/') {
            return (name, tag);
        }
    }
    (image, "latest")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_image() {
        assert_eq!(parse_image_ref("ubuntu:22.04"), ("ubuntu", "22.04"));
    }

    #[test]
    fn parse_image_no_tag() {
        assert_eq!(parse_image_ref("alpine"), ("alpine", "latest"));
    }

    #[test]
    fn parse_image_with_registry() {
        assert_eq!(
            parse_image_ref("registry.example.com/myimage:v1"),
            ("registry.example.com/myimage", "v1")
        );
    }

    #[test]
    fn parse_image_with_digest() {
        assert_eq!(
            parse_image_ref("ubuntu@sha256:abc123"),
            ("ubuntu", "latest")
        );
    }

    #[tokio::test]
    async fn image_exists_returns_true_on_200() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("HEAD", "/v2/ubuntu/manifests/22.04")
            .with_status(200)
            .create_async()
            .await;

        let result = image_exists(&server.url(), "ubuntu:22.04").await.unwrap();
        assert!(result);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn image_exists_returns_false_on_404() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("HEAD", "/v2/nonexistent/manifests/latest")
            .with_status(404)
            .create_async()
            .await;

        let result = image_exists(&server.url(), "nonexistent").await.unwrap();
        assert!(!result);
        mock.assert_async().await;
    }
}
