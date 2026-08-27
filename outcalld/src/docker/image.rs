use anyhow::{Context, Result};
use bollard::image::CreateImageOptions;
use futures::StreamExt;
use outcall_api::ImagePullResult;
use tracing::info;

use super::operation::{self, IMAGE_PULL_STALL_TIMEOUT, IMAGE_PULL_TOTAL_TIMEOUT};
use super::DockerManager;

impl DockerManager {
    pub async fn pull_image(&self, image: &str) -> Result<ImagePullResult> {
        let docker = self.docker.as_ref().context("Docker manager unavailable")?;
        let (from_image, tag) = split_image_reference(image)?;
        let already_present = match operation::run(
            format!("inspect image {image}"),
            docker.inspect_image(image),
        )
        .await
        {
            Ok(_) => true,
            Err(error) if error.status_code() == Some(404) => false,
            Err(error) => return Err(error.into()),
        };
        let mut stream = docker.create_image(
            Some(CreateImageOptions {
                from_image,
                tag,
                ..Default::default()
            }),
            None,
            None,
        );
        tokio::time::timeout(IMAGE_PULL_TOTAL_TIMEOUT, async {
            loop {
                let item = operation::run_for(
                    format!("pull image {image} progress"),
                    IMAGE_PULL_STALL_TIMEOUT,
                    async {
                        match stream.next().await {
                            Some(result) => result.map(Some),
                            None => Ok(None),
                        }
                    },
                )
                .await?;
                if item.is_none() {
                    return Ok::<_, super::operation::DockerOperationError>(());
                }
            }
        })
        .await
        .with_context(|| {
            format!(
                "image pull exceeded total timeout of {IMAGE_PULL_TOTAL_TIMEOUT:?} for \"{image}\""
            )
        })??;

        operation::run(
            format!("verify pulled image {image}"),
            docker.inspect_image(image),
        )
        .await?;

        info!(%image, "image pull complete");
        Ok(ImagePullResult {
            image: image.to_string(),
            pulled: !already_present,
        })
    }
}

fn split_image_reference(image: &str) -> Result<(&str, &str)> {
    let image = image.trim();
    if image.is_empty() {
        anyhow::bail!("image reference must not be empty");
    }
    if image.contains(char::is_whitespace) {
        anyhow::bail!("image reference must not contain whitespace");
    }
    if image.contains('@') {
        return Ok((image, ""));
    }

    let last_slash = image.rfind('/');
    let last_colon = image.rfind(':');
    if last_colon.is_some_and(|colon| last_slash.is_none_or(|slash| colon > slash)) {
        let colon = last_colon.unwrap_or_default();
        let (name, tag) = image.split_at(colon);
        let tag = &tag[1..];
        if name.is_empty() || tag.is_empty() {
            anyhow::bail!("invalid tagged image reference {image:?}");
        }
        Ok((name, tag))
    } else {
        Ok((image, "latest"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_tags_without_confusing_registry_ports() {
        assert_eq!(
            split_image_reference("ubuntu").unwrap(),
            ("ubuntu", "latest")
        );
        assert_eq!(
            split_image_reference("ghcr.io/outcall-dev/agent:v1").unwrap(),
            ("ghcr.io/outcall-dev/agent", "v1")
        );
        assert_eq!(
            split_image_reference("localhost:5000/team/agent").unwrap(),
            ("localhost:5000/team/agent", "latest")
        );
        assert_eq!(
            split_image_reference("localhost:5000/team/agent:dev").unwrap(),
            ("localhost:5000/team/agent", "dev")
        );
    }

    #[test]
    fn preserves_digest_references() {
        let reference = "ghcr.io/outcall-dev/agent@sha256:abc123";
        assert_eq!(split_image_reference(reference).unwrap(), (reference, ""));
    }

    #[test]
    fn rejects_empty_or_malformed_references() {
        for image in ["", " ", "ubuntu:", "bad image"] {
            assert!(split_image_reference(image).is_err(), "{image:?}");
        }
    }
}
