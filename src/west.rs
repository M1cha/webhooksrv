#[derive(PartialEq, Clone, Default, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(rename = "repo-path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(rename = "west-commands")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub west_commands: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import: Option<bool>,
}

#[derive(Clone, Default, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

#[derive(Clone, Default, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub name: String,
    #[serde(rename = "url-base")]
    pub url_base: String,
}

#[derive(Clone, Default, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub defaults: Defaults,
    pub remotes: Vec<Remote>,
    pub projects: Vec<Project>,
}

#[derive(Clone, Default, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct File {
    pub manifest: Manifest,
}

impl Project {
    pub fn repo_path(&self) -> &str {
        if let Some(repo_path) = &self.repo_path {
            repo_path
        } else {
            &self.name
        }
    }

    pub fn remote_name<'a>(&'a self, manifest: &'a Manifest) -> Option<&'a str> {
        if let Some(remote) = self.remote.as_deref() {
            return Some(remote);
        }

        manifest.defaults.remote.as_deref()
    }

    pub fn revision<'a>(&'a self, manifest: &'a Manifest) -> Option<&'a str> {
        if let Some(revision) = self.revision.as_deref() {
            return Some(revision);
        }

        manifest.defaults.revision.as_deref()
    }

    pub fn url(&self, manifest: &Manifest) -> Option<String> {
        if let Some(url) = self.url.as_ref() {
            return Some(url.to_string());
        }

        let remote = manifest.remote_by_name(self.remote_name(manifest)?)?;

        Some(format!("{}/{}", remote.url_base, self.repo_path()))
    }
}

impl Manifest {
    pub fn remote_by_name(&self, name: &str) -> Option<&Remote> {
        self.remotes.iter().find(|&r| r.name == name)
    }
}
