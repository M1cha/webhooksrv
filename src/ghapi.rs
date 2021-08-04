#[derive(Debug, serde::Serialize)]
pub struct Claims {
    pub iat: usize,
    pub exp: usize,
    pub iss: usize,
}

#[derive(Debug, serde::Deserialize)]
pub struct AccessTokens {
    pub token: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct Branch {
    pub r#ref: String,
    pub sha: String,
    pub repo: Repository,
}

#[derive(Debug, serde::Deserialize)]
pub struct PullRequest {
    pub title: String,
    pub body: String,
    pub head: Branch,
    pub base: Branch,
    pub state: String,
}

#[derive(Clone, Debug, serde::Deserialize)]
pub struct Repository {
    pub full_name: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct Installation {
    pub id: u64,
}

#[derive(Debug, serde::Deserialize)]
pub enum PullRequestAction {
    #[serde(rename = "closed")]
    Closed,
    #[serde(rename = "edited")]
    Edited,
    #[serde(rename = "opened")]
    Opened,
    #[serde(rename = "reopened")]
    Reopened,
    #[serde(rename = "synchronize")]
    Synchronize,
}

#[derive(Debug, serde::Deserialize)]
pub struct PullRequestEvent {
    pub action: PullRequestAction,
    pub number: u64,
    pub pull_request: PullRequest,
    pub repository: Repository,
    pub installation: Installation,
}

#[derive(Debug, serde::Deserialize)]
pub enum Event {
    PullRequest(PullRequestEvent),
}
