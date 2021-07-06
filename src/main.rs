use actix_web::{error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use hmac::{Mac, NewMac};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::convert::TryInto;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;

mod ghapi;
mod west;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

static DEFAULT_BRANCH: &str = "refs/heads/main";

#[derive(Debug, serde::Deserialize)]
struct Config {
    /// this can be used to verify the signature of GitHub webhook events
    webhook_secret: String,
    /// secret for accessing the status API
    api_token: String,
    /// installation id for the status API, TODO: encode this in the token
    api_installation_id: u64,
    /// repo with the workflow that gets started on webhook events
    repository: String,
    /// SSL key
    key: String,
    /// SSL cert
    cert: String,
    /// ID of this GitHub App
    jwt_iss: usize,
    /// Path to PEM with the private RSA key of this GitHub App
    jwt_key: String,
    /// repos to include. This gets passed to `startswith`
    repos_include: Vec<String>,
    /// repos to exclude. This has to be a full match and comes after repos_include
    repos_exclude: Vec<String>,
    /// path where we build the repo contents
    workdir: std::path::PathBuf,
}

trait ExitStatusCheck {
    fn check(&self) -> Result<(), anyhow::Error>;
}

impl ExitStatusCheck for std::process::ExitStatus {
    fn check(&self) -> Result<(), anyhow::Error> {
        if !self.success() {
            return Err(anyhow::anyhow!("process failed: {:?}", self.code()));
        }
        Ok(())
    }
}

trait OutputLog {
    fn log(&self, log: &mut Vec<u8>) -> &Self;
}

impl OutputLog for std::process::Output {
    fn log(&self, log: &mut Vec<u8>) -> &Self {
        log.extend_from_slice(&self.stderr);

        self
    }
}

async fn get_github_token(
    config: &web::Data<Mutex<Config>>,
    jwt_key: &web::Data<Mutex<jsonwebtoken::EncodingKey>>,
    installation_id: u64,
) -> Result<String, Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = ghapi::Claims {
        iat: (now - 60).try_into().unwrap(),
        exp: (now + 60).try_into().unwrap(),
        iss: config.lock().unwrap().jwt_iss,
    };

    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &jwt_key.lock().unwrap(),
    )
    .unwrap();

    let client = actix_web::client::Client::default();
    let mut response = client
        .post(format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            installation_id
        ))
        .header("User-Agent", "actix-web")
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let access_tokens: ghapi::AccessTokens = response.json().await?;

    Ok(access_tokens.token)
}

fn check_signature(
    mac: &web::Data<Mutex<HmacSha256>>,
    req: &HttpRequest,
    bytes: &web::Bytes,
) -> Result<(), Error> {
    let sig = req
        .headers()
        .get("X-Hub-Signature-256")
        .ok_or_else(|| HttpResponse::BadRequest().body("missing signature"))?
        .as_bytes();
    if !sig.starts_with(b"sha256=") {
        return Err(HttpResponse::BadRequest()
            .body("unsupported signature type")
            .into());
    }
    let sig = hex::decode(&sig[7..])
        .map_err(|_| HttpResponse::BadRequest().body("bad signature length"))?;

    let mut mac = mac.lock().unwrap().clone();
    mac.update(&bytes);
    mac.verify(&sig)
        .map_err(|_| HttpResponse::Forbidden().body("invalid signature"))?;

    Ok(())
}

fn parse_event(req: &HttpRequest, bytes: &web::Bytes) -> Result<ghapi::Event, Error> {
    let event_type = req
        .headers()
        .get("X-GitHub-Event")
        .ok_or_else(|| HttpResponse::BadRequest().body("missing event type"))?
        .to_str()
        .map_err(|_| HttpResponse::BadRequest().body("event-type isn't a valid string"))?;

    Ok(match event_type {
        "pull_request" => {
            serde_json::from_slice::<ghapi::PullRequestEvent>(bytes).map(ghapi::Event::PullRequest)
        }
        _ => return Err(HttpResponse::Ok().body("unsupported event").into()),
    }
    .map_err(|_| HttpResponse::Ok().body("can't parse event"))?)
}

fn build_git_url(token: &str, repository: &str) -> String {
    format!("https://git:{}@github.com/{}", token, repository)
}

fn extract_comment_westyml(body: &str) -> Option<(&str, &str)> {
    lazy_static::lazy_static! {
        static ref BODY_REGEX: regex::Regex = regex::Regex::new(r"(?s)west.yml(\(ref:([a-zA-Z0-9/]+)\))?:[\r\n]+```yaml[\r\n]+(.*)[\r\n]+```").unwrap();
    }

    let captures = BODY_REGEX.captures(body)?;
    let gitref = captures
        .get(2)
        .map(|m| m.as_str())
        .unwrap_or(DEFAULT_BRANCH);
    let manifest = captures.get(3)?.as_str();

    Some((gitref, manifest))
}

fn extract_comment_westyml_parsed(body: &str) -> Result<(&str, Vec<west::Project>), anyhow::Error> {
    Ok(extract_comment_westyml(body)
        .map(|(gitref, s)| {
            // yaml doesn't like empty lists
            if s.trim() == "" {
                Ok((gitref, vec![]))
            } else {
                serde_yaml::from_str::<Vec<west::Project>>(s).map(|v| (gitref, v))
            }
        })
        .unwrap_or_else(|| Ok((DEFAULT_BRANCH, vec![])))?)
}

fn github_path_from_url(url: &str) -> Option<&str> {
    url.strip_prefix("https://github.com/")
        .map_or_else(|| url.strip_prefix("ssh://git@github.com/"), |v| Some(v))
}

async fn delete_manifest_branch(
    config: &web::Data<Mutex<Config>>,
    event: &ghapi::PullRequestEvent,
    token: &str,
) -> Result<(), Error> {
    let config = config.lock().unwrap();
    let tmp_repo = config.workdir.join("tmp");

    if tmp_repo.exists() {
        tokio::fs::remove_dir_all(&tmp_repo).await?;
    }
    tokio::fs::create_dir_all(&tmp_repo).await?;

    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("init")
        .spawn()?
        .await?
        .check()
        .map_err(|_| HttpResponse::BadRequest().body("can't init tmp git repo"))?;

    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("push")
        .arg(build_git_url(&token, &config.repository))
        .arg(format!(
            ":refs/heads/manifest/pull/{}/{}",
            event.repository.full_name, event.number
        ))
        .spawn()?
        .await?
        .check()
        .map_err(|_| HttpResponse::BadRequest().body("can't delete manifest branch"))?;

    Ok(())
}

async fn update_manifest_branch_inner(
    config: &web::Data<Mutex<Config>>,
    event: &ghapi::PullRequestEvent,
    token: &str,
    force_update: bool,
    log: &mut Vec<u8>,
) -> Result<(), anyhow::Error> {
    let config = config.lock().unwrap();
    let manifest_repo = config.workdir.join("manifest");
    let tmp_repo = config.workdir.join("tmp");

    log.extend_from_slice(b"extract manifest from PR text...\n");
    let (comment_manifestref, mut comment_westyml) =
        extract_comment_westyml_parsed(&event.pull_request.body)?;

    log.extend_from_slice(b"create workdir...\n");
    tokio::fs::create_dir_all(&config.workdir).await?;

    if !manifest_repo.exists() {
        log.extend_from_slice(b"clone manifest...\n");
        tokio::process::Command::new("git")
            .arg("clone")
            .arg("--bare")
            .arg(build_git_url(&token, &config.repository))
            .arg(&manifest_repo)
            .stderr(std::process::Stdio::piped())
            .spawn()?
            .wait_with_output()
            .await?
            .log(log)
            .status
            .check()?;
    } else {
        log.extend_from_slice(b"set manifest URL...\n");
        tokio::process::Command::new("git")
            .current_dir(&manifest_repo)
            .arg("remote")
            .arg("set-url")
            .arg("origin")
            .arg(build_git_url(&token, &config.repository))
            .stderr(std::process::Stdio::piped())
            .spawn()?
            .wait_with_output()
            .await?
            .log(log)
            .status
            .check()?;
    }

    log.extend_from_slice(b"update manifest repo...\n");
    tokio::process::Command::new("git")
        .current_dir(&manifest_repo)
        .arg("fetch")
        .arg("-f")
        .arg("origin")
        .arg(format!("{gitref}:{gitref}", gitref = comment_manifestref))
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    log.extend_from_slice(b"create tmp repo dir...\n");
    if tmp_repo.exists() {
        tokio::fs::remove_dir_all(&tmp_repo).await?;
    }
    tokio::fs::create_dir_all(&tmp_repo).await?;

    log.extend_from_slice(b"init tmp repo...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("init")
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    log.extend_from_slice(b"set git name...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("config")
        .arg("user.name")
        .arg("multirepo-actions[bot]")
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    log.extend_from_slice(b"set git email...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("config")
        .arg("user.email")
        .arg(format!(
            "{}+multirepo-actions[bot]@users.noreply.github.com",
            config.jwt_iss
        ))
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    log.extend_from_slice(b"fetch local manifest repo...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("fetch")
        .arg(&manifest_repo)
        .arg(comment_manifestref)
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    log.extend_from_slice(b"checkout manifest code...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("checkout")
        .arg("FETCH_HEAD")
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    log.extend_from_slice(b"parse main west.yml...\n");
    let westyml = std::fs::read_to_string(tmp_repo.join("west.yml"))?;
    let mut westyml: west::File = serde_yaml::from_str(&westyml)?;
    let westprojects: Vec<_> = westyml
        .manifest
        .projects
        .iter()
        .filter(|p| {
            if let Some(url) = p.url(&westyml.manifest) {
                if let Some(path) = github_path_from_url(&url) {
                    if path == event.repository.full_name {
                        return true;
                    }
                }
            }

            false
        })
        .collect();
    if westprojects.is_empty() {
        return Err(anyhow::anyhow!("main west.yml has no matching project"));
    }
    if westprojects.len() > 1 {
        return Err(anyhow::anyhow!(
            "main west.yml has {} matching projects",
            westprojects.len()
        ));
    }
    let westproject = westprojects[0];

    if comment_westyml.iter().any(|p| p.name == westproject.name) {
        return Err(anyhow::anyhow!(
            "denied overwriting PR repo using PR comment"
        ));
    }

    let mut file = tokio::fs::File::create(tmp_repo.join("PR_INFO")).await?;
    file.write_all(format!("PR_REPOSITORY={}\n", event.repository.full_name).as_bytes())
        .await?;
    file.write_all(format!("PR_NUMBER={}\n", event.number).as_bytes())
        .await?;
    file.write_all(format!("PR_HEAD_SHA={}\n", event.pull_request.head.sha).as_bytes())
        .await?;
    file.write_all(format!("PR_BASE_SHA={}\n", event.pull_request.base.sha).as_bytes())
        .await?;
    file.write_all(format!("PR_WEST_PROJECT_NAME={}\n", westproject.name).as_bytes())
        .await?;
    file.sync_all().await?;

    log.extend_from_slice(b"generate PR manifest...\n");
    let mut westproject = westproject.clone();
    westproject.revision = Some(format!("refs/pull/{}/merge", event.number));

    if !westyml.manifest.replace_project(westproject) {
        return Err(anyhow::anyhow!("can't replace PR project"));
    }

    for project in comment_westyml.drain(..) {
        if !westyml.manifest.replace_project(project) {
            return Err(anyhow::anyhow!("can't replace comment project"));
        }
    }
    drop(comment_westyml);

    let newwestfile_str = serde_yaml::to_string(&westyml)?;

    let mut file = tokio::fs::File::create(tmp_repo.join("west.yml")).await?;
    file.write_all(newwestfile_str.as_bytes()).await?;
    file.sync_all().await?;

    log.extend_from_slice(b"git-add worktree...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("add")
        .arg(".")
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    log.extend_from_slice(b"commit tmp repo...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("commit")
        .arg("-m")
        .arg(&event.pull_request.title)
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    let url = build_git_url(&token, &config.repository);
    let gitref = format!(
        "refs/heads/manifest/pull/{}/{}",
        event.repository.full_name, event.number
    );

    log.extend_from_slice(b"fetch current tmp repo...\n");
    let fetch_result = tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("fetch")
        .arg(&url)
        .arg(&gitref)
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status;

    if force_update {
        log.extend_from_slice(b"force update.\n");
    } else if fetch_result.success() {
        log.extend_from_slice(b"check if tmp code changed...\n");
        let diff_result = tokio::process::Command::new("git")
            .current_dir(&tmp_repo)
            .arg("diff")
            .arg("-s")
            .arg("--exit-code")
            .arg("FETCH_HEAD")
            .stderr(std::process::Stdio::piped())
            .spawn()?
            .wait_with_output()
            .await?
            .log(log)
            .status;
        if diff_result.success() {
            log.extend_from_slice(b"nothing has changed, don't push.\n");
            return Ok(());
        }

        log.extend_from_slice(b"something has changed, let's push.\n");
    } else {
        log.extend_from_slice(b"can't fetch. ignore and continue pushing.\n");
    }

    log.extend_from_slice(b"push tmp repo...\n");
    tokio::process::Command::new("git")
        .current_dir(&tmp_repo)
        .arg("push")
        .arg("-f")
        .arg(&url)
        .arg(format!("HEAD:{}", gitref))
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?
        .log(log)
        .status
        .check()?;

    Ok(())
}

async fn update_manifest_branch(
    config: &web::Data<Mutex<Config>>,
    event: &ghapi::PullRequestEvent,
    token: &str,
    force_update: bool,
) -> Result<(), Error> {
    if event.pull_request.state != "open" {
        return Err(HttpResponse::Ok()
            .body("ignored event (PR is not open)")
            .into());
    }
    if event.pull_request.head.repo.full_name != event.repository.full_name {
        return Err(HttpResponse::Ok()
            .body("ignored event (heas is not in event repo)")
            .into());
    }
    if event.pull_request.base.repo.full_name != event.repository.full_name {
        return Err(HttpResponse::Ok()
            .body("ignored event (base is not in event repo)")
            .into());
    }

    let mut log = vec![];
    log.extend_from_slice(b"```\n");
    let result = update_manifest_branch_inner(config, event, token, force_update, &mut log).await;
    log.extend_from_slice(b"```\n");

    let request = serde_json::json!({
        "head_sha": event.pull_request.head.sha,
        "name": "Generate Manifest Branch",
        "status": "completed",
        "conclusion": if result.is_ok() { "success" } else { "failure" },
        "output": {
            "title": "Sync Log",
            "summary": result.map_or_else(|e| format!("Error:\n```\n{:?}\n```\n", e), |_| "Successful".to_string()),
            "text": String::from_utf8_lossy(&log),
        }
    });
    let client = actix_web::client::Client::default();
    let mut response = client
        .post(format!(
            "https://api.github.com/repos/{}/check-runs",
            event.repository.full_name
        ))
        .header("User-Agent", "actix-web")
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("token {}", token))
        .send_json(&request)
        .await?;
    let body = response.body().await?;

    Err(HttpResponse::build(response.status()).body(body).into())
}

async fn handle_pull_request_event(
    config: &web::Data<Mutex<Config>>,
    jwt_key: &web::Data<Mutex<jsonwebtoken::EncodingKey>>,
    event: &ghapi::PullRequestEvent,
) -> Result<(), Error> {
    let mut found = false;
    for repo_prefix in &config.lock().unwrap().repos_include {
        if event.repository.full_name.starts_with(repo_prefix) {
            found = true;
        }
    }
    if !found {
        return Err(HttpResponse::Ok()
            .body("ignored push event (no include)")
            .into());
    }

    for repo_name in &config.lock().unwrap().repos_exclude {
        if &event.repository.full_name == repo_name {
            return Err(HttpResponse::Ok()
                .body("ignored push event (exclude)")
                .into());
        }
    }

    let token = get_github_token(config, jwt_key, event.installation.id).await?;

    match &event.action {
        ghapi::PullRequestAction::Closed => delete_manifest_branch(config, &event, &token).await?,
        ghapi::PullRequestAction::Edited
        | ghapi::PullRequestAction::Opened
        | ghapi::PullRequestAction::Reopened => {
            update_manifest_branch(config, &event, &token, false).await?;
        }
        ghapi::PullRequestAction::Synchronize => {
            // make sure a new workflow gets started
            update_manifest_branch(config, &event, &token, true).await?;
        }
    };

    Ok(())
}

async fn index(
    config: web::Data<Mutex<Config>>,
    jwt_key: web::Data<Mutex<jsonwebtoken::EncodingKey>>,
    mac: web::Data<Mutex<HmacSha256>>,
    req: HttpRequest,
    bytes: web::Bytes,
) -> Result<HttpResponse, Error> {
    check_signature(&mac, &req, &bytes)?;
    let event = parse_event(&req, &bytes)?;

    match &event {
        ghapi::Event::PullRequest(event) => {
            handle_pull_request_event(&config, &jwt_key, event).await?
        }
    }

    Ok(HttpResponse::Ok().finish())
}

fn check_api_token(config: &web::Data<Mutex<Config>>, req: &HttpRequest) -> Result<(), Error> {
    let token = req
        .headers()
        .get("X-Api-Token")
        .ok_or_else(|| HttpResponse::BadRequest().body("missing api token"))?;
    if token != config.lock().unwrap().api_token.as_bytes() {
        return Err(HttpResponse::Forbidden().body("wrong api token").into());
    }

    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct StatusParams {
    head_sha: String,
    repository: String,
    conclusion: String,
    run_id: String,
}

async fn status(
    config: web::Data<Mutex<Config>>,
    jwt_key: web::Data<Mutex<jsonwebtoken::EncodingKey>>,
    req: HttpRequest,
    status_params: web::Json<StatusParams>,
) -> Result<HttpResponse, Error> {
    check_api_token(&config, &req)?;

    if !status_params
        .repository
        .chars()
        .all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_')
    {
        return Ok(HttpResponse::BadRequest().body("unsupported characters in repository"));
    }

    let installation_id = config.lock().unwrap().api_installation_id;
    let token = get_github_token(&config, &jwt_key, installation_id).await?;

    let details_url = format!(
        "https://github.com/{}/actions/runs/{}'",
        config.lock().unwrap().repository,
        status_params.run_id
    );
    let summary = format!(
        "[GitHub Actions Run](https://github.com/{}/actions/runs/{})",
        config.lock().unwrap().repository,
        status_params.run_id
    );
    let request = serde_json::json!({
        "head_sha": status_params.head_sha,
        "name": "Manifest Build",
        "status": "completed",
        "conclusion": status_params.conclusion,
        "details_url": details_url,
        "output": {
            "title": "Manifest Build",
            "summary": summary,
        }
    });
    let client = actix_web::client::Client::default();

    let mut response = client
        .post(format!(
            "https://api.github.com/repos/{}/check-runs",
            status_params.repository
        ))
        .header("User-Agent", "actix-web")
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("token {}", token))
        .send_json(&request)
        .await?;
    let body = response.body().await?;

    Ok(HttpResponse::build(response.status()).body(body))
}

fn json_error_handler(err: error::JsonPayloadError, _req: &HttpRequest) -> error::Error {
    use actix_web::error::JsonPayloadError;

    let detail = err.to_string();
    let resp = match &err {
        JsonPayloadError::ContentType => HttpResponse::UnsupportedMediaType().body(detail),
        JsonPayloadError::Deserialize(json_err) if json_err.is_data() => {
            HttpResponse::UnprocessableEntity().body(detail)
        }
        _ => HttpResponse::BadRequest().body(detail),
    };
    error::InternalError::from_response(err, resp).into()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let config = std::fs::read_to_string("/etc/webhooksrv")?;
    let config: Config = serde_yaml::from_str(&config).unwrap();

    let jwt_key = std::fs::read_to_string(&config.jwt_key)?;
    let jwt_key = jsonwebtoken::EncodingKey::from_rsa_pem(jwt_key.as_bytes()).unwrap();
    let jwt_key = web::Data::new(Mutex::new(jwt_key));

    let mac = HmacSha256::new_from_slice(config.webhook_secret.as_bytes()).unwrap();
    let mac = web::Data::new(Mutex::new(mac));

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file(&config.key, SslFiletype::PEM)
        .unwrap();
    builder.set_certificate_chain_file(&config.cert).unwrap();

    let config = web::Data::new(Mutex::new(config));
    HttpServer::new(move || {
        App::new()
            .app_data(web::JsonConfig::default().error_handler(json_error_handler))
            .app_data(jwt_key.clone())
            .app_data(mac.clone())
            .app_data(config.clone())
            .wrap(middleware::Logger::default())
            .service(web::resource("/").route(web::post().to(index)))
            .service(web::resource("/status").route(web::post().to(status)))
    })
    .bind_openssl("0.0.0.0:443", builder)?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pr_comment() {
        // no yml
        assert_eq!(
            extract_comment_westyml_parsed("").unwrap(),
            (DEFAULT_BRANCH, vec![])
        );
        // empty yml
        assert_eq!(
            extract_comment_westyml_parsed("west.yml:\n```yaml\n\n\n```\n").unwrap(),
            (DEFAULT_BRANCH, vec![])
        );
        // empty yml with ref
        assert_eq!(
            extract_comment_westyml_parsed("west.yml(ref:refs/heads/tmp):\n```yaml\n\n\n```\n")
                .unwrap(),
            ("refs/heads/tmp", vec![])
        );
        // simple yml
        assert_eq!(
            extract_comment_westyml_parsed("west.yml:\n```yaml\n- name: lol\n```\n").unwrap(),
            (
                DEFAULT_BRANCH,
                vec![west::Project {
                    name: "lol".to_string(),
                    ..west::Project::default()
                }]
            )
        );
        // simple yml with ref
        assert_eq!(
            extract_comment_westyml_parsed(
                "west.yml(ref:refs/heads/tmp2):\n```yaml\n- name: lol\n```\n"
            )
            .unwrap(),
            (
                "refs/heads/tmp2",
                vec![west::Project {
                    name: "lol".to_string(),
                    ..west::Project::default()
                }]
            )
        );
    }
}
