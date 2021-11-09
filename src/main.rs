use actix_web::{error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use hmac::{Mac, NewMac};
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
        .map_err(|e| HttpResponse::BadRequest().body(format!("bad signature length: {:?}", e)))?;

    let mut mac = mac.lock().unwrap().clone();
    mac.update(&bytes);
    mac.verify(&sig)
        .map_err(|e| HttpResponse::Forbidden().body(format!("invalid signature: {:?}", e)))?;

    Ok(())
}

fn parse_event(req: &HttpRequest, bytes: &web::Bytes) -> Result<ghapi::Event, Error> {
    let event_type = req
        .headers()
        .get("X-GitHub-Event")
        .ok_or_else(|| HttpResponse::BadRequest().body("missing event type"))?
        .to_str()
        .map_err(|e| {
            HttpResponse::BadRequest().body(format!("event-type isn't a valid string: {:?}", e))
        })?;

    Ok(match event_type {
        "pull_request" => {
            serde_json::from_slice::<ghapi::PullRequestEvent>(bytes).map(ghapi::Event::PullRequest)
        }
        _ => return Err(HttpResponse::Ok().body("unsupported event").into()),
    }
    .map_err(|e| HttpResponse::Ok().body(format!("can't parse event: {:?}", e)))?)
}

#[cfg(not(test))]
fn build_git_url(token: &str, repository: &str) -> String {
    format!("https://git:{}@github.com/{}", token, repository)
}

#[cfg(test)]
fn build_git_url(_token: &str, repository: &str) -> String {
    format!("file://{}", repository)
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

fn remote_callbacks_push<'cb>() -> git2::RemoteCallbacks<'cb> {
    let mut rc = git2::RemoteCallbacks::new();
    rc.push_update_reference(|name, status| {
        status.map_or_else(
            || Ok(()),
            |status| {
                Err(git2::Error::from_str(&format!(
                    "can't update reference `{}`: {}",
                    name, status
                )))
            },
        )
    });

    rc
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

    let repo = git2::Repository::init(&tmp_repo)
        .map_err(|e| HttpResponse::BadRequest().body(format!("can't init tmp git repo: {}", e)))?;
    let mut remote = repo
        .remote("origin", &build_git_url(&token, &config.repository))
        .map_err(|e| HttpResponse::BadRequest().body(format!("can't add remote: {}", e)))?;

    let mut po = git2::PushOptions::new();
    po.remote_callbacks(remote_callbacks_push());

    remote
        .push(
            &[format!(
                ":refs/heads/manifest/pull/{}/{}",
                event.repository.full_name, event.number
            )],
            Some(&mut po),
        )
        .map_err(|e| {
            HttpResponse::BadRequest().body(format!("can't delete manifest branch: {}", e))
        })?;

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
    let manifest_repo_path = config.workdir.join("manifest");
    let tmp_repo_path = config.workdir.join("tmp");

    log.extend_from_slice(b"extract manifest from PR text...\n");
    let (comment_manifestref, mut comment_westyml) =
        extract_comment_westyml_parsed(&event.pull_request.body)?;

    log.extend_from_slice(b"create workdir...\n");
    tokio::fs::create_dir_all(&config.workdir).await?;

    let manifest_repo = if !manifest_repo_path.exists() {
        log.extend_from_slice(b"clone manifest...\n");
        let mut rb = git2::build::RepoBuilder::new();
        rb.bare(true).clone(
            &build_git_url(&token, &config.repository),
            &manifest_repo_path,
        )?
    } else {
        log.extend_from_slice(b"set manifest URL...\n");
        let repo = git2::Repository::open(&manifest_repo_path)?;
        repo.remote_set_url("origin", &build_git_url(&token, &config.repository))?;
        repo
    };

    log.extend_from_slice(b"delete old manifest reference...\n");
    match manifest_repo.find_reference(&comment_manifestref) {
        Err(e) if e.code() == git2::ErrorCode::NotFound => (),
        Err(e) => return Err(e.into()),
        Ok(mut reference) => reference.delete()?,
    }

    log.extend_from_slice(b"update manifest repo...\n");
    manifest_repo.find_remote("origin")?.fetch(
        &[format!("{gitref}:{gitref}", gitref = comment_manifestref)],
        None,
        None,
    )?;

    log.extend_from_slice(b"create tmp repo dir...\n");
    if tmp_repo_path.exists() {
        tokio::fs::remove_dir_all(&tmp_repo_path).await?;
    }
    tokio::fs::create_dir_all(&tmp_repo_path).await?;

    log.extend_from_slice(b"init tmp repo...\n");
    let tmp_repo = git2::Repository::init(&tmp_repo_path)?;
    let mut tmp_repo_config = tmp_repo.config()?;

    log.extend_from_slice(b"set git name...\n");
    tmp_repo_config.set_str("user.name", "multirepo-actions[bot]")?;

    log.extend_from_slice(b"set git email...\n");
    tmp_repo_config.set_str(
        "user.email",
        &format!(
            "{}+multirepo-actions[bot]@users.noreply.github.com",
            config.jwt_iss
        ),
    )?;

    log.extend_from_slice(b"fetch local manifest repo...\n");
    tmp_repo
        .remote_anonymous(
            manifest_repo_path
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("{:?} is not valid unicode", manifest_repo_path))?,
        )?
        .fetch(&[comment_manifestref], None, None)?;

    log.extend_from_slice(b"checkout manifest code...\n");
    let fetch_head_oid = tmp_repo
        .find_reference("FETCH_HEAD")?
        .target()
        .ok_or_else(|| anyhow::anyhow!("can't get FETCH_HEAD target"))?;
    let fetch_head_commit = tmp_repo.find_commit(fetch_head_oid)?;
    tmp_repo.checkout_tree(fetch_head_commit.as_object(), None)?;

    log.extend_from_slice(b"parse main west.yml...\n");
    let westyml = std::fs::read_to_string(tmp_repo_path.join("west.yml"))?;
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

    let mut file = tokio::fs::File::create(tmp_repo_path.join("PR_INFO")).await?;
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

    let mut file = tokio::fs::File::create(tmp_repo_path.join("west.yml")).await?;
    file.write_all(newwestfile_str.as_bytes()).await?;
    file.sync_all().await?;

    log.extend_from_slice(b"git-add worktree...\n");
    let mut index = tmp_repo.index().unwrap();
    index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
    let tree_oid = index.write_tree().unwrap();
    index.write().unwrap();

    log.extend_from_slice(b"commit tmp repo...\n");
    let author = tmp_repo.signature()?;
    let tree = tmp_repo.find_tree(tree_oid).unwrap();
    tmp_repo
        .commit(
            Some("HEAD"),
            &author,
            &author,
            &event.pull_request.title,
            &tree,
            &[&fetch_head_commit],
        )
        .unwrap();

    let url = build_git_url(&token, &config.repository);
    let gitref = format!(
        "refs/heads/manifest/pull/{}/{}",
        event.repository.full_name, event.number
    );

    log.extend_from_slice(b"get list of manifest refs...\n");
    let mut remote = tmp_repo.remote_anonymous(&url)?;
    remote.connect(git2::Direction::Fetch)?;
    let remote_refs = remote.list()?;

    if force_update {
        log.extend_from_slice(b"force update.\n");
    } else if remote_refs.iter().any(|r| r.name() == gitref) {
        log.extend_from_slice(b"fetch current tmp repo...\n");
        remote.fetch(&[&gitref], None, None)?;

        log.extend_from_slice(b"check if tmp code changed...\n");
        let fetch_head_oid = tmp_repo
            .find_reference("FETCH_HEAD")?
            .target()
            .ok_or_else(|| anyhow::anyhow!("can't get FETCH_HEAD target"))?;
        let fetch_head_commit = tmp_repo.find_commit(fetch_head_oid)?;
        let fetch_head_tree = fetch_head_commit.tree()?;
        let diff = tmp_repo.diff_tree_to_workdir(Some(&fetch_head_tree), None)?;

        if diff.deltas().len() == 0 {
            log.extend_from_slice(b"nothing has changed, don't push.\n");
            return Ok(());
        }

        log.extend_from_slice(b"something has changed, let's push.\n");
    } else {
        log.extend_from_slice(b"ref doesn't exist yet, let's push.\n");
    }

    log.extend_from_slice(b"push tmp repo...\n");
    let mut po = git2::PushOptions::new();
    po.remote_callbacks(remote_callbacks_push());
    remote.push(&[format!("+HEAD:{}", gitref)], Some(&mut po))?;

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

/*
async fn cmd(
    _req: HttpRequest,
    bytes: web::Bytes,
) -> Result<HttpResponse, Error> {
    let args:Vec<_> = std::str::from_utf8(&bytes)?.split(' ').collect();
    let mut log = Vec::new();

    let result = tokio::process::Command::new(args[0])
        .env("LD_DEBUG", "all")
        .args(&args[1..])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?
        .wait_with_output()
        .await?;

    log.extend_from_slice(b"stdout:\n");
    log.extend_from_slice(&result.stdout);

    log.extend_from_slice(b"\n\nstderr:\n");
    log.extend_from_slice(&result.stderr);

    write!(log, "\n\nstatus:{:?}\n", result.status)?;

    Ok(HttpResponse::Ok().body(log))
}*/

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

    openssl_probe::init_ssl_cert_env_vars();

    let port: u16 = match std::env::var("FUNCTIONS_CUSTOMHANDLER_PORT") {
        Ok(val) => val.parse().expect("Custom Handler port is not a number!"),
        Err(_) => 3000,
    };
    eprintln!("function port: {}", port);

    let config = std::fs::read_to_string("webhooksrv.conf")?;
    let config: Config = serde_yaml::from_str(&config).unwrap();

    let jwt_key = std::fs::read_to_string(&config.jwt_key)?;
    let jwt_key = jsonwebtoken::EncodingKey::from_rsa_pem(jwt_key.as_bytes()).unwrap();
    let jwt_key = web::Data::new(Mutex::new(jwt_key));

    let mac = HmacSha256::new_from_slice(config.webhook_secret.as_bytes()).unwrap();
    let mac = web::Data::new(Mutex::new(mac));

    let config = web::Data::new(Mutex::new(config));
    HttpServer::new(move || {
        App::new()
            .app_data(web::JsonConfig::default().error_handler(json_error_handler))
            .app_data(jwt_key.clone())
            .app_data(mac.clone())
            .app_data(config.clone())
            .wrap(middleware::Logger::default())
            .service(web::resource("/api/webhook").route(web::post().to(index)))
            .service(web::resource("/api/status").route(web::post().to(status)))
    })
    .bind(format!("0.0.0.0:{}", port))?
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

    async fn make_manifest_repo(repo_path: &std::path::Path, westyml: &west::File) {
        let workdir = tempfile::tempdir().unwrap();

        // init repo
        let tmp_repo = git2::Repository::init(&workdir).unwrap();

        // write west.yml
        let westyml_str = serde_yaml::to_string(&westyml).unwrap();
        let mut westyml_file = tokio::fs::File::create(workdir.path().join("west.yml"))
            .await
            .unwrap();
        westyml_file
            .write_all(westyml_str.as_bytes())
            .await
            .unwrap();
        westyml_file.sync_all().await.unwrap();

        // stage files
        let mut index = tmp_repo.index().unwrap();
        index.add_path(std::path::Path::new("west.yml")).unwrap();
        let tree_oid = index.write_tree().unwrap();
        index.write().unwrap();

        // commit
        let author = git2::Signature::now("name", "name@example.com").unwrap();
        let tree = tmp_repo.find_tree(tree_oid).unwrap();
        tmp_repo
            .commit(Some("HEAD"), &author, &author, "Initial commit", &tree, &[])
            .unwrap();

        // init bare repo
        git2::Repository::init_bare(&repo_path).unwrap();

        // push to remote
        let repo_url = format!("file://{}", repo_path.to_str().unwrap());
        let mut remote = tmp_repo.remote_anonymous(&repo_url).unwrap();
        let mut po = git2::PushOptions::new();
        po.remote_callbacks(remote_callbacks_push());
        remote
            .push(&["HEAD:refs/heads/main"], Some(&mut po))
            .unwrap();
    }

    #[tokio::test]
    async fn update_manifest_branch() {
        let mut log = vec![];
        let workdir = tempfile::tempdir().unwrap();
        let remote_dir = tempfile::tempdir().unwrap();

        eprintln!("workdir: {:?}", workdir);
        eprintln!("remote_dir: {:?}", remote_dir);

        let westyml = west::File {
            manifest: west::Manifest {
                defaults: west::Defaults::default(),
                remotes: vec![west::Remote {
                    name: "github".to_string(),
                    url_base: "https://github.com".to_string(),
                }],
                projects: vec![west::Project {
                    name: "mcuboot".to_string(),
                    remote: Some("github".to_string()),
                    repo_path: Some("zephyrproject-rtos/mcuboot".to_string()),
                    revision: Some("main".to_string()),
                    ..west::Project::default()
                }],
            },
        };

        let manifest_repo_path = remote_dir.path().join("manifest");
        make_manifest_repo(&manifest_repo_path, &westyml).await;

        let config = web::Data::new(std::sync::Mutex::new(Config {
            webhook_secret: "secret".to_string(),
            api_token: "api-token".to_string(),
            api_installation_id: 1,
            repository: manifest_repo_path.to_str().unwrap().to_string(),
            jwt_iss: 1,
            jwt_key: "jwt-key".to_string(),
            repos_include: vec![],
            repos_exclude: vec![],
            workdir: workdir.path().to_path_buf(),
        }));

        let repo = ghapi::Repository {
            full_name: "zephyrproject-rtos/mcuboot".to_string(),
        };
        let event = ghapi::PullRequestEvent {
            action: ghapi::PullRequestAction::Opened,
            number: 1,
            pull_request: ghapi::PullRequest {
                title: "My PR".to_string(),
                body: "".to_string(),
                head: ghapi::Branch {
                    r#ref: "refs/heads/feature".to_string(),
                    sha: "00000000".to_string(),
                    repo: repo.clone(),
                },
                base: ghapi::Branch {
                    r#ref: "refs/heads/main".to_string(),
                    sha: "00000000".to_string(),
                    repo: repo.clone(),
                },
                state: "open".to_string(),
            },
            repository: repo,
            installation: ghapi::Installation { id: 1 },
        };

        let result = update_manifest_branch_inner(&config, &event, "token", false, &mut log).await;
        eprintln!("log:\n{}", String::from_utf8_lossy(&log));
        result.unwrap();

        let result = update_manifest_branch_inner(&config, &event, "token", false, &mut log).await;
        eprintln!("log:\n{}", String::from_utf8_lossy(&log));
        result.unwrap();

        tokio::time::delay_for(tokio::time::Duration::from_secs(9999999)).await;
    }
}
