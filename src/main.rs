use actix_web::{error, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use hmac::{Mac, NewMac};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::convert::TryInto;
use std::sync::Mutex;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

#[derive(Debug, serde::Deserialize)]
struct Config {
    /// this can be used to verify the signature of GitHub webhook events
    webhook_secret: String,
    /// repo with the workflow that gets started on webhook events
    repository: String,
    /// github access token for `repository`
    token: String,
    /// SSL key
    key: String,
    /// SSL cert
    cert: String,
    /// ID of this GitHub App
    jwt_iss: usize,
    /// Path to PEM with the private RSA key of this GitHub App
    jwt_key: String,
    /// installation ID of the GitHub org where we set status checks
    app_install_id: u64,
    /// the secret that's required to use the status API of this service
    access_token: String,
    /// repos to include. This gets passed to `startswith`
    repos_include: Vec<String>,
    /// repos to exclude. This has to be a full match and comes after repos_include
    repos_exclude: Vec<String>,
}

#[derive(Debug, serde::Serialize)]
struct Claims {
    iat: usize,
    exp: usize,
    iss: usize,
}

#[derive(Debug, serde::Deserialize)]
struct AccessTokens {
    token: String,
}

#[derive(Debug, serde::Deserialize)]
struct StatusParams {
    head_sha: String,
    repository: String,
    conclusion: String,
    details_url: String,
}

#[derive(Debug, serde::Deserialize)]
struct PushEventRepository {
    full_name: String,
}

#[derive(Debug, serde::Deserialize)]
struct PushEvent {
    repository: PushEventRepository,
}
async fn index(
    config: web::Data<Mutex<Config>>,
    mac: web::Data<Mutex<HmacSha256>>,
    req: HttpRequest,
    bytes: web::Bytes,
) -> Result<HttpResponse, Error> {
    let sig = req
        .headers()
        .get("X-Hub-Signature-256")
        .ok_or_else(|| HttpResponse::BadRequest().body("missing signature"))?
        .as_bytes();
    if !sig.starts_with(b"sha256=") {
        return Ok(HttpResponse::BadRequest().body("unsupported signature type"));
    }
    let sig = hex::decode(&sig[7..])
        .map_err(|_| HttpResponse::BadRequest().body("bad signature length"))?;
    let data = String::from_utf8(bytes.to_vec())
        .map_err(|_| HttpResponse::BadRequest().body("body is not valid utf-8"))?;

    let mut mac = mac.lock().unwrap().clone();
    mac.update(&bytes);
    mac.verify(&sig)
        .map_err(|_| HttpResponse::Forbidden().body("invalid signature"))?;

    let push_event = serde_json::from_slice::<PushEvent>(&bytes)
        .map_err(|_| HttpResponse::Ok().body("unsupported event"))?;

    let mut found = false;
    for repo_prefix in &config.lock().unwrap().repos_include {
        if push_event.repository.full_name.starts_with(repo_prefix) {
            found = true;
        }
    }
    if !found {
        return Ok(HttpResponse::Ok().body("ignored push event (no include)"));
    }

    for repo_name in &config.lock().unwrap().repos_exclude {
        if &push_event.repository.full_name == repo_name {
            return Ok(HttpResponse::Ok().body("ignored push event (exclude)"));
        }
    }

    let request = serde_json::json!({
        "ref": "refs/heads/main",
        "inputs": {
            "webhook_payload": data
        }
    });

    let client = actix_web::client::Client::default();
    let mut response = client
        .post(format!(
            "https://api.github.com/repos/{}/actions/workflows/build.yml/dispatches",
            config.lock().unwrap().repository
        ))
        .header("User-Agent", "actix-web")
        .header("Accept", "application/vnd.github.v3+json")
        .header(
            "Authorization",
            format!("token {}", config.lock().unwrap().token),
        )
        .send_json(&request)
        .await?;
    let body = response.body().await?;

    Ok(HttpResponse::build(response.status()).body(body))
}

async fn status(
    config: web::Data<Mutex<Config>>,
    jwt_key: web::Data<Mutex<jsonwebtoken::EncodingKey>>,
    req: HttpRequest,
    status_params: web::Json<StatusParams>,
) -> Result<HttpResponse, Error> {
    let token = req
        .headers()
        .get("X-Access-Token")
        .ok_or_else(|| HttpResponse::BadRequest().body("missing access token"))?;
    if token != config.lock().unwrap().access_token.as_bytes() {
        return Ok(HttpResponse::Forbidden().body("wrong access token"));
    }
    if !status_params
        .repository
        .chars()
        .all(|c| c.is_alphanumeric() || c == '/' || c == '-' || c == '_')
    {
        return Ok(HttpResponse::BadRequest().body("unsupported characters in repository"));
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        iat: (now - 60).try_into().unwrap(),
        exp: (now + (1 * 60)).try_into().unwrap(),
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
            config.lock().unwrap().app_install_id
        ))
        .header("User-Agent", "actix-web")
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await?;
    let access_tokens: AccessTokens = response.json().await?;

    let request = serde_json::json!({
        "head_sha": status_params.head_sha,
        "name": "Build",
        "status": "completed",
        "conclusion": status_params.conclusion,
        "details_url": status_params.details_url
    });
    let client = actix_web::client::Client::default();
    let mut response = client
        .post(format!(
            "https://api.github.com/repos/{}/check-runs",
            status_params.repository
        ))
        .header("User-Agent", "actix-web")
        .header("Accept", "application/vnd.github.v3+json")
        .header("Authorization", format!("token {}", access_tokens.token))
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
            .service(web::resource("/status").route(web::post().to(status)))
            .service(web::resource("/").route(web::post().to(index)))
    })
    .bind_openssl("0.0.0.0:443", builder)?
    .run()
    .await
}
