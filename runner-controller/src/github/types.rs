use serde::Deserialize;

/// Response from /repos/{owner}/{repo}/actions/runners
#[derive(Debug, Deserialize)]
pub struct RunnersResponse {
    pub runners: Vec<Runner>,
}

#[derive(Debug, Deserialize)]
pub struct Runner {
    pub id: u64,
    pub name: String,
    pub status: String,
    pub busy: bool,
}

/// Response from /repos/{owner}/{repo}/actions/runners/registration-token
#[derive(Debug, Deserialize)]
pub struct RegistrationTokenResponse {
    pub token: String,
}
