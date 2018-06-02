use ::Csfd;
use reqwest;

pub struct IdentityRequest<'a> {
    inner: Csfd<'a>
}

impl<'a> IdentityRequest<'a> {
    pub fn new(csfd: &Csfd<'a>) -> IdentityRequest<'a> {
        IdentityRequest {
            inner: csfd.clone()
        }
    }

    pub fn send(&self) -> Result<String, reqwest::Error> {
        self.inner.get("identity", None)?.text()
    }
}