extern crate reqwest;
extern crate oauth1;

#[macro_use]
extern crate failure;

extern crate url;
extern crate select;

#[macro_use]
extern crate hyper;

extern crate serde;
extern crate serde_json;

pub mod requests;

use select::document::Document;
use select::predicate::{Predicate, Attr, Class, Name};

use reqwest::{Client, Certificate, Proxy, RedirectPolicy};
use reqwest::header::Authorization;
use reqwest::header::UserAgent;
use reqwest::header;
use reqwest::IntoUrl;

use serde::Serialize;
use serde::de::DeserializeOwned;

use serde_json::Value;

use oauth1::Token;
use failure::{Error, Context, Backtrace, Fail, err_msg};

use url::form_urlencoded;

use std::fmt;
use std::fmt::Display;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::cell::RefCell;
use std::borrow::Cow;

const REQUEST_TOKEN_URL: &str = "https://android-api.csfd.cz/oauth/request-token";
const ACCESS_TOKEN_URL: &str = "https://android-api.csfd.cz/oauth/access-token";
const AUTHORIZE_URL: &str = "https://android-api.csfd.cz/oauth/authorize";
const BASE_URL: &str = "https://android-api.csfd.cz";
const AUTHORIZE_CALLBACK: &str = "csfdroid://oauth-callback";

header! { (XAppVersion, "X-App-Version") => [String] }

#[derive(Clone, Debug)]
pub struct Csfd<'a> {
    inner: Client,
    consumer_token: Token<'a>,
    oauth_token: RefCell<Option<Token<'a>>>,
}

impl<'a> Csfd<'a> {
    pub fn new(consumer_key: &str, consumer_secret: &str) -> Csfd<'a> {
        let mut cert = Vec::new();
        //File::open("/home/richard/.mitmproxy/mitmproxy-ca.pem").unwrap().read_to_end(&mut cert).unwrap();
        File::open("C:\\Users\\RHoza\\Documents\\csfdapp\\rustcsfd\\target\\debug\\charlescert.pem").unwrap().read_to_end(&mut cert).unwrap();

        let cert = Certificate::from_pem(&cert).unwrap();

        Csfd {
            inner: Client::builder()
                .danger_disable_hostname_verification()
                .add_root_certificate(cert)
                .proxy(Proxy::all("http://127.0.0.1:8888").unwrap())
                .redirect(RedirectPolicy::none())
                .build()
                .unwrap(),
            consumer_token: Token::new(String::from(consumer_key), String::from(consumer_secret)),
            oauth_token: RefCell::new(None),
        }
    }

    pub fn set_access_token(&self, token: Token<'a>) {
        self.oauth_token.replace(Some(token));
    }

    pub fn get_authorize_url(token: &str) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        serializer.append_pair("oauth_token", token);
        serializer.append_pair("oauth_callback", AUTHORIZE_CALLBACK);
        let params = serializer.finish();
        format!("{}?{}", AUTHORIZE_URL, params)
    }

    pub fn get_request_token(&self) -> Result<Token, Error> {
        let mut response = self.inner.get(REQUEST_TOKEN_URL)
            .header(Authorization(oauth1::authorize(
                "GET",
                REQUEST_TOKEN_URL,
                &self.consumer_token,
                None,
                None,
            )))
            .send()?;

        let text = response.text()?;
        let text = form_urlencoded::parse(text.as_bytes());
        let pairs: HashMap<_, _> = text.into_owned().collect();

        if let (Some(key), Some(secret)) = (pairs.get("oauth_token"), pairs.get("oauth_token_secret")) {
            Ok(Token::new(key.clone(), secret.clone()))
        } else {
            Err(ApiErrorKind::NoOauthToken)?
        }
    }

    pub fn get_access_token(&self, request_token: Token) -> Result<Token<'a>, Error> {
        let mut response = self.inner.post(ACCESS_TOKEN_URL)
            .header(Authorization(oauth1::authorize(
                "POST",
                ACCESS_TOKEN_URL,
                &self.consumer_token,
                Some(&request_token),
                None,
            )))
            .send()?;

        let text = response.text()?;
        let text = form_urlencoded::parse(text.as_bytes());
        let pairs: HashMap<_,_> = text.into_owned().collect();

        if let (Some(token), Some(secret)) = (pairs.get("oauth_token"), pairs.get("oauth_token_secret")) {
            Ok(Token::new(token.clone(), secret.clone()))
        } else {
            Err(ApiErrorKind::NoOauthToken)?
        }
    }

    pub fn get(&self, endpoint: &str, params: Option<HashMap<&'static str, Cow<str>>>) -> Result<reqwest::Response, reqwest::Error> {
        let endpoint_url = format!("{}/{}", BASE_URL, endpoint);
        let mut request = self.inner.get(&endpoint_url);

        if let Some(ref params) = params {
            request.query(params);
        }

        request
            .header(Authorization(oauth1::authorize(
                "GET",
                &endpoint_url,
                &self.consumer_token,
                self.oauth_token.borrow().as_ref(),
                params,
            )))
            //.header(UserAgent::new("CSFDroid/2.2.3.1508 (Nexus 7; 4.4.4 REL)"))
            //.header(XAppVersion("1508".to_owned()))
            .header(header::Connection::keep_alive())
            .send()
    }

    fn get_phpsessid_cookie_from_set_cookie(response: &reqwest::Response) -> Option<header::Cookie> {
        let set_cookie = response.headers().get::<header::SetCookie>();

        if let Some(set_cookie) = set_cookie {
            if set_cookie.len() == 0 {
                return None;
            }

            if let Some(phpsessid) = set_cookie[0].split(";").nth(0) {
                if let Some(sessionid) = phpsessid.split("=").nth(1) {
                    if sessionid == "deleted" {
                        return None;
                    } else {
                        let mut cookie = header::Cookie::new();
                        cookie.append("PHPSESSID", String::from(sessionid));
                        return Some(cookie);
                    }
                }
            }
        }

        None
    }

    fn follow_redirect(&self, location: Option<&header::Location>, session: Option<header::Cookie>) -> Result<(), Error> {
        if let (Some(location), Some(session)) = (location, session) {
            let response = self.inner.get(location as &str)
                 .header(session)
                 .send()?;

            let location = response.headers().get::<header::Location>();
            let session = Csfd::get_phpsessid_cookie_from_set_cookie(&response);
            self.follow_redirect(location, session)?;
        }

        Ok(())
    }

    pub fn authorize(&self, username: &str, password: &str) -> Result<(), Error> {
        let request_token = self.get_request_token()?;
        self.authorize_user(username, password, &request_token.key)?;
        let access_token = self.get_access_token(request_token)?;
        self.oauth_token.replace(Some(access_token));
        Ok(())
    }

    pub fn authorize_user(&self, username: &str, password: &str, request_token: &str) -> Result<(), Error> {
        let authorize_url = Csfd::get_authorize_url(request_token);
        let mut response = self.inner.get(&authorize_url).send()?;
        let document = response.text()?;
        let document = Document::from(&document[..]);

        let action = document.find(Attr("id", "frm-authorizeForm"))
            .nth(0)
            .ok_or(err_msg("could not find authorization form"))?
            .attr("action")
            .ok_or(err_msg("authorization form does not contain action attribute"))?;

        let session_cookie = Csfd::get_phpsessid_cookie_from_set_cookie(&response).ok_or(err_msg("could not get phpsessid set-cookie"))?;

        let response = self.inner.post(action)
            .form(&[("username", username), ("password", password)])
            .header(session_cookie)
            .send()?;

        let location = response.headers().get::<header::Location>();
        let session = Csfd::get_phpsessid_cookie_from_set_cookie(&response);

        self.follow_redirect(location, session)?;

        //let location = response.headers().get::<header::Location>().ok_or(err_msg("response does not contain redirect location"))?;
        //let session_cookie = Csfd::get_phpsessid_cookie_from_set_cookie(&response).ok_or(err_msg("could not get phpsessid set-cookie"))?;

        // let response = self.inner.get(location as &str)
        //     .header(session_cookie)
        //     .send()?;

        // let location = response.headers().get::<header::Location>().ok_or(err_msg("response does not contain redirect location"))?;
        // let session_cookie = Csfd::get_phpsessid_cookie_from_set_cookie(&response).ok_or(err_msg("could not get phpsessid set-cookie"))?;

        // let response = self.inner.get(location as &str)
        //     .header(session_cookie)
        //     .send()?;

        // let location = response.headers().get::<header::Location>().ok_or(err_msg("response does not contain redirect location"))?;
        // let session_cookie = Csfd::get_phpsessid_cookie_from_set_cookie(&response).ok_or(err_msg("could not get phpsessid set-cookie"))?;

        // let response = self.inner.get(location as &str)
        //     .header(session_cookie)
        //     .send()?;

        //self.follow_redirect(Some(&header::Location::new("")), Some(header::Cookie::new()));

        Ok(())
        // if let Some(node) = document.find(Attr("id", "frm-authorizeForm")).next() {
        //     if let Some(action) = node.attr("action") {
        //         let response = self.inner.post(action)
        //             .form(&[("username", username), ("password", password)])
        //             .send()?;

        //         println!("response {:?}", response);

        //         let location = response.headers().get::<header::Location>();
        //         let set_cookie = response.headers().get::<header::SetCookie>();

        //         if let (Some(location), Some(set_cookie)) = (location, set_cookie) {
        //             println!("location {:?}", location);
        //             println!("set_cookie {:?}", set_cookie);

        //             if set_cookie.len() != 1 {
        //                 panic!("more than one cookie to set");
        //             }

        //             if let Some(phpsessid) = set_cookie[0].split(";").next() {
        //                 if let Some(sessionid) = phpsessid.split("=").nth(1) {
        //                     println!("PHPSESSID {:?}", sessionid);

        //                     let mut cookie = header::Cookie::new();
        //                     cookie.append("PHPSESSID", String::from(sessionid));

        //                     let response = self.inner.get(location as &str)
        //                         .header(cookie)
        //                         .send()?;

        //                     println!("response {:?}", response);

        //                     return Ok(());
        //                 }
        //             }
        //         }
        //     }
        // }

        //panic!("invalid form");
    }


    pub fn identity(&self) -> requests::IdentityRequest<'a> {
        requests::IdentityRequest::new(self)
    }

    pub fn home(&self) -> requests::HomeRequest<'a> {
        requests::HomeRequest::new(self)
    }

    pub fn ad_mob(&self) {
        let text: String = self.get("ad/ad-mob", None).expect("could not get ad-mob").text().unwrap();
        println!("{:?}", text);
    }
}

#[derive(Debug)]
struct ApiError {
    inner: Context<ApiErrorKind>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
enum ApiErrorKind {
    #[fail(display = "Response did not contain oauth token.")]
    NoOauthToken,

    #[fail(display = "Could not find login form in response from server.")]
    ResponseWithoutForm,
}

impl Fail for ApiError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.inner, f)
    }
}

impl ApiError {
    pub fn kind(&self) -> ApiErrorKind {
        *self.inner.get_context()
    }
}

impl From<ApiErrorKind> for ApiError {
    fn from(kind: ApiErrorKind) -> ApiError {
        ApiError { inner: Context::new(kind) }
    }
}

impl From<Context<ApiErrorKind>> for ApiError {
    fn from(inner: Context<ApiErrorKind>) -> ApiError {
        ApiError { inner: inner }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
