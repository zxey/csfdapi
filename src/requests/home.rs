use ::Csfd;
use reqwest;
use std::collections::HashMap;
use std::borrow::Cow;
use std::fmt;

pub struct HomeData {
    data: Vec<HomeDataItem>
}

impl HomeData {
    fn new() -> HomeData {
        HomeData {
            data: Vec::new()
        }
    }

    fn add_if_not_exists(&mut self, item: HomeDataItem) -> &mut Self {
        if !self.data.contains(&item) {
            self.data.push(item);
        }

        self
    }

    pub fn all(&mut self) -> &mut Self {
        self.new_videos()
            .tv_tips()
            .cinema_releases()
            .dvd_releases()
            .bluray_releases()
            .film_profile_visits()
            .creator_profile_visits()
            .adverts()
    }

    pub fn new_videos(&mut self) -> &mut Self {
        self.add_if_not_exists(HomeDataItem::NewVideos)
    }

    pub fn tv_tips(&mut self) -> & mut Self {
        self.add_if_not_exists(HomeDataItem::TvTips)
    }

    pub fn cinema_releases(&mut self) -> & mut Self {
        self.add_if_not_exists(HomeDataItem::CinemaReleases)
    }

    pub fn dvd_releases(&mut self) -> & mut Self {
        self.add_if_not_exists(HomeDataItem::DvdReleases)
    }

    pub fn bluray_releases(&mut self) -> & mut Self {
        self.add_if_not_exists(HomeDataItem::BlurayReleases)
    }

    pub fn film_profile_visits(&mut self) -> & mut Self {
        self.add_if_not_exists(HomeDataItem::FilmProfileVisits)
    }

    pub fn creator_profile_visits(&mut self) -> & mut Self {
        self.add_if_not_exists(HomeDataItem::CreatorProfileVisits)
    }

    pub fn adverts(&mut self) -> & mut Self {
        self.add_if_not_exists(HomeDataItem::Adverts)
    }
}

impl fmt::Display for HomeData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = self.data.iter().map(|i| i.to_string()).collect::<Vec<String>>().join(",");
        write!(f, "{}", string)
    }
}

#[derive(PartialEq, Clone)]
pub enum HomeDataItem {
    NewVideos,
    TvTips,
    CinemaReleases,
    DvdReleases,
    BlurayReleases,
    FilmProfileVisits,
    CreatorProfileVisits,
    Adverts,
}

impl fmt::Display for HomeDataItem {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            HomeDataItem::NewVideos => "new_videos",
            HomeDataItem::TvTips => "tv_tips",
            HomeDataItem::CinemaReleases => "cinema_releases",
            HomeDataItem::DvdReleases => "dvd_releases",
            HomeDataItem::BlurayReleases => "bluray_releases",
            HomeDataItem::FilmProfileVisits => "film_profile_visits",
            HomeDataItem::CreatorProfileVisits => "creator_profile_visits",
            HomeDataItem::Adverts => "adverts",
        };

        write!(f, "{}", string)
    }
}

#[derive(Debug)]
pub struct HomeRequest<'a> {
    inner: Csfd<'a>,
    params: HashMap<&'static str, Cow<'a, str>>,
}

impl<'a> HomeRequest<'a> {
    pub fn new(csfd: &Csfd<'a>) -> HomeRequest<'a> {
        HomeRequest {
            inner: csfd.clone(),
            params: HashMap::new(),
        }
    }

    pub fn data<F>(&mut self, data: F) -> &mut Self
        where F: FnOnce(&mut HomeData) -> &mut HomeData
    {
        let mut home_data = HomeData::new();
        data(&mut home_data);
        self.params.insert("data", home_data.to_string().into());
        self
    }

    pub fn limit(&mut self, limit: u32) -> &mut Self {
        self.params.insert("limit", limit.to_string().into());
        self
    }

    pub fn creator_profile_visits_limit(&mut self, limit: u32) -> &mut Self {
        self.params.insert("creator_profile_visits_limit", limit.to_string().into());
        self
    }

    pub fn send(&self) -> Result<String, reqwest::Error> {
        self.inner.get("home", Some(self.params.clone()))?.text()
    }
}