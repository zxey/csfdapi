use ::Csfd;
use reqwest;
use std::collections::HashMap;
use std::borrow::Cow;
use std::fmt;
use std::fmt::Display;

pub type Params<'a> = HashMap<&'static str, Cow<'a, str>>;

pub struct NoParams<'a>(Params<'a>);

impl<'a> NoParams<'a> {
    pub(crate) fn new() -> Self {
        NoParams(Params::new())
    }
}

impl<'a> Into<Params<'a>> for NoParams<'a> {
    fn into(self) -> Params<'a> {
        self.0
    }
}

pub struct CreatorParams<'a>(Params<'a>);

impl<'a> CreatorParams<'a> {
    pub(crate) fn new() -> Self {
        CreatorParams(Params::new())
    }

    pub fn limit(&mut self, limit: u32) -> &mut Self {
        self.0.insert("limit", limit.to_string().into());
        self
    }

    pub fn offset(&mut self, offset: u32) -> &mut Self {
        self.0.insert("offset", offset.to_string().into());
        self
    }
}

impl<'a> Into<Params<'a>> for CreatorParams<'a> {
    fn into(self) -> Params<'a> {
        self.0
    }
}

pub struct SearchParams<'a>(Params<'a>);

impl<'a> SearchParams<'a> {
    pub(crate) fn new() -> Self {
        SearchParams(Params::new())
    }

    pub fn limit(&mut self, limit: u8) -> &mut Self {
        self.0.insert("limit", limit.to_string().into());
        self
    }

    pub fn query(&mut self, query: &'a str) -> &mut Self {
        self.0.insert("q", query.into());
        self
    }
}

impl<'a> Into<Params<'a>> for SearchParams<'a> {
    fn into(self) -> Params<'a> {
        self.0
    }
}

pub struct AutocompleteParams<'a>(Params<'a>);

impl<'a> AutocompleteParams<'a> {
    pub(crate) fn new() -> Self {
        AutocompleteParams(Params::new())
    }

    pub fn query(&mut self, query: &'a str) -> &mut Self {
        self.0.insert("q", query.into());
        self
    }
}

impl<'a> Into<Params<'a>> for AutocompleteParams<'a> {
    fn into(self) -> Params<'a> {
        self.0
    }
}

pub struct HomeData {
    data: Vec<HomeDataItem>
}

impl HomeData {
    pub fn new() -> HomeData {
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

#[derive(Clone)]
pub struct HomeParams<'a>(Params<'a>);

impl<'a> HomeParams<'a> {
    pub(crate) fn new() -> Self {
        //let mut map = HashMap::new();
        //map.insert("data", "new_videos".into());
        HomeParams(Params::new())
    }

    pub fn data<F>(&mut self, data: F) -> &mut Self
        where F: FnOnce(&mut HomeData) -> &mut HomeData
    {
        let mut home_data = HomeData::new();
        data(&mut home_data);
        self.0.insert("data", home_data.to_string().into());
        self
    }

    pub fn limit(&mut self, limit: u32) -> &mut Self {
        self.0.insert("limit", limit.to_string().into());
        self
    }

    pub fn creator_profile_visits_limit(&mut self, limit: u32) -> &mut Self {
        self.0.insert("creator_profile_visits_limit", limit.to_string().into());
        self
    }
}

impl<'a> Into<Params<'a>> for HomeParams<'a> {
    fn into(self) -> Params<'a> {
        self.0
    }
}

pub enum Search {
    Films,
    Creators,
    Users,
}

impl Display for Search {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = match self {
            Search::Films => "films",
            Search::Creators => "creators",
            Search::Users => "users",
        };

        write!(f, "{}", string)
    }
}