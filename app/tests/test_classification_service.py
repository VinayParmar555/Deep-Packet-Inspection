import pytest
from app.services.classification_service import ClassificationService
from app.schema.connection_schema import AppType


@pytest.fixture
def svc():
    return ClassificationService()


# ---------------------------------------------------------------------------
# Known app mappings
# ---------------------------------------------------------------------------

class TestKnownApps:
    def test_google(self, svc):
        assert svc.sni_to_app("www.google.com") == AppType.GOOGLE

    def test_google_googleapis(self, svc):
        assert svc.sni_to_app("fonts.googleapis.com") == AppType.GOOGLE

    def test_youtube(self, svc):
        assert svc.sni_to_app("www.youtube.com") == AppType.YOUTUBE

    def test_youtube_img(self, svc):
        assert svc.sni_to_app("i.ytimg.com") == AppType.YOUTUBE

    def test_facebook(self, svc):
        assert svc.sni_to_app("www.facebook.com") == AppType.FACEBOOK

    def test_instagram(self, svc):
        assert svc.sni_to_app("www.instagram.com") == AppType.INSTAGRAM

    def test_whatsapp(self, svc):
        assert svc.sni_to_app("web.whatsapp.com") == AppType.WHATSAPP

    def test_twitter(self, svc):
        assert svc.sni_to_app("api.twitter.com") == AppType.TWITTER

    def test_twitter_x_com(self, svc):
        assert svc.sni_to_app("x.com") == AppType.TWITTER

    def test_netflix(self, svc):
        assert svc.sni_to_app("www.netflix.com") == AppType.NETFLIX

    def test_amazon(self, svc):
        assert svc.sni_to_app("www.amazon.com") == AppType.AMAZON

    def test_microsoft(self, svc):
        assert svc.sni_to_app("login.microsoftonline.com") == AppType.MICROSOFT

    def test_apple(self, svc):
        assert svc.sni_to_app("www.apple.com") == AppType.APPLE

    def test_telegram(self, svc):
        assert svc.sni_to_app("web.telegram.org") == AppType.TELEGRAM

    def test_tiktok(self, svc):
        assert svc.sni_to_app("www.tiktok.com") == AppType.TIKTOK

    def test_spotify(self, svc):
        assert svc.sni_to_app("api.spotify.com") == AppType.SPOTIFY

    def test_discord(self, svc):
        assert svc.sni_to_app("discord.com") == AppType.DISCORD

    def test_github(self, svc):
        assert svc.sni_to_app("github.com") == AppType.GITHUB

    def test_cloudflare(self, svc):
        assert svc.sni_to_app("cloudflare.com") == AppType.CLOUDFLARE


# ---------------------------------------------------------------------------
# Zoom — no false positives
# ---------------------------------------------------------------------------

class TestZoomClassification:
    def test_zoom_us(self, svc):
        assert svc.sni_to_app("zoom.us") == AppType.ZOOM

    def test_zoom_subdomain(self, svc):
        assert svc.sni_to_app("us02web.zoom.us") == AppType.ZOOM

    def test_zoom_false_positive_blocked(self, svc):
        """customerzoom.example.com must NOT match Zoom after the fix."""
        result = svc.sni_to_app("customerzoom.example.com")
        assert result != AppType.ZOOM

    def test_zoominfo_not_zoom(self, svc):
        result = svc.sni_to_app("www.zoominfo.com")
        assert result != AppType.ZOOM


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_string(self, svc):
        assert svc.sni_to_app("") == AppType.UNKNOWN

    def test_none_like_empty(self, svc):
        # sni_to_app guards with `if not sni`
        assert svc.sni_to_app("") == AppType.UNKNOWN

    def test_unknown_domain_returns_https(self, svc):
        assert svc.sni_to_app("www.somerandomunknowndomain.io") == AppType.HTTPS

    def test_case_insensitive(self, svc):
        assert svc.sni_to_app("WWW.YOUTUBE.COM") == AppType.YOUTUBE
