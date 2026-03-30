import pytest
from app.services.classification_service import ClassificationService
from app.schema.connection_schema import AppType


@pytest.fixture
def svc():
    # Clear flow cache before each test for isolation
    ClassificationService.clear_flow_cache()
    return ClassificationService()


# ---------------------------------------------------------------------------
# Known app mappings (legacy sni_to_app — backward compat)
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


# ---------------------------------------------------------------------------
# NEW: Expanded domain mappings
# ---------------------------------------------------------------------------

class TestExpandedDomains:
    """Verify the new domain mappings added in the expanded table."""

    @pytest.mark.parametrize("domain, expected", [
        # Google family
        ("googleusercontent.com", AppType.GOOGLE),
        ("translate.googleapis.com", AppType.GOOGLE),
        ("fonts.gstatic.com", AppType.GOOGLE),
        ("mail.gmail.com", AppType.GOOGLE),
        ("lh3.googleusercontent.com", AppType.GOOGLE),

        # YouTube
        ("r1---sn-abc.googlevideo.com", AppType.GOOGLE),  # googlevideo → Google
        ("youtu.be", AppType.YOUTUBE),

        # Microsoft
        ("login.office.com", AppType.MICROSOFT),
        ("outlook.office365.com", AppType.MICROSOFT),
        ("login.live.com", AppType.MICROSOFT),
        ("portal.azure.com", AppType.MICROSOFT),
        ("teams.com", AppType.MICROSOFT),
        ("app.teams.com", AppType.MICROSOFT),
        ("login.skype.com", AppType.MICROSOFT),

        # Amazon / AWS
        ("s3.amazonaws.com", AppType.AMAZON),
        ("d1234.cloudfront.net", AppType.AMAZON),
        ("images.awsstatic.com", AppType.AMAZON),

        # Meta
        ("fbcdn.net", AppType.FACEBOOK),
        ("static.xx.fbcdn.net", AppType.FACEBOOK),
        ("meta.com", AppType.FACEBOOK),

        # Apple
        ("icloud.com", AppType.APPLE),
        ("p32.mzstatic.com", AppType.APPLE),

        # Cloudflare
        ("cloudflare-dns.com", AppType.CLOUDFLARE),

        # GitHub
        ("raw.githubusercontent.com", AppType.GITHUB),
        ("github.githubassets.com", AppType.GITHUB),

        # Netflix
        ("nflxvideo.net", AppType.NETFLIX),
        ("assets.nflximg.net", AppType.NETFLIX),

        # Twitter / X
        ("pbs.twimg.com", AppType.TWITTER),
        ("api.x.com", AppType.TWITTER),

        # Zoom
        ("zoomgov.com", AppType.ZOOM),
        ("us02web.zoom.us", AppType.ZOOM),

        # Akamai
        ("akamai.com", AppType.AKAMAI),
        ("cdn.akamaized.net", AppType.AKAMAI),
        ("ss.akamaihd.net", AppType.AKAMAI),

        # Fastly
        ("fastly.net", AppType.FASTLY),
        ("cdn.fastlylabs.com", AppType.FASTLY),
    ])
    def test_expanded_domain(self, svc, domain, expected):
        assert svc.sni_to_app(domain) == expected


# ---------------------------------------------------------------------------
# NEW: Subdomain suffix matching
# ---------------------------------------------------------------------------

class TestSubdomainMatching:
    """Subdomain suffixes should match the parent domain entry."""

    @pytest.mark.parametrize("domain, expected", [
        ("mail.google.com", AppType.GOOGLE),
        ("deep.nested.sub.google.com", AppType.GOOGLE),
        ("api.github.com", AppType.GITHUB),
        ("chat.whatsapp.com", AppType.WHATSAPP),
        ("app.discord.com", AppType.DISCORD),
        ("cdn.netflix.com", AppType.NETFLIX),
        ("signin.aws", AppType.AMAZON),
    ])
    def test_subdomain_match(self, svc, domain, expected):
        assert svc.sni_to_app(domain) == expected

    def test_trailing_dot_stripped(self, svc):
        """FQDN with trailing dot should still match."""
        assert svc.sni_to_app("www.google.com.") == AppType.GOOGLE


# ---------------------------------------------------------------------------
# NEW: Port-based fallback classification
# ---------------------------------------------------------------------------

class TestPortFallback:
    """When no domain is available, classification falls back to port."""

    @pytest.mark.parametrize("port, expected", [
        (443,  AppType.HTTPS),
        (80,   AppType.HTTP),
        (53,   AppType.DNS),
        (22,   AppType.SSH),
        (25,   AppType.EMAIL),
        (465,  AppType.EMAIL),
        (587,  AppType.EMAIL),
        (3478, AppType.STUN_VOIP),
        (3479, AppType.STUN_VOIP),
        (8080, AppType.HTTP_ALT),
        (8443, AppType.HTTP_ALT),
    ])
    def test_port_fallback(self, svc, port, expected):
        assert svc.classify_packet(domain=None, dst_port=port) == expected

    def test_unknown_port_returns_unknown(self, svc):
        assert svc.classify_packet(domain=None, dst_port=9999) == AppType.UNKNOWN


# ---------------------------------------------------------------------------
# NEW: DNS IP-based classification
# ---------------------------------------------------------------------------

class TestDNSIPClassification:
    """Known DNS IPs should classify correctly when no domain is available."""

    @pytest.mark.parametrize("ip, expected", [
        ("8.8.8.8", AppType.GOOGLE_DNS),
        ("8.8.4.4", AppType.GOOGLE_DNS),
        ("1.1.1.1", AppType.CLOUDFLARE_DNS),
        ("1.0.0.1", AppType.CLOUDFLARE_DNS),
    ])
    def test_ip_classification(self, svc, ip, expected):
        assert svc.classify_packet(domain=None, dst_ip=ip) == expected

    def test_unknown_ip_with_port(self, svc):
        """Unknown IP with known port should fall back to port classification."""
        assert svc.classify_packet(
            domain=None, dst_port=443, dst_ip="192.168.1.1"
        ) == AppType.HTTPS


# ---------------------------------------------------------------------------
# NEW: Priority order
# ---------------------------------------------------------------------------

class TestPriorityOrder:
    """Domain match > IP match > Port match."""

    def test_domain_beats_port(self, svc):
        """When domain is known, it wins over the port classification."""
        result = svc.classify_packet(
            domain="www.google.com", dst_port=443
        )
        assert result == AppType.GOOGLE

    def test_domain_beats_ip(self, svc):
        """When domain is known, it wins over IP classification."""
        result = svc.classify_packet(
            domain="www.netflix.com", dst_ip="8.8.8.8"
        )
        assert result == AppType.NETFLIX

    def test_ip_beats_port(self, svc):
        """When IP is known, it wins over port fallback."""
        result = svc.classify_packet(
            domain=None, dst_port=53, dst_ip="8.8.8.8"
        )
        assert result == AppType.GOOGLE_DNS

    def test_all_none_returns_unknown(self, svc):
        assert svc.classify_packet() == AppType.UNKNOWN


# ---------------------------------------------------------------------------
# NEW: Domains extracted from new_traffic.pcap
# ---------------------------------------------------------------------------

class TestExtractedPcapDomains:
    """Verify classification of domains extracted from new_traffic.pcap."""

    @pytest.mark.parametrize("domain, expected", [
        # Analytics
        ("api2.amplitude.com", AppType.ANALYTICS),
        ("c.contentsquare.net", AppType.ANALYTICS),
        ("frontdoor.knotch.it", AppType.ANALYTICS),

        # Microsoft family
        ("assets.msn.com", AppType.MICROSOFT),
        ("browser.events.data.microsoft.com", AppType.MICROSOFT),
        ("mobile.events.data.microsoft.com", AppType.MICROSOFT),
        ("self.events.data.microsoft.com", AppType.MICROSOFT),
        ("settings-win.data.microsoft.com", AppType.MICROSOFT),
        ("v10.events.data.microsoft.com", AppType.MICROSOFT),
        ("v20.events.data.microsoft.com", AppType.MICROSOFT),
        ("teams.microsoft.com", AppType.MICROSOFT),
        ("main.vscode-cdn.net", AppType.MICROSOFT),

        # Zoom
        ("explore.zoom.us", AppType.ZOOM),
        ("st1.zoom.us", AppType.ZOOM),
        ("zoom.us", AppType.ZOOM),

        # LinkedIn
        ("px.ads.linkedin.com", AppType.LINKEDIN),

        # Sentry
        ("o64374.ingest.us.sentry.io", AppType.SENTRY),

        # Supabase
        ("configcat.supabase.com", AppType.SUPABASE),

        # CDN
        ("cdn.prod.website-files.com", AppType.CDN),

        # Google
        ("content-autofill.googleapis.com", AppType.GOOGLE),

        # GitHub
        ("viewscreen.githubusercontent.com", AppType.GITHUB),

        # YouTube
        ("yt3.ggpht.com", AppType.YOUTUBE),
    ])
    def test_pcap_domain(self, svc, domain, expected):
        assert svc.sni_to_app(domain) == expected


# ---------------------------------------------------------------------------
# NEW: Ephemeral port handling (Problem 1)
# ---------------------------------------------------------------------------

class TestEphemeralPortHandling:
    """Test bidirectional port classification for response packets."""

    def test_response_packet_with_ephemeral_dst_port(self, svc):
        """Response packet: dst_port=58942 (ephemeral), src_port=443 (HTTPS)."""
        result = svc.classify_packet(
            src_port=443, dst_port=58942,
            src_ip="93.184.216.34", dst_ip="192.168.1.100"
        )
        assert result == AppType.HTTPS

    def test_request_packet_dst_port_preferred(self, svc):
        """Request packet: dst_port=443 should be used."""
        result = svc.classify_packet(
            src_port=49672, dst_port=443,
            src_ip="192.168.1.100", dst_ip="93.184.216.34"
        )
        assert result == AppType.HTTPS

    def test_dns_response_packet(self, svc):
        """DNS response: dst_port=64016 (ephemeral), src_port=53 (DNS)."""
        result = svc.classify_packet(
            src_port=53, dst_port=64016,
            src_ip="8.8.8.8", dst_ip="192.168.1.100"
        )
        # Should be GOOGLE_DNS due to IP match (higher priority than port)
        assert result == AppType.GOOGLE_DNS

    def test_ssh_response_packet(self, svc):
        """SSH response: dst_port=52341 (ephemeral), src_port=22 (SSH)."""
        result = svc.classify_packet(
            src_port=22, dst_port=52341,
            src_ip="10.0.0.5", dst_ip="192.168.1.100"
        )
        # Internal IP takes precedence
        assert result == AppType.INTERNAL

    def test_well_known_port_under_1024(self, svc):
        """Port < 1024 should be preferred."""
        result = svc.classify_packet(
            src_port=80, dst_port=45678,
            src_ip="203.0.113.50", dst_ip="192.168.1.100"
        )
        assert result == AppType.HTTP


# ---------------------------------------------------------------------------
# NEW: IP-based classification (Problem 2)
# ---------------------------------------------------------------------------

class TestIPClassification:
    """Test exact IP match, prefix match, and private IP detection."""

    @pytest.mark.parametrize("ip, expected", [
        # Exact matches
        ("162.159.130.233", AppType.CLOUDFLARE),
        ("185.199.108.154", AppType.GITHUB),
        ("140.82.114.21", AppType.GITHUB),
        ("20.207.73.82", AppType.MICROSOFT),
        ("3.254.238.10", AppType.AMAZON),
        ("44.215.143.203", AppType.AMAZON),
    ])
    def test_exact_ip_match(self, svc, ip, expected):
        result = svc.classify_packet(dst_ip=ip)
        assert result == expected

    @pytest.mark.parametrize("ip, expected", [
        # Prefix matches
        ("162.159.200.100", AppType.CLOUDFLARE),
        ("104.18.55.99", AppType.CLOUDFLARE),
        ("140.82.200.1", AppType.GITHUB),
        ("185.199.111.222", AppType.GITHUB),
        ("20.100.50.25", AppType.MICROSOFT),
        ("13.52.100.200", AppType.AMAZON),
        ("52.10.20.30", AppType.AMAZON),
        ("54.200.100.50", AppType.AMAZON),
        ("3.100.200.50", AppType.AMAZON),
    ])
    def test_ip_prefix_match(self, svc, ip, expected):
        result = svc.classify_packet(dst_ip=ip)
        assert result == expected

    @pytest.mark.parametrize("ip", [
        "10.0.0.1",
        "10.255.255.255",
        "192.168.0.1",
        "192.168.100.50",
        "172.16.0.1",
        "172.31.255.255",
        "127.0.0.1",
    ])
    def test_private_ip_classified_as_internal(self, svc, ip):
        result = svc.classify_packet(dst_ip=ip)
        assert result == AppType.INTERNAL

    def test_source_ip_also_checked(self, svc):
        """When dst_ip is private but src_ip is a known service, src_ip wins."""
        result = svc.classify_packet(
            src_ip="185.199.108.154",  # GitHub
            dst_ip="192.168.1.100",    # Private
            src_port=443, dst_port=52341
        )
        # src_ip is GitHub (known service) → GitHub wins over private dst
        assert result == AppType.GITHUB


# ---------------------------------------------------------------------------
# NEW: Flow cache / session memory (Problem 3)
# ---------------------------------------------------------------------------

class TestFlowCache:
    """Test bidirectional flow caching for session memory."""

    def test_flow_cached_after_classification(self, svc):
        """First packet classifies and caches; second uses cache."""
        # Clear cache
        ClassificationService.clear_flow_cache()
        assert ClassificationService.get_flow_cache_size() == 0

        # First classification
        result1 = svc.classify_packet(
            domain="www.google.com",
            src_ip="192.168.1.100", dst_ip="172.217.0.100",
            src_port=49672, dst_port=443
        )
        assert result1 == AppType.GOOGLE
        assert ClassificationService.get_flow_cache_size() == 1

        # Second packet (same flow) — should use cache
        result2 = svc.classify_packet(
            src_ip="192.168.1.100", dst_ip="172.217.0.100",
            src_port=49672, dst_port=443
        )
        assert result2 == AppType.GOOGLE

    def test_reverse_direction_uses_same_cache(self, svc):
        """Response packet (reversed src/dst) should hit same cache entry."""
        ClassificationService.clear_flow_cache()

        # Request direction
        svc.classify_packet(
            domain="www.netflix.com",
            src_ip="192.168.1.100", dst_ip="54.200.100.50",
            src_port=49672, dst_port=443
        )

        # Response direction (src/dst swapped)
        result = svc.classify_packet(
            src_ip="54.200.100.50", dst_ip="192.168.1.100",
            src_port=443, dst_port=49672
        )
        assert result == AppType.NETFLIX

    def test_different_flows_cached_separately(self, svc):
        """Different flows should have separate cache entries."""
        ClassificationService.clear_flow_cache()

        svc.classify_packet(
            domain="www.google.com",
            src_ip="192.168.1.100", dst_ip="172.217.0.100",
            src_port=49672, dst_port=443
        )
        svc.classify_packet(
            domain="www.netflix.com",
            src_ip="192.168.1.100", dst_ip="54.200.100.50",
            src_port=49673, dst_port=443
        )

        assert ClassificationService.get_flow_cache_size() == 2

    def test_clear_flow_cache(self, svc):
        """Cache can be cleared."""
        svc.classify_packet(
            domain="www.google.com",
            src_ip="192.168.1.100", dst_ip="172.217.0.100",
            src_port=49672, dst_port=443
        )
        assert ClassificationService.get_flow_cache_size() > 0

        ClassificationService.clear_flow_cache()
        assert ClassificationService.get_flow_cache_size() == 0


# ---------------------------------------------------------------------------
# NEW: Full classification priority order
# ---------------------------------------------------------------------------

class TestClassificationPriority:
    """Test the full priority order of classification."""

    def test_flow_cache_beats_everything(self, svc):
        """Cached flow result should be returned immediately."""
        ClassificationService.clear_flow_cache()

        # First: classify as Google
        svc.classify_packet(
            domain="www.google.com",
            src_ip="192.168.1.100", dst_ip="172.217.0.100",
            src_port=49672, dst_port=443
        )

        # Second: same flow, different domain — cache should win
        result = svc.classify_packet(
            domain="www.netflix.com",  # Would be NETFLIX without cache
            src_ip="192.168.1.100", dst_ip="172.217.0.100",
            src_port=49672, dst_port=443
        )
        assert result == AppType.GOOGLE

    def test_domain_beats_ip(self, svc):
        """Domain classification takes precedence over IP."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            domain="www.netflix.com",
            dst_ip="185.199.108.154",  # GitHub IP
        )
        assert result == AppType.NETFLIX

    def test_ip_beats_port(self, svc):
        """IP classification takes precedence over port."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            dst_ip="185.199.108.154",  # GitHub IP
            dst_port=80,               # Would be HTTP
        )
        assert result == AppType.GITHUB

    def test_private_ip_recognized(self, svc):
        """Private IP returns INTERNAL when no other match."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            dst_ip="192.168.1.1",
            dst_port=9999,  # Unknown port
        )
        assert result == AppType.INTERNAL


# ---------------------------------------------------------------------------
# NEW: Local infrastructure classification
# ---------------------------------------------------------------------------

class TestLocalInfrastructure:
    """Test classification of local network infrastructure IPs."""

    def test_campus_dns_classified_as_dns(self, svc):
        """Traffic to/from campus DNS resolver should be classified as DNS."""
        ClassificationService.clear_flow_cache()
        # Outbound to campus DNS
        result = svc.classify_packet(
            src_ip="10.8.232.122", dst_ip="10.80.115.84",
            src_port=52341, dst_port=53
        )
        assert result == AppType.DNS

    def test_campus_dns_response(self, svc):
        """DNS response from campus DNS should also be DNS."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            src_ip="10.80.115.84", dst_ip="10.8.232.122",
            src_port=53, dst_port=52341
        )
        assert result == AppType.DNS

    def test_wsl_interface_classified_as_wsl(self, svc):
        """Traffic involving WSL interface should be WSL."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            src_ip="172.21.112.1", dst_ip="10.8.232.122",
            src_port=8080, dst_port=49672
        )
        assert result == AppType.WSL

    def test_router_traffic_classifies_by_other_endpoint_cloudflare(self, svc):
        """Traffic via campus router should classify by the remote endpoint."""
        ClassificationService.clear_flow_cache()
        # My machine → Router → Cloudflare IP
        result = svc.classify_packet(
            src_ip="10.8.232.122", dst_ip="162.159.130.233",
            src_port=49672, dst_port=443
        )
        assert result == AppType.CLOUDFLARE

    def test_router_traffic_classifies_by_other_endpoint_github(self, svc):
        """Traffic via campus router with GitHub IP should be GITHUB."""
        ClassificationService.clear_flow_cache()
        # Response from GitHub via router
        result = svc.classify_packet(
            src_ip="185.199.108.154", dst_ip="10.8.232.122",
            src_port=443, dst_port=49672
        )
        assert result == AppType.GITHUB

    def test_gateway_traffic_classifies_by_remote_endpoint(self, svc):
        """Traffic via gateway (10.8.255.250) should classify by other endpoint."""
        ClassificationService.clear_flow_cache()
        # Outbound via gateway to AWS
        result = svc.classify_packet(
            src_ip="10.8.255.250", dst_ip="52.10.20.30",
            src_port=443, dst_port=49672
        )
        assert result == AppType.AMAZON

    def test_router_with_unknown_remote_falls_back_to_port(self, svc):
        """Router traffic with unknown remote IP falls back to port classification."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            src_ip="10.80.115.1", dst_ip="203.0.113.50",  # Unknown IP
            src_port=443, dst_port=49672
        )
        assert result == AppType.HTTPS

    def test_my_machine_outbound_classifies_by_dst(self, svc):
        """Outbound from my machine classifies by destination."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            src_ip="10.8.232.122", dst_ip="140.82.114.21",  # GitHub
            src_port=49672, dst_port=443
        )
        assert result == AppType.GITHUB

    def test_my_machine_inbound_classifies_by_src(self, svc):
        """Inbound to my machine classifies by source."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            src_ip="20.207.73.82", dst_ip="10.8.232.122",  # Microsoft Azure
            src_port=443, dst_port=49672
        )
        assert result == AppType.MICROSOFT

    def test_generic_private_ip_still_internal(self, svc):
        """Private IPs not in infrastructure list are still INTERNAL."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            dst_ip="10.99.99.99",  # Not in LOCAL_INFRASTRUCTURE
            dst_port=9999
        )
        assert result == AppType.INTERNAL

    def test_local_machine_to_local_machine(self, svc):
        """Traffic from my machine to itself should be LOCAL."""
        ClassificationService.clear_flow_cache()
        result = svc.classify_packet(
            src_ip="10.8.232.122", dst_ip="10.8.232.122",
            src_port=8080, dst_port=3000
        )
        assert result == AppType.LOCAL
