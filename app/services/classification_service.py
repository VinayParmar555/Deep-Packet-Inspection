from typing import Optional, Tuple
from app.services.connection import AppType


# ─────────────────────────────────────────────────────────────
# Flow cache for bidirectional session tracking (Problem 3)
# ─────────────────────────────────────────────────────────────

_flow_cache: dict[Tuple[Tuple[str, int], Tuple[str, int]], AppType] = {}


# ─────────────────────────────────────────────────────────────
# Domain-suffix → AppType mapping table
# ─────────────────────────────────────────────────────────────

DOMAIN_MAP: dict[str, AppType] = {
    # ── Google ────────────────────────────────────────────────
    "google.com":            AppType.GOOGLE,
    "googleapis.com":        AppType.GOOGLE,
    "gstatic.com":           AppType.GOOGLE,
    "gmail.com":             AppType.GOOGLE,
    "ggpht.com":             AppType.GOOGLE,
    "googleusercontent.com": AppType.GOOGLE,
    "googlevideo.com":       AppType.GOOGLE,
    "gvt1.com":              AppType.GOOGLE,
    "gvt2.com":              AppType.GOOGLE,
    "google-analytics.com":  AppType.GOOGLE,
    "googletagmanager.com":  AppType.GOOGLE,
    "doubleclick.net":       AppType.GOOGLE,

    # ── YouTube ───────────────────────────────────────────────
    "youtube.com":           AppType.YOUTUBE,
    "youtu.be":              AppType.YOUTUBE,
    "ytimg.com":             AppType.YOUTUBE,
    "yt3.ggpht.com":         AppType.YOUTUBE,

    # ── Microsoft ─────────────────────────────────────────────
    "microsoft.com":         AppType.MICROSOFT,
    "office.com":            AppType.MICROSOFT,
    "office365.com":         AppType.MICROSOFT,
    "live.com":              AppType.MICROSOFT,
    "outlook.com":           AppType.MICROSOFT,
    "azure.com":             AppType.MICROSOFT,
    "microsoftonline.com":   AppType.MICROSOFT,
    "skype.com":             AppType.MICROSOFT,
    "teams.com":             AppType.MICROSOFT,
    "msn.com":               AppType.MICROSOFT,
    "bing.com":              AppType.MICROSOFT,
    "windows.net":           AppType.MICROSOFT,
    "msedge.net":            AppType.MICROSOFT,

    # ── Amazon / AWS ──────────────────────────────────────────
    "amazon.com":            AppType.AMAZON,
    "amazonaws.com":         AppType.AMAZON,
    "cloudfront.net":        AppType.AMAZON,
    "awsstatic.com":         AppType.AMAZON,
    "aws":                   AppType.AMAZON,

    # ── Meta / Facebook ───────────────────────────────────────
    "facebook.com":          AppType.FACEBOOK,
    "fb.com":                AppType.FACEBOOK,
    "fbcdn.net":             AppType.FACEBOOK,
    "fbsbx.com":             AppType.FACEBOOK,
    "meta.com":              AppType.FACEBOOK,

    # ── Instagram ─────────────────────────────────────────────
    "instagram.com":         AppType.INSTAGRAM,
    "cdninstagram.com":      AppType.INSTAGRAM,

    # ── WhatsApp ──────────────────────────────────────────────
    "whatsapp.com":          AppType.WHATSAPP,
    "whatsapp.net":          AppType.WHATSAPP,
    "wa.me":                 AppType.WHATSAPP,

    # ── Apple ─────────────────────────────────────────────────
    "apple.com":             AppType.APPLE,
    "icloud.com":            AppType.APPLE,
    "mzstatic.com":          AppType.APPLE,
    "itunes.com":            AppType.APPLE,

    # ── Cloudflare ────────────────────────────────────────────
    "cloudflare.com":        AppType.CLOUDFLARE,
    "cloudflare-dns.com":    AppType.CLOUDFLARE,

    # ── GitHub ────────────────────────────────────────────────
    "github.com":            AppType.GITHUB,
    "githubusercontent.com": AppType.GITHUB,
    "githubassets.com":      AppType.GITHUB,

    # ── Twitter / X ───────────────────────────────────────────
    "twitter.com":           AppType.TWITTER,
    "x.com":                 AppType.TWITTER,
    "twimg.com":             AppType.TWITTER,
    "t.co":                  AppType.TWITTER,

    # ── Netflix ───────────────────────────────────────────────
    "netflix.com":           AppType.NETFLIX,
    "nflxvideo.net":         AppType.NETFLIX,
    "nflximg.net":           AppType.NETFLIX,

    # ── Zoom ──────────────────────────────────────────────────
    "zoom.us":               AppType.ZOOM,
    "zoomgov.com":           AppType.ZOOM,

    # ── Telegram ──────────────────────────────────────────────
    "telegram.org":          AppType.TELEGRAM,
    "telegram.me":           AppType.TELEGRAM,
    "t.me":                  AppType.TELEGRAM,

    # ── TikTok ────────────────────────────────────────────────
    "tiktok.com":            AppType.TIKTOK,
    "tiktokcdn.com":         AppType.TIKTOK,
    "musical.ly":            AppType.TIKTOK,
    "bytedance.com":         AppType.TIKTOK,

    # ── Spotify ───────────────────────────────────────────────
    "spotify.com":           AppType.SPOTIFY,
    "scdn.co":               AppType.SPOTIFY,

    # ── Discord ───────────────────────────────────────────────
    "discord.com":           AppType.DISCORD,
    "discordapp.com":        AppType.DISCORD,
    "discord.gg":            AppType.DISCORD,

    # ── Akamai ────────────────────────────────────────────────
    "akamai.com":            AppType.AKAMAI,
    "akamaized.net":         AppType.AKAMAI,
    "akamaihd.net":          AppType.AKAMAI,

    # ── Fastly ────────────────────────────────────────────────
    "fastly.net":            AppType.FASTLY,
    "fastlylabs.com":        AppType.FASTLY,

    # ── Zoom ──────────────────────────────────────────────────
    # (Additional Zoom domains from traffic capture)
    "explore.zoom.us":       AppType.ZOOM,
    "st1.zoom.us":           AppType.ZOOM,

    # ── LinkedIn ─────────────────────────────────────────────
    "linkedin.com":          AppType.LINKEDIN,
    "ads.linkedin.com":      AppType.LINKEDIN,

    # ── Analytics Services ───────────────────────────────────
    "amplitude.com":         AppType.ANALYTICS,
    "contentsquare.net":     AppType.ANALYTICS,
    "knotch.it":             AppType.ANALYTICS,

    # ── Sentry (Error Tracking) ──────────────────────────────
    "sentry.io":             AppType.SENTRY,
    "ingest.us.sentry.io":   AppType.SENTRY,

    # ── Supabase (Cloud DB) ──────────────────────────────────
    "supabase.com":          AppType.SUPABASE,
    "supabase.io":           AppType.SUPABASE,

    # ── CDN Services ─────────────────────────────────────────
    "website-files.com":     AppType.CDN,
    "prod.website-files.com": AppType.CDN,

    # ── Microsoft (Additional domains from traffic capture) ──
    "msn.com":               AppType.MICROSOFT,
    "data.microsoft.com":    AppType.MICROSOFT,
    "events.data.microsoft.com": AppType.MICROSOFT,
    "vscode-cdn.net":        AppType.MICROSOFT,
}

# ─────────────────────────────────────────────────────────────
# Known IP → AppType mapping (expanded for Problem 2)
# ─────────────────────────────────────────────────────────────

IP_MAP: dict[str, AppType] = {
    # DNS servers
    "8.8.8.8":   AppType.GOOGLE_DNS,
    "8.8.4.4":   AppType.GOOGLE_DNS,
    "1.1.1.1":   AppType.CLOUDFLARE_DNS,
    "1.0.0.1":   AppType.CLOUDFLARE_DNS,
    # Cloudflare
    "162.159.130.233": AppType.CLOUDFLARE,
    "162.159.128.233": AppType.CLOUDFLARE,
    "104.18.17.5":     AppType.CLOUDFLARE,
    # GitHub
    "185.199.108.154": AppType.GITHUB,
    "185.199.108.133": AppType.GITHUB,
    "140.82.114.21":   AppType.GITHUB,
    "140.82.114.26":   AppType.GITHUB,
    # Microsoft Azure
    "20.207.73.82":    AppType.MICROSOFT,
    "20.42.65.91":     AppType.MICROSOFT,
    # AWS
    "3.254.238.10":    AppType.AMAZON,
    "3.254.238.163":   AppType.AMAZON,
    "3.248.124.234":   AppType.AMAZON,
    "44.215.143.203":  AppType.AMAZON,
}

# ─────────────────────────────────────────────────────────────
# IP prefix → AppType mapping for range-based classification
# ─────────────────────────────────────────────────────────────

IP_PREFIX_MAP: dict[str, AppType] = {
    "162.159.": AppType.CLOUDFLARE,
    "104.18.":  AppType.CLOUDFLARE,
    "140.82.":  AppType.GITHUB,
    "185.199.": AppType.GITHUB,
    "20.":      AppType.MICROSOFT,  # Azure range
    "13.":      AppType.AMAZON,     # AWS range
    "52.":      AppType.AMAZON,
    "54.":      AppType.AMAZON,
    "3.":       AppType.AMAZON,
}

# ─────────────────────────────────────────────────────────────
# Local network infrastructure IPs (from ipconfig)
# ─────────────────────────────────────────────────────────────

# My machine IP (Wi-Fi adapter)
MY_MACHINE_IP = "10.80.115.1"

# Default gateway/router IP
GATEWAY_IP = "10.80.115.84"

LOCAL_INFRASTRUCTURE: dict[str, str] = {
    MY_MACHINE_IP:   "MY_MACHINE",      # My own machine (Wi-Fi IP)
    GATEWAY_IP:      "GATEWAY",         # Default gateway/router - transparent
    "172.21.112.1":  "WSL_INTERFACE",   # WSL network interface
}

# IPs that should be "transparent" - classify by the OTHER endpoint
# Gateway just forwards packets, so we look at the non-gateway endpoint
_TRANSPARENT_IPS = {GATEWAY_IP}

# ─────────────────────────────────────────────────────────────
# Port → AppType fallback mapping
# ─────────────────────────────────────────────────────────────

PORT_MAP: dict[int, AppType] = {
    443:  AppType.HTTPS,
    80:   AppType.HTTP,
    53:   AppType.DNS,
    22:   AppType.SSH,
    25:   AppType.EMAIL,
    465:  AppType.EMAIL,
    587:  AppType.EMAIL,
    3478: AppType.STUN_VOIP,
    3479: AppType.STUN_VOIP,
    8080: AppType.HTTP_ALT,
    8443: AppType.HTTP_ALT,
}

# Well-known ports for bidirectional port classification (Problem 1)
_WELL_KNOWN_MAX = 1024
_KNOWN_PORTS = {443, 80, 53, 22, 25, 465, 587, 3478, 3479, 8080, 8443}

# Pre-sort domains by length descending so longer (more specific) suffixes
# are checked first — e.g. "yt3.ggpht.com" before "ggpht.com".
_SORTED_DOMAINS = sorted(DOMAIN_MAP.keys(), key=len, reverse=True)

# Pre-sort IP prefixes by length descending for most specific match first
_SORTED_IP_PREFIXES = sorted(IP_PREFIX_MAP.keys(), key=len, reverse=True)


class ClassificationService:
    """
    Classifies network traffic by application.

    Priority order:
        1. Flow cache lookup (bidirectional session memory)
        2. Domain exact match
        3. Domain suffix match
        4. Local infrastructure handling:
           - If dst is MY_MACHINE (10.80.115.1) → RESPONSE packet, classify by src
           - If src is MY_MACHINE (10.80.115.1) → REQUEST packet, classify by dst
           - If src or dst is GATEWAY (10.80.115.84) → look at OTHER endpoint
        5. Exact IP match (IP_MAP)
        6. IP prefix match (IP_PREFIX_MAP)
        7. Port-based fallback (checks both src + dst port)
        8. INTERNAL only if BOTH endpoints are private IPs (not my machine/gateway)
           AND no port classification matches
        9. UNKNOWN

    Network configuration:
        - 10.80.115.1   → MY_MACHINE (Wi-Fi IP)
        - 10.80.115.84  → GATEWAY (default gateway/router - transparent)
        - 172.21.112.1  → WSL (WSL interface)
    """

    # ── Flow key helper (Problem 3) ───────────────────────────

    @staticmethod
    def _get_flow_key(
        src_ip: str, dst_ip: str, src_port: int, dst_port: int
    ) -> Tuple[Tuple[str, int], Tuple[str, int]]:
        """Generate bidirectional flow key — same key regardless of direction."""
        return tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))

    # ── Port selection helper (Problem 1) ─────────────────────

    @staticmethod
    def _get_port_for_classification(
        src_port: Optional[int], dst_port: Optional[int]
    ) -> Optional[int]:
        """
        Select the best port for classification.
        Handles response packets with ephemeral dst_port.
        """
        if dst_port is None and src_port is None:
            return None

        dst = dst_port or 0
        src = src_port or 0

        # Prefer well-known ports (< 1024)
        if dst < _WELL_KNOWN_MAX and dst > 0:
            return dst
        if src < _WELL_KNOWN_MAX and src > 0:
            return src

        # Check extended well-known ports
        if dst in _KNOWN_PORTS:
            return dst
        if src in _KNOWN_PORTS:
            return src

        # Fallback to dst_port
        return dst_port

    # ── Private IP check (Problem 2) ──────────────────────────

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private/internal range (excluding my machine and gateway)."""
        # My machine and gateway are NOT considered generic private IPs
        # They have special handling in _classify_with_local_awareness
        if ip == MY_MACHINE_IP or ip == GATEWAY_IP:
            return False

        # Known infrastructure IPs are handled separately
        if ip in LOCAL_INFRASTRUCTURE:
            return False

        if ip.startswith("10."):
            return True
        if ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            # 172.16.0.0 - 172.31.255.255
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (IndexError, ValueError):
                pass
        if ip.startswith("127."):
            return True
        return False

    # ── Local infrastructure classification ───────────────────

    @staticmethod
    def _classify_local_infrastructure(ip: str) -> Optional[AppType]:
        """
        Classify known local infrastructure IPs.
        Returns None if IP should be "transparent" (classify by other endpoint).
        """
        infra_type = LOCAL_INFRASTRUCTURE.get(ip)
        if not infra_type:
            return None

        if infra_type == "MY_MACHINE":
            # My machine should NOT be classified as LOCAL/INTERNAL
            # Instead, return None so we classify by the OTHER endpoint
            return None
        if infra_type == "GATEWAY":
            # Gateway is transparent - return None to look at other endpoint
            return None
        if infra_type == "WSL_INTERFACE":
            return AppType.WSL

        return None

    # ── IP classification helper (Problem 2) ──────────────────

    @staticmethod
    def _classify_by_ip_simple(ip: str) -> AppType:
        """Classify by IP without private IP handling (used for remote endpoint lookup)."""
        # 1: Exact IP match
        exact = IP_MAP.get(ip)
        if exact:
            return exact

        # 2: IP prefix match (most specific first)
        for prefix in _SORTED_IP_PREFIXES:
            if ip.startswith(prefix):
                return IP_PREFIX_MAP[prefix]

        return AppType.UNKNOWN

    @staticmethod
    def _classify_by_ip(ip: str) -> AppType:
        """Classify by IP: exact match → prefix match only (no private IP check)."""
        # 1: Check if this is known local infrastructure
        infra_result = ClassificationService._classify_local_infrastructure(ip)
        if infra_result is not None:
            return infra_result

        # 2: Exact IP match
        exact = IP_MAP.get(ip)
        if exact:
            return exact

        # 3: IP prefix match (most specific first)
        for prefix in _SORTED_IP_PREFIXES:
            if ip.startswith(prefix):
                return IP_PREFIX_MAP[prefix]

        # Note: Private IP check is done at the end of classify_packet
        # to allow port-based classification to take precedence
        return AppType.UNKNOWN

    # ── Smart classification for local traffic ────────────────

    def _classify_with_local_awareness(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
    ) -> AppType:
        """
        Smart classification that handles local infrastructure IPs.
        
        Logic:
        1. If dst is MY_MACHINE (10.80.115.1) → RESPONSE packet
           - Classify by src IP using IP_MAP/IP_PREFIX_MAP
           - If not found, classify by src_port
           - Never label as INTERNAL
        
        2. If src is MY_MACHINE (10.80.115.1) → REQUEST packet
           - Classify by dst IP using IP_MAP/IP_PREFIX_MAP
           - If not found, classify by dst_port
           - Never label as INTERNAL
        
        3. If src or dst is GATEWAY (10.80.115.84):
           - Gateway just forwards, look at the OTHER endpoint
           - Classify by the non-gateway IP/port
           - Never label as INTERNAL
        
        4. INTERNAL only if BOTH endpoints are private IPs that are NOT
           my machine or gateway, AND no port classification matches
        """
        # Check for WSL interface
        if src_ip == "172.21.112.1" or dst_ip == "172.21.112.1":
            return AppType.WSL

        # Case 1: Inbound to my machine (RESPONSE packet)
        if dst_ip == MY_MACHINE_IP:
            # Classify by src (remote endpoint)
            if src_ip and src_ip != GATEWAY_IP:
                result = self._classify_by_ip_simple(src_ip)
                if result is not AppType.UNKNOWN:
                    return result
            # Fallback to src_port (service port of the remote server)
            if src_port:
                result = PORT_MAP.get(src_port)
                if result:
                    return result
            # Also try dst_port in case src_port is ephemeral
            if dst_port:
                result = PORT_MAP.get(dst_port)
                if result:
                    return result
            # Never return INTERNAL for traffic to/from my machine
            return AppType.UNKNOWN

        # Case 2: Outbound from my machine (REQUEST packet)
        if src_ip == MY_MACHINE_IP:
            # Classify by dst (remote endpoint)
            if dst_ip and dst_ip != GATEWAY_IP:
                result = self._classify_by_ip_simple(dst_ip)
                if result is not AppType.UNKNOWN:
                    return result
            # Fallback to dst_port (service port we're connecting to)
            if dst_port:
                result = PORT_MAP.get(dst_port)
                if result:
                    return result
            # Also try src_port
            if src_port:
                result = PORT_MAP.get(src_port)
                if result:
                    return result
            # Never return INTERNAL for traffic to/from my machine
            return AppType.UNKNOWN

        # Case 3: Gateway involvement - look at the OTHER endpoint
        src_is_gateway = (src_ip == GATEWAY_IP)
        dst_is_gateway = (dst_ip == GATEWAY_IP)

        if src_is_gateway and dst_ip:
            # Gateway is src, classify by dst
            result = self._classify_by_ip_simple(dst_ip)
            if result is not AppType.UNKNOWN:
                return result
            # Fallback to port
            if dst_port:
                result = PORT_MAP.get(dst_port)
                if result:
                    return result
            if src_port:
                result = PORT_MAP.get(src_port)
                if result:
                    return result
            return AppType.UNKNOWN

        if dst_is_gateway and src_ip:
            # Gateway is dst, classify by src
            result = self._classify_by_ip_simple(src_ip)
            if result is not AppType.UNKNOWN:
                return result
            # Fallback to port
            if src_port:
                result = PORT_MAP.get(src_port)
                if result:
                    return result
            if dst_port:
                result = PORT_MAP.get(dst_port)
                if result:
                    return result
            return AppType.UNKNOWN

        # Both are gateway (unlikely but handle it)
        if src_is_gateway and dst_is_gateway:
            port = self._get_port_for_classification(src_port, dst_port)
            if port:
                result = PORT_MAP.get(port)
                if result:
                    return result
            return AppType.GATEWAY

        return AppType.UNKNOWN

    # ── Primary entrypoint ────────────────────────────────────

    def classify_packet(
        self,
        domain: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
    ) -> AppType:
        """
        Classify a packet by domain, IP, or port.
        
        Priority:
        1. Flow cache lookup (bidirectional session memory)
        2. Domain-based classification
        3. Local infrastructure handling
        4. IP-based classification (exact, then prefix)
        5. Port-based fallback
        6. Private IP detection (INTERNAL)
        7. UNKNOWN
        """
        # ── Step 0: Flow cache lookup (Problem 3) ──────────────────
        if src_ip and dst_ip and src_port and dst_port:
            flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port)
            cached = _flow_cache.get(flow_key)
            if cached:
                return cached

        # ── Step 1: Domain-based classification ────────────────────
        if domain:
            result = self._classify_by_domain(domain)
            if result is not AppType.UNKNOWN:
                self._cache_flow(src_ip, dst_ip, src_port, dst_port, result)
                return result

        # ── Step 2: Local-to-local detection ───────────────────────
        if src_ip and dst_ip and src_ip == dst_ip:
            return AppType.LOCAL

        # ── Step 3: Local infrastructure handling ──────────────────
        local_result = self._classify_with_local_awareness(
            src_ip, dst_ip, src_port, dst_port
        )
        if local_result is not AppType.UNKNOWN:
            self._cache_flow(src_ip, dst_ip, src_port, dst_port, local_result)
            return local_result

        # ── Step 4: IP-based classification (dst first, then src) ──
        if dst_ip:
            result = self._classify_by_ip(dst_ip)
            if result is not AppType.UNKNOWN:
                self._cache_flow(src_ip, dst_ip, src_port, dst_port, result)
                return result

        if src_ip:
            result = self._classify_by_ip(src_ip)
            if result is not AppType.UNKNOWN:
                self._cache_flow(src_ip, dst_ip, src_port, dst_port, result)
                return result

        # ── Step 5: Private IP check (for internal-to-internal traffic) ───
        # BOTH endpoints must be private for INTERNAL classification
        src_is_private = src_ip and self._is_private_ip(src_ip)
        dst_is_private = dst_ip and self._is_private_ip(dst_ip)
        
        if src_is_private and dst_is_private:
            return AppType.INTERNAL

        # ── Step 6: Port-based fallback (Problem 1) ────────────────
        port = self._get_port_for_classification(src_port, dst_port)
        if port:
            result = PORT_MAP.get(port)
            if result:
                self._cache_flow(src_ip, dst_ip, src_port, dst_port, result)
                return result

        # ── Step 7: Single private IP with no port match ───────────
        # If only one endpoint is private and no port classification, 
        # return INTERNAL as a fallback
        if src_is_private or dst_is_private:
            return AppType.INTERNAL

        return AppType.UNKNOWN

    # ── Cache helper (Problem 3) ──────────────────────────────

    def _cache_flow(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        app_type: AppType,
    ) -> None:
        """Store classification result in flow cache."""
        if src_ip and dst_ip and src_port and dst_port:
            flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port)
            _flow_cache[flow_key] = app_type

    # ── Flow cache management ─────────────────────────────────

    @staticmethod
    def clear_flow_cache() -> None:
        """Clear the flow cache (useful for testing or memory management)."""
        _flow_cache.clear()

    @staticmethod
    def get_flow_cache_size() -> int:
        """Return current size of flow cache."""
        return len(_flow_cache)

    # ── Backward-compatible wrapper ───────────────────────────

    def sni_to_app(self, sni: str) -> AppType:
        """
        Legacy method — kept so existing callers and tests work unchanged.
        Delegates to classify_packet with domain only.
        """
        if not sni:
            return AppType.UNKNOWN

        result = self._classify_by_domain(sni)
        if result is not AppType.UNKNOWN:
            return result

        # Original behaviour: known SNI but unrecognised app → HTTPS
        return AppType.HTTPS

    # ── Internal helpers ──────────────────────────────────────

    @staticmethod
    def _classify_by_domain(domain: str) -> AppType:
        lower = domain.lower().rstrip(".")

        # 1: Exact match
        exact = DOMAIN_MAP.get(lower)
        if exact:
            return exact

        # 2: Subdomain suffix match (e.g. "mail.google.com" → google.com)
        for known_domain in _SORTED_DOMAINS:
            if lower.endswith("." + known_domain):
                return DOMAIN_MAP[known_domain]

        return AppType.UNKNOWN