from app.services.connection import AppType

class ClassificationService:

    def sni_to_app(self, sni: str) -> AppType:
        if not sni:
            return AppType.UNKNOWN

        lower_sni = sni.lower()

        # Google
        if any(x in lower_sni for x in [
            "google", "gstatic", "googleapis",
            "ggpht", "gvt1"
        ]):
            return AppType.GOOGLE

        # YouTube
        if any(x in lower_sni for x in [
            "youtube", "ytimg", "youtu.be", "yt3.ggpht"
        ]):
            return AppType.YOUTUBE

        # Facebook
        if any(x in lower_sni for x in [
            "facebook", "fbcdn", "fb.com", "fbsbx", "meta.com"
        ]):
            return AppType.FACEBOOK

        # Instagram
        if any(x in lower_sni for x in [
            "instagram", "cdninstagram"
        ]):
            return AppType.INSTAGRAM

        # WhatsApp
        if any(x in lower_sni for x in [
            "whatsapp", "wa.me"
        ]):
            return AppType.WHATSAPP

        # Twitter / X
        if any(x in lower_sni for x in [
            "twitter", "twimg", "x.com", "t.co"
        ]):
            return AppType.TWITTER

        # Netflix
        if any(x in lower_sni for x in [
            "netflix", "nflxvideo", "nflximg"
        ]):
            return AppType.NETFLIX

        # Amazon
        if any(x in lower_sni for x in [
            "amazon", "amazonaws", "cloudfront", "aws"
        ]):
            return AppType.AMAZON

        # Microsoft
        if any(x in lower_sni for x in [
            "microsoft", "msn.com", "office",
            "azure", "live.com", "outlook", "bing"
        ]):
            return AppType.MICROSOFT

        # Apple
        if any(x in lower_sni for x in [
            "apple", "icloud", "mzstatic", "itunes"
        ]):
            return AppType.APPLE

        # Telegram
        if any(x in lower_sni for x in [
            "telegram", "t.me"
        ]):
            return AppType.TELEGRAM

        # TikTok
        if any(x in lower_sni for x in [
            "tiktok", "tiktokcdn", "musical.ly", "bytedance"
        ]):
            return AppType.TIKTOK

        # Spotify
        if any(x in lower_sni for x in [
            "spotify", "scdn.co"
        ]):
            return AppType.SPOTIFY

        # Zoom
        if "zoom" in lower_sni:
            return AppType.ZOOM

        # Discord
        if any(x in lower_sni for x in [
            "discord", "discordapp"
        ]):
            return AppType.DISCORD

        # GitHub
        if any(x in lower_sni for x in [
            "github", "githubusercontent"
        ]):
            return AppType.GITHUB

        # Cloudflare
        if any(x in lower_sni for x in [
            "cloudflare", "cf-"
        ]):
            return AppType.CLOUDFLARE

        # If SNI present but unknown → HTTPS
        return AppType.HTTPS