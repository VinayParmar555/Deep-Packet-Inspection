import pytest
from unittest.mock import AsyncMock, patch


def make_mock_redis(sismember_return=False, smembers_return=None):
    mock = AsyncMock()
    mock.sismember = AsyncMock(return_value=sismember_return)
    mock.sadd = AsyncMock(return_value=1)
    mock.srem = AsyncMock(return_value=1)
    mock.smembers = AsyncMock(return_value=smembers_return or set())
    return mock


# ---------------------------------------------------------------------------
# IP rules
# ---------------------------------------------------------------------------

class TestIPRules:
    async def test_block_ip_calls_sadd(self):
        mock_redis = make_mock_redis()
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            await svc.block_ip("1.2.3.4")
            mock_redis.sadd.assert_called_once_with("blocked:ips", "1.2.3.4")

    async def test_is_ip_blocked_true(self):
        mock_redis = make_mock_redis(sismember_return=True)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            assert await svc.is_ip_blocked("1.2.3.4") is True

    async def test_is_ip_blocked_false(self):
        mock_redis = make_mock_redis(sismember_return=False)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            assert await svc.is_ip_blocked("9.9.9.9") is False

    async def test_unblock_ip_calls_srem(self):
        mock_redis = make_mock_redis()
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            await svc.unblock_ip("1.2.3.4")
            mock_redis.srem.assert_called_once_with("blocked:ips", "1.2.3.4")


# ---------------------------------------------------------------------------
# Domain rules — O(1) two-set pattern
# ---------------------------------------------------------------------------

class TestDomainRules:
    async def test_exact_domain_stored_in_exact_set(self):
        mock_redis = make_mock_redis()
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            await svc.block_domain("example.com")
            mock_redis.sadd.assert_called_once_with("blocked:domains:exact", "example.com")

    async def test_wildcard_domain_stored_in_wildcard_set(self):
        mock_redis = make_mock_redis()
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            await svc.block_domain("*.example.com")
            mock_redis.sadd.assert_called_once_with("blocked:domains:wildcard", "*.example.com")

    async def test_exact_match_uses_sismember(self):
        mock_redis = make_mock_redis(sismember_return=True)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            result = await svc.is_domain_blocked("example.com")
            assert result is True
            mock_redis.sismember.assert_called_once_with("blocked:domains:exact", "example.com")

    async def test_wildcard_match_uses_sismember(self):
        """mail.example.com should match *.example.com via sismember O(1)."""
        call_count = 0

        async def sismember_side_effect(key, value):
            nonlocal call_count
            call_count += 1
            # First call: exact → miss; second call: wildcard → hit
            return key == "blocked:domains:wildcard" and value == "*.example.com"

        mock_redis = AsyncMock()
        mock_redis.sismember = AsyncMock(side_effect=sismember_side_effect)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            result = await svc.is_domain_blocked("mail.example.com")
            assert result is True
            assert call_count == 2  # exact check + wildcard check (both O(1))

    async def test_domain_not_blocked(self):
        mock_redis = make_mock_redis(sismember_return=False)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            assert await svc.is_domain_blocked("safe.example.com") is False

    async def test_domain_lowercased_on_block(self):
        mock_redis = make_mock_redis()
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            await svc.block_domain("EXAMPLE.COM")
            mock_redis.sadd.assert_called_once_with("blocked:domains:exact", "example.com")


# ---------------------------------------------------------------------------
# App rules
# ---------------------------------------------------------------------------

class TestAppRules:
    async def test_block_app(self):
        mock_redis = make_mock_redis()
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            await svc.block_app("NETFLIX")
            mock_redis.sadd.assert_called_once_with("blocked:apps", "NETFLIX")

    async def test_is_app_blocked_true(self):
        mock_redis = make_mock_redis(sismember_return=True)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            assert await svc.is_app_blocked("NETFLIX") is True


# ---------------------------------------------------------------------------
# Combined should_block
# ---------------------------------------------------------------------------

class TestShouldBlock:
    async def test_blocks_on_ip_match(self):
        async def sismember(key, value):
            return key == "blocked:ips"

        mock_redis = AsyncMock()
        mock_redis.sismember = AsyncMock(side_effect=sismember)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            from app.schema.rule_schema import BlockType
            svc = RuleService()
            reason = await svc.should_block("1.2.3.4", 443, "HTTPS", None)
            assert reason is not None
            assert reason.type == BlockType.IP

    async def test_returns_none_when_nothing_blocked(self):
        mock_redis = make_mock_redis(sismember_return=False)
        with patch("app.services.rule_service.redis_client", return_value=mock_redis):
            from app.services.rule_service import RuleService
            svc = RuleService()
            reason = await svc.should_block("1.2.3.4", 443, "HTTPS", None)
            assert reason is None
