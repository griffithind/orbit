-- Record who an actor was, not only which credential they held.
--
-- actor_id is a token uuid. Answering "who retired that CA" therefore means
-- looking the uuid up in orbit.api_token — and if the token has since been
-- deleted, the answer is gone. An audit trail that needs a join against mutable
-- state to be legible is one that degrades over exactly the time period an
-- audit cares about.
--
-- actor_display holds the name as it was at the time of the action: a token
-- name today, an email address when an OIDC subject can authenticate. It is
-- denormalized on purpose. Renaming a token must not rewrite history, which is
-- the same reason this table has no UPDATE grant.

ALTER TABLE orbit.audit_log
    ADD COLUMN IF NOT EXISTS actor_display text;

COMMENT ON COLUMN orbit.audit_log.actor_display IS
    'Human-readable actor name captured at write time; never backfilled.';
