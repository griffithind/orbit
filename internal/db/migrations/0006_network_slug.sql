-- Network identity in three parts: id, slug, name.
--
-- orbit.network had two columns doing three jobs. `id` was the immutable key,
-- and `name` was both the label a human reads AND the value that is about to
-- become a filesystem path component (/var/lib/orbit/<slug>/), a systemd
-- instance name, and the stem of a tun device. Those two jobs have opposite
-- requirements: a label wants to be readable and editable, a path component
-- wants to be narrow and to never change.
--
-- Splitting them is the same move Tailscale makes between a tailnet's DNS name
-- and its display name, for the same reason: renaming what you show a person
-- must not rename what a machine has already written to disk.
--
--   id    uuid  immutable primary key, unchanged
--   slug  text  immutable, globally unique, machine-safe    <- NEW
--   name  text  mutable, unique, display only
--
-- ADDRESSING. A network is addressed by id or by slug, and by nothing else.
-- Both are immutable, so a script that memorised either keeps working across a
-- rename. The friendly name is deliberately NOT an addressing key: resolving by
-- a mutable string is precisely how a rename silently retargets automation, and
-- the failure is invisible until the wrong network is changed.
--
-- WHY THE UUID CONSTRAINT GOES. 0005 refused a network name shaped like a uuid,
-- because GET /v1/networks/{ref} tried uuid.Parse first and a uuid-shaped name
-- would either miss or resolve to a different network. That rule is now
-- unnecessary twice over:
--
--   * A slug can never look like a uuid. A uuid's canonical form is 36
--     characters and the slug charset below caps at 32, so the two forms are
--     disjoint by length alone, before a single character is compared. No
--     constraint is needed to say so.
--   * A name is no longer resolved at all, so a name that looks like a uuid can
--     no longer be mistaken for one.
--
-- What replaces it for `name` is not an addressing rule but a legibility one:
-- a display string that renders in a terminal, a CLI table, and an audit entry
-- without escaping. Hence the charset, the length bound, and the refusal of
-- leading or trailing whitespace — a name with a trailing space looks identical
-- to one without and compares unequal, which is a support ticket, not a
-- security property.

ALTER TABLE orbit.network ADD COLUMN slug text;

-- Backfill before NOT NULL.
--
-- Nothing is deployed, so no production database needs this — but every
-- development and CI database already holds networks from previous runs, and a
-- migration that only applies to an empty table is a migration nobody can run.
-- The uuid with its hyphens removed is 32 lowercase hex characters: a valid
-- slug by the charset below, and unique by construction because the id is.
UPDATE orbit.network SET slug = replace(id::text, '-', '') WHERE slug IS NULL;

ALTER TABLE orbit.network
    ALTER COLUMN slug SET NOT NULL,
    ADD CONSTRAINT network_slug_unique UNIQUE (slug),
    -- Lowercase alphanumerics and hyphens, 1-32, no leading or trailing hyphen.
    --
    -- No periods: a period is ambiguous in a path, and in a hostname context it
    -- is a label separator rather than a character, so "prod.eu" would be one
    -- name here and two labels there.
    --
    -- No underscores: they are not valid in a network interface name, and the
    -- slug is the stem this deployment derives tun.dev from.
    --
    -- Tailscale excludes both from tailnet names for the same two reasons.
    ADD CONSTRAINT network_slug_charset
        CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$');

-- Slug immutability, enforced here rather than in a handler.
--
-- The house position is that invariants live in the database, and this one is
-- the case that position was written for: a slug becomes a directory name on
-- every managed host in the network, so changing it does not rename anything —
-- it strands the old directory and makes every agent write a second one. Two
-- paths already create networks (POST /v1/networks and `orbitd bootstrap`) and
-- any number may update them; an invariant enforced in one handler is enforced
-- in whichever handler someone remembers.
--
-- A trigger rather than something cheaper, and the alternatives were weighed:
--
--   * Column-level privileges (REVOKE UPDATE (slug)) cannot subtract from the
--     table-wide GRANT UPDATE in 0002. Making them work means revoking UPDATE
--     on the table and re-granting it column by column, which fails OPEN in the
--     worst way: a column added by a later migration gets no grant, and the
--     omission surfaces at runtime as a permission error on a write path, not
--     at migration time.
--   * A generated column cannot be used: the slug is chosen, not derived.
--
-- The trigger costs one WHEN-clause comparison, and only on statements that
-- name slug in their SET list — the WHEN is evaluated without entering the
-- function, so an UPDATE that does not touch slug pays nothing at all.
--
-- ERRCODE 23514 (check_violation) with an explicit CONSTRAINT name so the error
-- arrives at store.mapErr as ErrInvalid and reaches the caller as a 400 naming
-- the rule, rather than as a 500 that reads like a bug in the control plane.
CREATE FUNCTION orbit.refuse_network_slug_change() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION
        'network slug is immutable: % cannot become %', OLD.slug, NEW.slug
        USING ERRCODE = '23514',
              CONSTRAINT = 'network_slug_immutable',
              HINT = 'the slug is a directory name on every managed host in this '
                     'network; create a new network instead, or edit the display name';
END
$$;

CREATE TRIGGER network_slug_immutable
    BEFORE UPDATE OF slug ON orbit.network
    FOR EACH ROW WHEN (OLD.slug IS DISTINCT FROM NEW.slug)
    EXECUTE FUNCTION orbit.refuse_network_slug_change();

-- The display name's rules, replacing the addressing rule 0005 carried.
ALTER TABLE orbit.network
    DROP CONSTRAINT network_name_is_not_a_uuid,
    ADD CONSTRAINT network_name_shape CHECK (
        char_length(name) BETWEEN 1 AND 65
        -- Letters, digits, spaces, apostrophes, hyphens. Control characters are
        -- excluded by omission rather than by a second rule, which also rules
        -- out a newline that would break every line-oriented output this value
        -- appears in.
        --
        -- [[:alnum:]] follows the database's ctype, so on a UTF-8 database this
        -- admits "Zürich" and on a C-locale one it does not. That is a
        -- rejection rather than a hole, and the alternative — enumerating
        -- Unicode ranges in a CHECK — is worse to read and no more correct.
        AND name ~ '^[[:alnum:] ''-]+$'
        -- Whitespace at either end renders identically to none and compares
        -- unequal.
        AND name = btrim(name)
    );

-- No GRANT accompanies this file: it creates no table. The trigger function is
-- EXECUTE-to-PUBLIC by default and is invoked by the trigger, not by a caller.
