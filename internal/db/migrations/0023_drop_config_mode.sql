-- Fragment mode is gone, so the columns that selected it are too.
--
-- WHAT FRAGMENT MODE WAS.
--
-- Orbit wrote config.d/50-orbit.yml and pointed nebula at the DIRECTORY, so
-- nebula merged Orbit's file with operator-authored ones. It existed as the
-- escape hatch for a host that genuinely carried its own nebula configuration.
--
-- WHY IT IS GONE.
--
-- It is the one mode in which Orbit cannot say what a host is running. Nebula
-- merges a config directory with mergo.WithAppendSlice, so firewall lists
-- CONCATENATE across files — Orbit could neither see nor remove a rule an
-- operator wrote, and every policy answer it gave was a lower bound rather than
-- the truth. `orbit why` had to carry a disclaimer saying so.
--
-- It is also incompatible with where the agent is going. The agent now hands
-- nebula the verified configuration IN MEMORY rather than letting it read a
-- file, so that a config the control plane did not sign cannot be loaded at
-- all. Merging a directory means reading files, which means loading unsigned
-- configuration by design. The two cannot both be true.
--
-- So: one mode, and it is the one where Orbit owns the whole file. A host that
-- needs operator-authored nebula settings uses config_overrides, which the
-- control plane renders INTO the signed configuration — the same outcome, with
-- the control plane still able to say what is running.

ALTER TABLE orbit.membership DROP COLUMN config_mode;
ALTER TABLE orbit.network    DROP COLUMN config_mode;
