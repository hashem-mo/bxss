-- Per-listener out-of-band response control.
--
-- By default an OOB listener answers every callback with one uniform, inert,
-- empty 200 (see src/routes/oob.ts). An operator can opt a listener into serving
-- a custom response instead, to drive blind vulnerabilities that depend on what
-- comes back: an XXE that needs a valid DTD body, an SSRF that must follow a
-- redirect to an internal host, a parser that only triggers on a specific
-- content type, and so on.
--
-- response_status is the switch: NULL keeps the built-in uniform default (and is
-- what unknown and disabled tokens always receive, so enumeration stays
-- infeasible); a non-NULL status activates the custom response. The body is
-- bounded operator-authored text and the headers are a bounded JSON array of
-- {name, value} pairs validated by the application. These are configuration,
-- not captured data, so like page_paths and chainload_url they are stored in
-- plaintext D1 columns rather than encrypted R2.

ALTER TABLE oob_probes
ADD COLUMN response_status INTEGER
  CHECK (response_status IS NULL OR (response_status >= 100 AND response_status <= 599));

ALTER TABLE oob_probes
ADD COLUMN response_body TEXT NOT NULL DEFAULT '';

ALTER TABLE oob_probes
ADD COLUMN response_headers TEXT NOT NULL DEFAULT '[]';
