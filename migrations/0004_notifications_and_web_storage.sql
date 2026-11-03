ALTER TABLE collectors
ADD COLUMN capture_storage INTEGER NOT NULL DEFAULT 0 CHECK (capture_storage IN (0, 1));

ALTER TABLE collectors
ADD COLUMN discord_notifications INTEGER NOT NULL DEFAULT 0 CHECK (discord_notifications IN (0, 1));
