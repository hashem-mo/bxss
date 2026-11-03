CREATE INDEX IF NOT EXISTS events_retention
ON events(received_at ASC, id ASC);

CREATE INDEX IF NOT EXISTS injection_requests_retention
ON injection_requests(created_at ASC, id ASC);
