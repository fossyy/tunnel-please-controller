DO $$
BEGIN
    RAISE EXCEPTION 'migration 000003 backfills ssh_identifier from google account links and cannot be reversed';
END
$$;
