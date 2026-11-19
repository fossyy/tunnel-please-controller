DO $$
DECLARE
    duplicate_keys INTEGER;
BEGIN
    SELECT COUNT(*) INTO duplicate_keys
    FROM (
        SELECT provider_id, account_id
        FROM public.account
        GROUP BY provider_id, account_id
        HAVING COUNT(*) > 1
    ) duplicates;
    IF duplicate_keys > 0 THEN
        RAISE EXCEPTION '% duplicate provider/account key(s) in public.account; resolve manually before migrating', duplicate_keys;
    END IF;
END
$$;

CREATE UNIQUE INDEX account_provider_account_unique
    ON public.account(provider_id, account_id);
