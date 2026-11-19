DO $$
DECLARE
    conflicts INTEGER;
BEGIN
    SELECT COUNT(*) INTO conflicts
    FROM (
        SELECT account_id
        FROM public.account
        WHERE provider_id = 'google'
        GROUP BY account_id
        HAVING COUNT(DISTINCT user_id) > 1
    ) rebound;
    IF conflicts > 0 THEN
        RAISE EXCEPTION '% google account(s) are linked to more than one user; resolve manually before migrating', conflicts;
    END IF;

    SELECT COUNT(*) INTO conflicts
    FROM (
        SELECT user_id, MIN(account_id) AS subject
        FROM public.account
        WHERE provider_id = 'google'
        GROUP BY user_id
        HAVING COUNT(*) = 1
    ) single_link
    JOIN public."user" owner ON owner.id = single_link.user_id
    JOIN public."user" holder ON holder.ssh_identifier = single_link.subject
    WHERE holder.id <> owner.id;
    IF conflicts > 0 THEN
        RAISE EXCEPTION '% google subject(s) already used as ssh_identifier by a different user; resolve manually before migrating', conflicts;
    END IF;
END
$$;

WITH single_link AS (
    SELECT user_id, MIN(account_id) AS subject
    FROM public.account
    WHERE provider_id = 'google'
    GROUP BY user_id
    HAVING COUNT(*) = 1
)
UPDATE public."user" owner
SET ssh_identifier = single_link.subject,
    updated_at = now()
FROM single_link
WHERE owner.id = single_link.user_id
  AND owner.ssh_identifier <> single_link.subject;
