-- name: GetVerifiedSSHIdentifier :one
SELECT ssh_identifier
FROM public."user"
WHERE ssh_identifier = $1
  AND email_verified = true;

-- name: UpsertGoogleUser :one
WITH linked AS (
    SELECT a.user_id AS id
    FROM public.account a
    WHERE a.provider_id = 'google'
      AND a.account_id = @google_subject
),
by_email AS (
    SELECT u.id
    FROM public."user" u
    WHERE u.email = @user_email
      AND u.email_verified = true
      AND NOT EXISTS (SELECT 1 FROM linked)
),
matched AS (
    SELECT id FROM linked
    UNION
    SELECT id FROM by_email
),
created AS (
    INSERT INTO public."user" (id, ssh_identifier, name, email, email_verified, image)
    SELECT @user_id, @google_subject, @user_name, @user_email, true, @image
    WHERE NOT EXISTS (SELECT 1 FROM matched)
      AND NOT EXISTS (
          SELECT 1 FROM public."user" holder
          WHERE holder.ssh_identifier = @google_subject
            AND holder.id <> @user_id
      )
    ON CONFLICT (email) DO UPDATE
        SET email_verified = true,
            updated_at = now()
    RETURNING id, ssh_identifier
),
resolved AS (
    SELECT id FROM matched
    UNION
    SELECT id FROM created
),
canonicalized AS (
    UPDATE public."user" u
    SET ssh_identifier = @google_subject,
        updated_at = now()
    WHERE u.id IN (SELECT id FROM resolved)
      AND u.ssh_identifier <> @google_subject
      AND NOT EXISTS (
          SELECT 1 FROM public."user" holder
          WHERE holder.ssh_identifier = @google_subject
            AND holder.id <> u.id
      )
    RETURNING u.id, u.ssh_identifier
),
canonical AS (
    SELECT id, ssh_identifier FROM created
    UNION
    SELECT id, ssh_identifier FROM canonicalized
    UNION
    SELECT r.id, u.ssh_identifier
    FROM resolved r
    JOIN public."user" u ON u.id = r.id
    WHERE u.ssh_identifier = @google_subject
),
accounted AS (
    INSERT INTO public.account (id, account_id, provider_id, user_id, updated_at)
    SELECT @account_row_id, @google_subject, 'google', c.id, now()
    FROM canonical c
    ON CONFLICT (provider_id, account_id) DO NOTHING
    RETURNING user_id
),
refreshed AS (
    UPDATE public."user"
    SET name = @user_name,
        image = COALESCE(@image, image),
        email_verified = true,
        updated_at = now()
    WHERE id IN (SELECT id FROM canonical)
)
SELECT c.id AS user_id, c.ssh_identifier
FROM canonical c;

-- name: GetUserIdentity :one
SELECT id, ssh_identifier, email
FROM public."user"
WHERE id = $1;

-- name: CreateRefreshToken :exec
INSERT INTO public.refresh_token (id, user_id, family_id, token_hash, expires_at)
VALUES (@id, @user_id, @family_id, @token_hash, @expires_at);

-- name: GetRefreshTokenByHash :one
SELECT id, user_id, family_id, expires_at, rotated_at, revoked_at
FROM public.refresh_token
WHERE token_hash = $1;

-- name: RotateRefreshToken :one
WITH rotated AS (
    UPDATE public.refresh_token rt
    SET rotated_at = now()
    FROM public."user" u
    WHERE rt.token_hash = @lookup_hash
      AND rt.rotated_at IS NULL
      AND rt.revoked_at IS NULL
      AND rt.expires_at > now()
      AND u.id = rt.user_id
    RETURNING rt.user_id, rt.family_id, u.ssh_identifier, u.email
),
replaced AS (
    INSERT INTO public.refresh_token (id, user_id, family_id, token_hash, expires_at)
    SELECT @new_id, user_id, family_id, @new_token_hash, @new_expires_at
    FROM rotated
    RETURNING user_id, family_id
)
SELECT r.user_id, r.family_id, r.ssh_identifier, r.email
FROM replaced p
JOIN rotated r USING (user_id, family_id);

-- name: DeleteExpiredRefreshTokens :execrows
DELETE FROM public.refresh_token
WHERE id IN (
    SELECT id FROM public.refresh_token
    WHERE expires_at < now()
    LIMIT @max_rows
);

-- name: RevokeRefreshTokenFamily :exec
UPDATE public.refresh_token
SET revoked_at = now()
WHERE family_id = @family_id
  AND revoked_at IS NULL;
