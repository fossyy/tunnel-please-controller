-- name: CreateIdentifier :one
INSERT INTO identifiers (slug)
VALUES ($1)
RETURNING id, slug, created_at, updated_at;

-- name: GetIdentifierById :one
SELECT id, slug, created_at, updated_at
FROM identifiers
WHERE id = $1;

-- name: GetIdentifierBySlug :one
SELECT id, slug, created_at, updated_at
FROM identifiers
WHERE slug = $1;

-- name: ListIdentifiers :many
SELECT id, slug, created_at, updated_at
FROM identifiers
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: DeleteIdentifier :exec
DELETE FROM identifiers
WHERE id = $1;

-- name: UpdateIdentifierSlug :one
UPDATE identifiers
SET slug = $2, updated_at = NOW()
WHERE id = $1
RETURNING id, slug, created_at, updated_at;

-- name: CountIdentifiers :one
SELECT COUNT(*) FROM identifiers;

