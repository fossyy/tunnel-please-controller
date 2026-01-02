-- name: UserExistsByIdentifier :one
SELECT EXISTS (
    SELECT 1
    FROM public."user"
    WHERE identifier = $1
) AS exists;