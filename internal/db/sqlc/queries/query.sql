-- name: GetVerifiedEmailBySSHIdentifier :one
SELECT email
FROM public."user"
WHERE ssh_identifier = $1
  AND email_verified = true;
