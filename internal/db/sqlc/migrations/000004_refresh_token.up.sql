CREATE TABLE public.refresh_token (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    rotated_at TIMESTAMP WITHOUT TIME ZONE,
    revoked_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE UNIQUE INDEX refresh_token_hash_unique
    ON public.refresh_token(token_hash);

CREATE INDEX refresh_token_user_id_idx
    ON public.refresh_token(user_id);

CREATE INDEX refresh_token_family_id_idx
    ON public.refresh_token(family_id);

ALTER TABLE public.refresh_token
    ADD CONSTRAINT refresh_token_user_id_user_id_fk
        FOREIGN KEY (user_id)
            REFERENCES public."user"(id)
            ON DELETE CASCADE;
