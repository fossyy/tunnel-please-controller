CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE public."user" (
    id TEXT PRIMARY KEY,
    ssh_identifier TEXT NOT NULL DEFAULT substr(encode(gen_random_bytes(16), 'hex'), 1, 32),
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    image TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX user_email_unique
    ON public."user"(email);

CREATE UNIQUE INDEX user_ssh_identifier_unique
    ON public."user"(ssh_identifier);

CREATE TABLE public.account (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    id_token TEXT,
    access_token_expires_at TIMESTAMP WITHOUT TIME ZONE,
    refresh_token_expires_at TIMESTAMP WITHOUT TIME ZONE,
    scope TEXT,
    password TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL
);

CREATE INDEX account_userId_idx
    ON public.account(user_id);

ALTER TABLE public.account
    ADD CONSTRAINT account_user_id_user_id_fk
        FOREIGN KEY (user_id)
            REFERENCES public."user"(id)
            ON DELETE CASCADE;


CREATE TABLE public.session (
    id TEXT PRIMARY KEY,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    token TEXT NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    user_id TEXT NOT NULL
);

CREATE UNIQUE INDEX session_token_unique
    ON public.session(token);

CREATE INDEX session_userId_idx
    ON public.session(user_id);

ALTER TABLE public.session
    ADD CONSTRAINT session_user_id_user_id_fk
        FOREIGN KEY (user_id)
            REFERENCES public."user"(id)
            ON DELETE CASCADE;


CREATE TABLE public.jwks (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE public.verification (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT now()
);

CREATE INDEX verification_identifier_idx
    ON public.verification(identifier);
