CREATE UNIQUE INDEX account_provider_account_unique
    ON public.account(provider_id, account_id);
