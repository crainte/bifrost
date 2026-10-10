-module(bifrost_dns_settings_store).
-export([read/0, save/4]).

read() ->
    Sql = "SELECT revision, overrides::text, "
          "COALESCE((SELECT value FROM settings WHERE key = 'ptr_ttl_seconds'), '21600'), "
          "COALESCE((SELECT value FROM settings WHERE key = 'query_log_retention_months'), '6') "
          "FROM dns_settings WHERE singleton = true",
    decode(bifrost_db_pool:query(Sql, 3000)).

save(Revision, Overrides, PtrTTL, Retention)
  when is_integer(Revision), Revision >= 0, is_map(Overrides),
       is_integer(PtrTTL), PtrTTL >= 1, PtrTTL =< 604800,
       is_integer(Retention), Retention >= 0, Retention =< 1200 ->
    Sql = "WITH changed AS (UPDATE dns_settings SET overrides = $2::jsonb, "
          "revision = revision + 1, updated_at = now() "
          "WHERE singleton = true AND revision = $1 RETURNING revision, overrides), "
          "ptr AS (INSERT INTO settings (key, value) "
          "SELECT 'ptr_ttl_seconds', $3::text FROM changed "
          "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value RETURNING value), "
          "retention AS (INSERT INTO settings (key, value) "
          "SELECT 'query_log_retention_months', $4::text FROM changed "
          "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value RETURNING value) "
          "SELECT changed.revision, changed.overrides::text, ptr.value, retention.value "
          "FROM changed CROSS JOIN ptr CROSS JOIN retention",
    decode(bifrost_db_pool:equery(Sql,
        [Revision, jsx:encode(Overrides), integer_to_binary(PtrTTL), integer_to_binary(Retention)], 3000));
save(_, _, _, _) -> {error, invalid_settings}.

decode({ok, _, [{Revision, JSON, Ptr, Retention}]}) ->
    try
        {ok, #{revision => number(Revision), overrides => jsx:decode(JSON, [return_maps]),
               ptr_ttl_seconds => number(Ptr), retention_months => number(Retention)}}
    catch error:_ -> {error, invalid_stored_settings} end;
decode({ok, _, []}) -> {error, conflict};
decode({error, Reason}) -> {error, Reason};
decode(_) -> {error, unavailable}.

number(V) when is_integer(V) -> V;
number(V) when is_binary(V) -> binary_to_integer(V).
