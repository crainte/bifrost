%% Rendering tests for the query table's operator-facing details and copy actions.
-module(bifrost_view_tests).
-include_lib("eunit/include/eunit.hrl").

query_details_are_escaped_test() ->
    Html = bifrost_view:render_query_log_table([entry()], 1, 1, <<"time">>, <<"desc">>),
    ?assert(binary:match(Html, <<"query-detail-42">>) =/= nomatch),
    ?assert(binary:match(Html, <<"Policy decision">>) =/= nomatch),
    ?assert(binary:match(Html, <<"Extended DNS Error">>) =/= nomatch),
    ?assert(binary:match(Html, <<"&lt;unsafe&gt;">>) =/= nomatch),
    ?assertEqual(nomatch, binary:match(Html, <<"<unsafe>">>)).

response_records_are_inside_a_table_test() ->
    Html = bifrost_view:render_query_log_table([entry()], 1, 1, <<"time">>, <<"desc">>),
    ?assert(binary:match(Html, <<"</dl><table class=\"response-records\"><tbody><tr>">>) =/= nomatch),
    ?assertEqual(nomatch, binary:match(Html, <<"</dl><tr>">>)),
    ?assert(binary:match(Html, <<"data-table query-table">>) =/= nomatch).

action_badges_use_brand_palette_test() ->
    Cases = [{<<"BIFROST_BLOCK">>, <<"pill-danger">>}, {<<"BIFROST_CACHE">>, <<"pill-cache">>},
             {<<"BIFROST_RW">>, <<"pill-violet">>}, {<<"BIFROST_ALLOW">>, <<"pill-good">>},
             {<<"NOERROR">>, <<"pill-cool">>}, {<<"NXDOMAIN">>, <<"pill-warn">>},
             {<<"SERVFAIL">>, <<"pill-danger">>}, {<<"SOMETHING_ELSE">>, <<"pill-muted">>}],
    lists:foreach(fun({Action, Class}) ->
        Html = bifrost_view:action_badge(Action, <<"label">>),
        ?assert(binary:match(Html, <<"pill ", Class/binary>>) =/= nomatch),
        ?assertEqual(nomatch, binary:match(Html, <<"-red-">>))
    end, Cases),
    ?assert(binary:match(bifrost_view:action_badge(undefined, <<>>), <<"pill-muted">>) =/= nomatch).

%% escape_h output is placed inside HTML attributes (data-domain="...",
%% data-copy="..."), so quotes must be escaped too, not only < > &.
escape_h_escapes_quotes_test() ->
    ?assertEqual(<<"&quot;x&#39;&lt;&gt;&amp;">>, bifrost_view:escape_h(<<"\"x'<>&">>)).

copy_actions_are_rendered_test() ->
    Html = bifrost_view:render_query_log_table([entry()], 1, 1, <<"time">>, <<"desc">>),
    ?assert(binary:match(Html, <<"ql-copy-btn">>) =/= nomatch),
    ?assert(binary:match(Html, <<"aria-label=\"Copy domain\"">>) =/= nomatch),
    ?assert(binary:match(Html, <<"aria-label=\"Copy client IP\"">>) =/= nomatch).

redesigned_operational_pages_use_shared_primitives_test() ->
    PrivDir = code:priv_dir(bifrost),
    %% Every operational page shares the Settings page's sectioned layout and
    %% carries no leftover Tailwind slate utilities, inline colours or prompt().
    lists:foreach(fun(Page) ->
        {ok, Html} = file:read_file(filename:join([PrivDir, "templates", Page])),
        [?assertNotEqual(nomatch, binary:match(Html, N))
         || N <- [<<"class=\"st-section\"">>, <<"class=\"st-stats\"">>]],
        [?assertEqual(nomatch, binary:match(Html, N))
         || N <- [<<"text-slate-">>, <<"color: #">>, <<"prompt(">>]]
    end, ["blocklists.html", "threats.html", "filters.html", "clients.html", "query_log.html"]),
    lists:foreach(fun(Page) ->
        {ok, Html} = file:read_file(filename:join([PrivDir, "templates", Page])),
        [?assertEqual(nomatch, binary:match(Html, N))
         || N <- [<<"class=\"st-nav\"">>, <<"IntersectionObserver">>]]
    end, ["blocklists.html", "threats.html", "filters.html"]),
    {ok, Rules} = file:read_file(filename:join([PrivDir, "templates", "filters.html"])),
    ?assertNotEqual(nomatch, binary:match(Rules, <<"id=\"client-block-rows\"">>)),
    {ok, Css} = file:read_file(filename:join([PrivDir, "static", "bifrost.css"])),
    ?assert(binary:match(Css, <<".section-toolbar">>) =/= nomatch),
    ?assert(binary:match(Css, <<".table-shell">>) =/= nomatch),
    ?assert(binary:match(Css, <<".resource-row">>) =/= nomatch),
    {ok, Blocklists} = file:read_file(filename:join([PrivDir, "templates", "blocklists.html"])),
    ?assert(binary:match(Blocklists, <<"id=\"refresh-all-btn\"">>) =/= nomatch),
    ?assert(binary:match(Blocklists, <<"id=\"active-lists\"">>) =/= nomatch),
    {ok, Filters} = file:read_file(filename:join([PrivDir, "templates", "filters.html"])),
    ?assert(binary:match(Filters, <<"id=\"block-rows\"">>) =/= nomatch),
    ?assert(binary:match(Filters, <<"id=\"rewrite-rows\"">>) =/= nomatch),
    ?assert(binary:match(Blocklists, <<"id=\"catalog-grid\"">>) =/= nomatch),
    ?assert(binary:match(Blocklists, <<"id=\"run-analysis-btn\"">>) =/= nomatch),
    {ok, Threats} = file:read_file(filename:join([PrivDir, "templates", "threats.html"])),
    ?assert(binary:match(Threats, <<"id=\"t-rows\"">>) =/= nomatch),
    ?assert(binary:match(Threats, <<"id=\"t-select-all\"">>) =/= nomatch),
    ?assert(binary:match(Threats, <<"id=\"ab-preview\"">>) =/= nomatch),
    ?assert(binary:match(Threats, <<"exact hostname shown">>) =/= nomatch),
    ?assert(binary:match(Threats, <<"registry looked up">>) =/= nomatch),
    ?assert(binary:match(Threats, <<"registry pending">>) =/= nomatch),
    ?assert(binary:match(Threats, <<"registry unavailable">>) =/= nomatch),
    ?assertEqual(nomatch, binary:match(Threats, <<"collapsed to the registrable domain">>)),
    %% No leftover Tailwind slate utilities or inline colours on redesigned pages.
    ?assertEqual(nomatch, binary:match(Threats, <<"text-slate-">>)),
    ?assertEqual(nomatch, binary:match(Blocklists, <<"color: #">>)),
    {ok, Clients} = file:read_file(filename:join([PrivDir, "templates", "clients.html"])),
    ?assert(binary:match(Clients, <<"id=\"cl-rows\"">>) =/= nomatch).

query_rows_show_client_name_and_block_source_test() ->
    Html = bifrost_view:render_query_log_table([entry()], 1, 1, <<"time">>, <<"desc">>),
    ?assertNotEqual(nomatch, binary:match(Html, <<"class=\"ql-row\"">>)),
    ?assertNotEqual(nomatch, binary:match(Html, <<"Kitchen">>)),
    ?assertNotEqual(nomatch, binary:match(Html, <<"ql-sub\">example-list">>)),
    ?assertNotEqual(nomatch, binary:match(Html, <<"datetime=\"2026-10-02T12:00:00Z\"">>)),
    ?assertEqual(nomatch, binary:match(Html, <<"text-slate-">>)).

rendered_html_is_valid_utf8_test() ->
    Html = bifrost_view:render_query_log_table(
        [(entry())#{list_id => null, latency_us => 12}], 1, 1, <<"time">>, <<"desc">>),
    ?assert(is_binary(unicode:characters_to_binary(Html, utf8, utf8))),
    ?assertNotEqual(nomatch, binary:match(Html, <<"·"/utf8>>)),
    ?assertNotEqual(nomatch, binary:match(Html, <<"µs"/utf8>>)),
    ?assertNotEqual(nomatch, binary:match(Html, <<"—"/utf8>>)).

layout_has_collapsible_icon_sidebar_test() ->
    PrivDir = code:priv_dir(bifrost),
    {ok, Html} = file:read_file(filename:join([PrivDir, "templates", "layout.html"])),
    [?assertNotEqual(nomatch, binary:match(Html, N))
     || N <- [<<"id=\"sidebar-collapse\"">>, <<"class=\"brand-icon\"">>,
              <<"<symbol id=\"i-queries\"">>, <<"href=\"#i-settings\"">>,
              <<"bifrost.sidebar">>]],
    {ok, Css} = file:read_file(filename:join([PrivDir, "static", "bifrost.css"])),
    ?assertNotEqual(nomatch, binary:match(Css, <<".sidebar-collapsed .sidebar{">>)).

settings_page_has_structured_layout_test() ->
    PrivDir = code:priv_dir(bifrost),
    {ok, Html} = file:read_file(filename:join([PrivDir, "templates", "settings.html"])),
    lists:foreach(fun(Needle) -> ?assertNotEqual(nomatch, binary:match(Html, Needle)) end,
        [<<"class=\"st-section\"">>, <<"class=\"st-row\"">>, <<"st-endpoints__head">>,
          <<"class=\"st-savebar\"">>, <<"name=\"up-strategy\"">>, <<"id=\"block-ip-field\"">>]),
    [?assertEqual(nomatch, binary:match(Html, Needle))
     || Needle <- [<<"class=\"st-nav\"">>, <<"IntersectionObserver">>, <<"<script>alert">>]],
    {ok, Css} = file:read_file(filename:join([PrivDir, "static", "bifrost.css"])),
    %% Port inputs get a fixed narrow column, never full width.
    ?assertNotEqual(nomatch, binary:match(Css,
        <<".endpoint-row{display:grid;grid-template-columns:minmax(0,1fr) 104px 34px">>)),
    ?assertNotEqual(nomatch, binary:match(Css, <<".st-row{display:grid">>)),
    ?assertEqual(nomatch, binary:match(Css, <<".settings-grid">>)).

entry() ->
    #{id => 42, client_ip => <<"192.168.1.10">>, domain => <<"<unsafe>">>,
      qtype => 1, action => <<"BIFROST_BLOCK">>, client_rcode => <<"NXDOMAIN">>,
      ede_code => 15, list_id => <<"example-list">>, latency_us => null,
      queried_at => {{2026, 10, 2}, {12, 0, 0}}, client_name => <<"Kitchen">>,
      response_records => []}.
