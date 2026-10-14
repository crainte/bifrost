-module(bifrost_view).

-export([render_query_log_table/5, action_badge/2, escape_h/1]).

-define(PER_PAGE, 50).

%% ── Query log table (HTML fragment) ─────────────────────────

render_query_log_table(Entries, Total, Page, Sort, Order) ->
    Pages = max(1, (Total + ?PER_PAGE - 1) div ?PER_PAGE),
    Rows = case Entries of
        [] -> <<"<tr><td colspan=\"5\" class=\"q-empty\">No queries match these filters.</td></tr>">>;
        _ -> [format_log_row(E) || E <- Entries]
    end,
    iolist_to_binary([
        <<"<div class=\"q-meta\"><span>">>, thousands(Total), <<" matching queries</span>">>,
        <<"<span>Click a row for full details</span></div>">>,
        <<"<div class=\"table-wrap query-results\"><table class=\"data-table query-table q-table\">">>,
        <<"<thead><tr>">>,
        sortable_th(<<"time">>, <<"Time">>, Sort, Order, <<"width:150px">>),
        sortable_th(<<"domain">>, <<"Domain">>, Sort, Order, <<"">>),
        sortable_th(<<"client">>, <<"Client">>, Sort, Order, <<"width:200px">>),
        sortable_th(<<"action">>, <<"Result">>, Sort, Order, <<"width:190px">>),
        <<"<th style=\"width:44px\"><span class=\"sr-only\">Actions</span></th>">>,
        <<"</tr></thead><tbody>">>, Rows, <<"</tbody></table></div>">>,
        render_pagination(Page, Pages, Total)
    ]).

sortable_th(Col, Label, Sort, Order, Style) ->
    Arrow = case {Col =:= Sort, Order} of
        {true, <<"asc">>} -> <<"<svg class=\"ic sort-arrow\" aria-hidden=\"true\" viewBox=\"0 0 24 24\"><path d=\"m18 15-6-6-6 6\"/></svg>">>;
        {true, _} -> <<"<svg class=\"ic sort-arrow\" aria-hidden=\"true\" viewBox=\"0 0 24 24\"><path d=\"m6 9 6 6 6-6\"/></svg>">>;
        _ -> <<"">>
    end,
    AriaSort = case {Col =:= Sort, Order} of
        {true, <<"asc">>} -> <<" aria-sort=\"ascending\"">>;
        {true, _} -> <<" aria-sort=\"descending\"">>;
        _ -> <<"">>
    end,
    StyleAttr = case Style of <<"">> -> <<"">>; _ -> <<" style=\"", Style/binary, "\"">> end,
    [<<"<th data-sort=\"">>, Col, <<"\"">>, AriaSort, StyleAttr, <<">">>, Label, Arrow, <<"</th>">>].

render_pagination(Page, Pages, Total) ->
    First = case Total of 0 -> 0; _ -> (Page - 1) * ?PER_PAGE + 1 end,
    Last = min(Total, Page * ?PER_PAGE),
    Prev = integer_to_binary(max(1, Page - 1)),
    Next = integer_to_binary(min(Pages, Page + 1)),
    PrevDis = if Page =< 1 -> <<" disabled">>; true -> <<"">> end,
    NextDis = if Page >= Pages -> <<" disabled">>; true -> <<"">> end,
    iolist_to_binary([
        <<"<div class=\"q-pager pager\"><span>Showing ">>, thousands(First), <<"–"/utf8>>, thousands(Last),
        <<" of ">>, thousands(Total), <<"</span><div class=\"q-pager__btns\">">>,
        <<"<button class=\"btn btn-secondary btn-sm\" aria-label=\"Previous page\" data-page=\"">>, Prev, <<"\"">>, PrevDis,
        <<"><svg class=\"ic\" aria-hidden=\"true\"><use href=\"#i-chevron\" transform=\"rotate(180 12 12)\"/></svg></button>">>,
        <<"<span>Page ">>, integer_to_binary(Page), <<" of ">>, integer_to_binary(Pages), <<"</span>">>,
        <<"<button class=\"btn btn-secondary btn-sm\" aria-label=\"Next page\" data-page=\"">>, Next, <<"\"">>, NextDis,
        <<"><svg class=\"ic\" aria-hidden=\"true\"><use href=\"#i-chevron\"/></svg></button>">>,
        <<"</div></div>">>
    ]).

format_log_row(#{client_ip := ClientIp, domain := Domain, qtype := Qtype,
                  action := Action, queried_at := QueriedAt, client_name := ClientName,
                  client_rcode := ClientRcode, ede_code := EdeCode, list_id := ListId,
                  latency_us := LatencyUs} = Entry) ->
    ResponseRecords = maps:get(response_records, Entry, []),
    {TimeStr, DateStr} = format_time(QueriedAt),
    DomainE = escape_h(Domain),
    ClientIpE = escape_h(ClientIp),
    ClientNameE = case ClientName of
        undefined -> <<"">>; null -> <<"">>; <<"">> -> <<"">>; _ -> escape_h(ClientName)
    end,
    QtypeName = qtype_name(Qtype),
    DisplayAction = friendly_action(Action),
    ActionAttr = case Action of undefined -> <<"">>; _ -> escape_h(Action) end,
    Id = integer_to_binary(maps:get(id, Entry)),
    DetailId = <<"query-detail-", Id/binary>>,
    Client = case ClientNameE of
        <<"">> -> [<<"<a href=\"/clients?ip=">>, ClientIpE, <<"\" class=\"mono\">">>, ClientIpE, <<"</a>">>];
        _ -> [<<"<a href=\"/clients?ip=">>, ClientIpE, <<"\">">>, ClientNameE, <<"</a><span class=\"ql-sub\">">>, ClientIpE, <<"</span>">>]
    end,
    Menu = case Action of
        <<"BIFROST_RW">> -> <<"">>;
        _ -> [<<"<button type=\"button\" class=\"ql-icon-btn ql-menu-btn\" aria-label=\"Row actions\" data-domain=\"">>, DomainE,
              <<"\" data-client=\"">>, ClientIpE, <<"\" data-action=\"">>, ActionAttr,
              <<"\"><svg class=\"ic\" aria-hidden=\"true\"><use href=\"#i-more\"/></svg></button>">>]
    end,
    Details = query_details(DomainE, ClientIpE, ClientNameE, QtypeName, DisplayAction,
                            ClientRcode, EdeCode, ListId, LatencyUs, ResponseRecords),
    iolist_to_binary([
        <<"<tr class=\"ql-row\" tabindex=\"0\" aria-expanded=\"false\" aria-controls=\"">>, DetailId, <<"\">">>,
        <<"<td class=\"ql-time\"><div style=\"display:flex;align-items:center;gap:8px\">">>,
        <<"<svg class=\"ic ql-chev\" aria-hidden=\"true\"><use href=\"#i-chevron\"/></svg><div>">>,
        <<"<time datetime=\"">>, iso_time(QueriedAt), <<"\">">>, TimeStr, <<"</time>">>,
        <<"<span class=\"ql-sub\">">>, DateStr, <<"</span></div></div></td>">>,
        <<"<td><div class=\"ql-domain\"><span class=\"mono\" title=\"">>, DomainE, <<"\">">>, DomainE, <<"</span>">>,
        <<"<span class=\"ql-qtype\">">>, QtypeName, <<"</span>">>,
        <<"<button type=\"button\" class=\"ql-icon-btn ql-copy-btn\" data-copy=\"">>, DomainE,
        <<"\" aria-label=\"Copy domain\" title=\"Copy domain\"><svg class=\"ic ic-sm\" aria-hidden=\"true\"><use href=\"#i-copy\"/></svg></button>">>,
        <<"</div></td>">>,
        <<"<td class=\"ql-client\"><div style=\"display:flex;align-items:center;gap:6px\"><div style=\"min-width:0\">">>, Client, <<"</div>">>,
        <<"<button type=\"button\" class=\"ql-icon-btn ql-copy-btn\" data-copy=\"">>, ClientIpE,
        <<"\" aria-label=\"Copy client IP\" title=\"Copy client IP\"><svg class=\"ic ic-sm\" aria-hidden=\"true\"><use href=\"#i-copy\"/></svg></button></div></td>">>,
        <<"<td>">>, action_badge(Action, DisplayAction), result_note(Action, ListId, LatencyUs), <<"</td>">>,
        <<"<td style=\"text-align:right\">">>, Menu, <<"</td></tr>">>,
        <<"<tr id=\"">>, DetailId, <<"\" class=\"ql-detail hidden\"><td colspan=\"5\"><div class=\"ql-detail-body\">">>,
        Details, <<"</div></td></tr>">>
    ]).

result_note(<<"BIFROST_BLOCK">>, <<"client:", _/binary>>, _) -> note(<<"Client rule">>);
result_note(<<"BIFROST_BLOCK">>, ListId, _) when is_binary(ListId), ListId =/= <<>> -> note(escape_h(ListId));
result_note(<<"BIFROST_BLOCK">>, _, _) -> note(<<"Manual block">>);
result_note(<<"BIFROST_CACHE">>, _, _) -> note(<<"Served from cache">>);
result_note(<<"BIFROST_RW">>, _, _) -> note(<<"Local rewrite">>);
result_note(_, _, Latency) when is_integer(Latency) -> note(latency_value(Latency));
result_note(_, _, _) -> <<"">>.

note(Text) -> [<<"<span class=\"ql-sub\">">>, Text, <<"</span>">>].

action_badge(undefined, _Display) ->
    badge_span(<<"pill-muted">>, <<"Unknown">>);
action_badge(Action, DisplayName) ->
    Class = case Action of
        <<"BIFROST_BLOCK">> -> <<"pill-danger">>;
        <<"BIFROST_CACHE">> -> <<"pill-cache">>;
        <<"BIFROST_RW">>    -> <<"pill-violet">>;
        <<"BIFROST_ALLOW">> -> <<"pill-good">>;
        <<"NOERROR">>       -> <<"pill-cool">>;
        <<"NXDOMAIN">>      -> <<"pill-warn">>;
        <<"SERVFAIL">>      -> <<"pill-danger">>;
        <<"REFUSED">>       -> <<"pill-danger">>;
        _                   -> <<"pill-muted">>
    end,
    badge_span(Class, escape_h(DisplayName)).

%% ── Accessible query details ─────────────────────────────────

query_details(Domain, ClientIp, ClientName, Qtype, Action, ClientRcode, EdeCode, ListId, LatencyUs, ResponseRecords) ->
    Client = case ClientName of <<>> -> ClientIp; _ -> <<ClientName/binary, " (", ClientIp/binary, ")">> end,
    iolist_to_binary([
        <<"<dl>">>,
        detail_item(<<"Question">>, <<Domain/binary, " · "/utf8, Qtype/binary>>),
        detail_item(<<"Client">>, Client),
        detail_item(<<"Policy decision">>, Action),
        detail_item(<<"Client response">>, display_value(ClientRcode)),
        detail_item(<<"Extended DNS Error">>, display_value(EdeCode)),
        detail_item(<<"Blocklist">>, display_value(ListId)),
        detail_item(<<"Upstream latency">>, latency_value(LatencyUs)),
        <<"</dl><table class=\"response-records\"><tbody>">>,
        format_response_records(ResponseRecords, ClientRcode),
        <<"</tbody></table>">>
    ]).

detail_item(Label, Value) ->
    [<<"<div><dt>">>, Label, <<"</dt><dd>">>, Value, <<"</dd></div>">>].

display_value(undefined) -> <<"—"/utf8>>;
display_value(null) -> <<"—"/utf8>>;
display_value(<<>>) -> <<"—"/utf8>>;
display_value(Value) when is_integer(Value) -> integer_to_binary(Value);
display_value(Value) -> escape_h(Value).

latency_value(undefined) -> <<"Not upstreamed">>;
latency_value(null) -> <<"Not upstreamed">>;
latency_value(N) when is_integer(N), N >= 1000 -> iolist_to_binary([float_to_binary(N / 1000, [{decimals, 1}]), <<" ms">>]);
latency_value(N) when is_integer(N) -> iolist_to_binary([integer_to_binary(N), <<" µs"/utf8>>]);
latency_value(_) -> <<"—"/utf8>>.

format_response_records(Records, _ClientRcode) when is_list(Records), Records =/= [] ->
    Lines = [[<<"<div>">>, escape_h(maps:get(<<"rtype">>, R, <<"">>)), <<" ">>,
              escape_h(maps:get(<<"value">>, R, <<"">>)), <<"</div>">>] || R <- Records],
    iolist_to_binary([<<"<tr><td>Answers</td><td class=\"mono\">">>, Lines, <<"</td></tr>">>]);
format_response_records(_, ClientRcode) ->
    Rcode = case ClientRcode of undefined -> <<"—"/utf8>>; null -> <<"—"/utf8>>; R -> escape_h(R) end,
    iolist_to_binary([<<"<tr><td>Answers</td><td>No answer records (">>, Rcode, <<")</td></tr>">>]).

badge_span(Class, Label) ->
    iolist_to_binary([<<"<span class=\"pill ">>, Class, <<"\">">>, Label, <<"</span>">>]).

%% ── Formatting helpers ──────────────────────────────────────

format_time({{Y,M,D},{H,Min,S}}) ->
    AmPm = if H >= 12 -> <<" PM">>; true -> <<" AM">> end,
    H12 = if H == 0 -> 12; H > 12 -> H - 12; true -> H end,
    TimeStr = iolist_to_binary([integer_to_binary(H12), <<":">>, pad2(Min), <<":">>, pad2(trunc(S)), AmPm]),
    DateStr = iolist_to_binary([pad2(M), <<"/">>, pad2(D), <<"/">>, integer_to_binary(Y)]),
    {TimeStr, DateStr};
format_time(_) ->
    {<<"--">>, <<"----">>}.

iso_time({{Y,M,D},{H,Min,S}}) ->
    iolist_to_binary([integer_to_binary(Y), <<"-">>, pad2(M), <<"-">>, pad2(D), <<"T">>,
                      pad2(H), <<":">>, pad2(Min), <<":">>, pad2(trunc(S)), <<"Z">>]);
iso_time(_) -> <<"">>.

friendly_action(undefined) -> <<"Unknown">>;
friendly_action(<<"BIFROST_BLOCK">>) -> <<"Blocked">>;
friendly_action(<<"BIFROST_CACHE">>) -> <<"Cached">>;
friendly_action(<<"BIFROST_RW">>) -> <<"Rewritten">>;
friendly_action(<<"BIFROST_ALLOW">>) -> <<"Allowed">>;
friendly_action(<<"NOERROR">>) -> <<"Forwarded">>;
friendly_action(<<"NXDOMAIN">>) -> <<"NXDOMAIN">>;
friendly_action(<<"SERVFAIL">>) -> <<"SERVFAIL">>;
friendly_action(<<"REFUSED">>) -> <<"Refused">>;
friendly_action(A) -> escape_h(A).

thousands(N) when N < 1000 -> integer_to_binary(N);
thousands(N) ->
    iolist_to_binary([thousands(N div 1000), <<",">>, pad3(N rem 1000)]).

pad3(N) when N < 10 -> <<"00", (integer_to_binary(N))/binary>>;
pad3(N) when N < 100 -> <<"0", (integer_to_binary(N))/binary>>;
pad3(N) -> integer_to_binary(N).

pad2(N) when is_float(N) -> pad2(trunc(N));
pad2(N) when N < 10 -> <<"0", (integer_to_binary(N))/binary>>;
pad2(N) -> integer_to_binary(N).

escape_h(undefined) -> <<"">>;
%% Output also lands inside HTML attributes (data-domain="..."), so quotes are
%% escaped as well as < > &.
escape_h(Bin) when is_binary(Bin) ->
    iolist_to_binary(lists:map(fun
        ($&) -> <<"&amp;">>;
        ($<) -> <<"&lt;">>;
        ($>) -> <<"&gt;">>;
        ($") -> <<"&quot;">>;
        ($') -> <<"&#39;">>;
        (C) -> <<C>>
    end, binary_to_list(Bin)));
escape_h(List) when is_list(List) ->
    escape_h(list_to_binary(List)).

qtype_name(1) -> <<"A">>;
qtype_name(28) -> <<"AAAA">>;
qtype_name(5) -> <<"CNAME">>;
qtype_name(15) -> <<"MX">>;
qtype_name(16) -> <<"TXT">>;
qtype_name(33) -> <<"SRV">>;
qtype_name(6) -> <<"SOA">>;
qtype_name(12) -> <<"PTR">>;
qtype_name(2) -> <<"NS">>;
qtype_name(65) -> <<"HTTPS">>;
qtype_name(64) -> <<"SVCB">>;
qtype_name(255) -> <<"ANY">>;
qtype_name(N) -> iolist_to_binary([<<"TYPE">>, integer_to_list(N)]).
