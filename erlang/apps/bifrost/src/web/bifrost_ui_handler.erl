-module(bifrost_ui_handler).

-export([init/2]).

-define(CT_HTML, #{<<"content-type">> => <<"text/html; charset=utf-8">>}).

init(Req0, redirect) ->
    Req1 = cowboy_req:reply(302, #{<<"location">> => <<"/dashboard">>}, Req0),
    {ok, Req1, []};
init(Req0, Page) ->
    try
        Html = render_page(Page),
        Req1 = cowboy_req:reply(200, ?CT_HTML, Html, Req0),
        {ok, Req1, []}
    catch
        Class:Reason:Stack ->
            logger:error("ui handler crashed: ~p:~p~n~p", [Class, Reason, Stack]),
            ErrorHtml = <<"<h1>Internal Error</h1>">>,
            ReqErr = cowboy_req:reply(500, ?CT_HTML, ErrorHtml, Req0),
            {ok, ReqErr, []}
    end.

render_page(dashboard) ->
    bifrost_template:render("dashboard", #{title => "Overview", heading => "Overview", subtitle => "DNS operations at a glance", page => "dashboard"});
render_page(blocklists) ->
    bifrost_template:render("blocklists", #{title => "Blocklists", heading => "Blocklists", subtitle => "Manage subscribed blocking sources", page => "blocklists"});
render_page(query_log) ->
    bifrost_template:render("query_log", #{title => "Queries", heading => "Queries", subtitle => "Inspect DNS decisions and responses", page => "query-log"});
render_page(clients) ->
    bifrost_template:render("clients", #{title => "Clients", heading => "Clients", subtitle => "Devices observed on your network", page => "clients"});
render_page(filters) ->
    bifrost_template:render("filters", #{title => "Rules", heading => "Rules", subtitle => "Live operational DNS policy", page => "filters"});
render_page(settings) ->
    bifrost_template:render("settings", #{title => "Settings", heading => "Settings", subtitle => "Live DNS routing, cache, and history policy", page => "settings"});
render_page(threats) ->
    bifrost_template:render("threats", #{title => "Threats", heading => "Threats", subtitle => "Review suspicious forwarded domains", page => "threats"});
render_page(_) ->
    <<"<h1>Not Found</h1>">>.
