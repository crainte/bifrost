-module(bifrost_template).
-export([render/2, render/3]).

%% Render a template from priv/templates/ with variable substitution.
%% The result is wrapped in the layout template.
render(Name, Vars) when is_atom(Name) ->
    render(atom_to_list(Name), Vars);
render(Name, Vars) when is_list(Name) ->
    render(Name, Vars, #{}).

render(Name, Vars, Extra) when is_list(Name) ->
    Root = code:priv_dir(bifrost),
    PagePath = filename:join([Root, "templates", Name ++ ".html"]),
    LayoutPath = filename:join([Root, "templates", "layout.html"]),
    Page = read_page(PagePath),
    Rendered = substitute(Page, Vars),
    Layout = read_page(LayoutPath),
    AllVars = maps:merge(Extra, Vars#{content => Rendered}),
    substitute(Layout, AllVars).

%% ── Template file loading ────────────────────────────────────

read_page(Path) ->
    case file:read_file(Path) of
        {ok, Bin} -> Bin;
        {error, enoent} ->
            <<"<p>Template not found: ", (list_to_binary(Path))/binary, "</p>">>
    end.

%% ── Substitution ─────────────────────────────────────────────

substitute(Bin, Vars) when is_binary(Bin), is_map(Vars) ->
    Pattern = <<"\\{\\{([A-Za-z_][A-Za-z0-9_]*)(\\|raw)?\\}\\}">>,
    case re:run(Bin, Pattern, [global, {capture, [0, 1, 2], binary}]) of
        {match, Matches} ->
            do_subst(Bin, Matches, Vars, 0);
        nomatch ->
            Bin
    end.

do_subst(Bin, [[Full, Key, Mode] | Rest], Vars, Offset) ->
    %% Find the match position in the original binary
    {Pos, Len} = match_pos(Bin, Full, Offset),
    %% Get the text before this match
    Before = binary:part(Bin, Offset, Pos - Offset),
    %% Get the replacement value
    Value = var_value(Key, Mode, Vars),
    %% Continue with the rest
    RestBin = do_subst(Bin, Rest, Vars, Pos + Len),
    <<Before/binary, Value/binary, RestBin/binary>>;
do_subst(Bin, [], _Vars, Offset) ->
    binary:part(Bin, Offset, byte_size(Bin) - Offset).

%% Find the position of Full (a binary pattern match) starting from Offset.
%% Since Full came from re:run on the same binary, binary:match works.
match_pos(Bin, Full, Offset) ->
    case binary:match(Bin, Full, [{scope, {Offset, byte_size(Bin) - Offset}}]) of
        {Pos, Len} -> {Pos, Len};
        nomatch -> {byte_size(Bin), 0}
    end.

var_value(Key, Mode, Vars) ->
    AtomKey = try binary_to_existing_atom(Key, utf8)
              catch error:badarg -> undefined
              end,
    case AtomKey =/= undefined andalso maps:find(AtomKey, Vars) of
        {ok, Val} ->
            Bin = to_binary(Val),
            case Mode of
                <<"|raw">> -> Bin;
                _ -> escape_html(Bin)
            end;
        _ ->
            <<"">>
    end.

to_binary(Val) when is_list(Val) -> unicode:characters_to_binary(Val);
to_binary(Val) when is_binary(Val) -> Val;
to_binary(Val) when is_integer(Val) -> integer_to_binary(Val);
to_binary(Val) when is_float(Val) -> float_to_binary(Val, [{decimals, 1}, compact]);
to_binary(Val) when is_atom(Val) -> atom_to_binary(Val, utf8);
to_binary(_) -> <<"">>.

%% ── HTML escaping ────────────────────────────────────────────

escape_html(Bin) when is_binary(Bin) ->
    << <<(escape_byte(B))/binary>> || <<B>> <= Bin >>.

escape_byte($<)  -> <<"&lt;">>;
escape_byte($>)  -> <<"&gt;">>;
escape_byte($&)  -> <<"&amp;">>;
escape_byte($")  -> <<"&quot;">>;
escape_byte($')  -> <<"&#39;">>;
escape_byte(B)   -> <<B>>.
