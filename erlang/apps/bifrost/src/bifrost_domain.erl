%% Canonical form for every domain the control plane stores: lowercase ASCII, no
%% trailing dot. Rules entered in the UI, unblocks clicked from the query log
%% and threats blocked from the review page all pass through here, so a block and
%% an allow for the same name can never be stored in two different spellings.
-module(bifrost_domain).

-export([normalize/1]).

%% Accepts a bare name, or AdGuard/hosts syntax (`||name^`, `0.0.0.0 name`,
%% `*.name`). Single-label names (`nas`) are valid for rules even though
%% blocklist files ignore them.
-spec normalize(term()) -> {ok, binary()} | error.
normalize(Raw) when is_binary(Raw) ->
    Trimmed = string:trim(Raw),
    case bifrost_blocklist_manager:parse_line(Trimmed) of
        {block, Domain} -> {ok, Domain};
        skip -> single_label(Trimmed);
        _ -> error
    end;
normalize(_) ->
    error.

single_label(Name0) ->
    Name = string:lowercase(string:trim(Name0, trailing, ".")),
    Ok = byte_size(Name) > 0 andalso byte_size(Name) =< 63
        andalso lists:all(fun(C) -> (C >= $a andalso C =< $z) orelse (C >= $0 andalso C =< $9)
                                    orelse C =:= $- end, binary_to_list(Name)),
    case Ok of
        true -> {ok, Name};
        false -> error
    end.
