%%
%% sftp-manta bridge
%%
%% Copyright 2025 Alex Wilson <alex@uq.edu.au>
%% The University of Queensland
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(sftpd_manta).

-export([subsystem_spec/1]).
-export([init/1, handle_ssh_msg/2, handle_msg/2, terminate/2]).

-compile([{parse_transform, lager_transform}]).

-record(?MODULE, {
    sftpd_state :: tuple(),
    rec_fields :: #{atom() => integer()}
    }).

subsystem_spec(Opts0) ->
    Opts1 = Opts0 ++ [{sftpd_vsn, 3}],
    {"sftp", {ssh_sftpd, Spec}} = ssh_sftpd:subsystem_spec(Opts1),
    {"sftp", {sftpd_manta, Spec}}.

init(Opts) ->
    {ok, SS0} = ssh_sftpd:init(Opts),
    {ssh_sftpd, Beam, _} = code:get_object_code(ssh_sftpd),
    {ok, {_Mod, [{abstract_code,{_Vsn,Forms}},{"CInf",_CB}]}} =
        beam_lib:chunks(Beam, [abstract_code, "CInf"]),
    RecAttrs = maps:from_list(
        [{Name, Defs} || {attribute,_,record,{Name, Defs}} <- Forms]),
    #{state := StateFields} = RecAttrs,
    {FMap,_N} = lists:foldl(fun
        ({record_field,_Loc,{atom,_ALoc,Field}}, {Acc, I}) ->
            {Acc#{Field => I}, I + 1};
        (_, Acc) ->
            Acc
    end, {#{}, 2}, StateFields),
    {ok, #?MODULE{sftpd_state = SS0, rec_fields = FMap}}.

handle_ssh_msg(Msg, S0 = #?MODULE{sftpd_state = SS0}) ->
    case ssh_sftpd:handle_ssh_msg(Msg, SS0) of
        {ok, SS1} ->
            {ok, S0#?MODULE{sftpd_state = SS1}};
        {stop, StopChanId, SS1} ->
            {stop, StopChanId, S0#?MODULE{sftpd_state = SS1}}
    end.

handle_msg({ssh_channel_up, ChanId, ConnMgr} = Msg,
        S0 = #?MODULE{sftpd_state = SS0, rec_fields = RF}) ->
    #{file_handler := FileHandlerIdx, file_state := FileStateIdx} = RF,
    FileMod = element(FileHandlerIdx, SS0),
    FS0 = element(FileStateIdx, SS0),
    FS1 = case erlang:function_exported(FileMod, login, 2) of
        true ->
            [{user, User}] = ssh_connection_handler:connection_info(ConnMgr,
                [user]),
            try
                FileMod:login(User, FS0)
            catch Class:Reason:Stack ->
                lager:error("login callback died: ~p: ~p: ~p",
                    [Class, Reason, Stack]),
                {stop, ChanId, S0}
            end;
        _ ->
            FS0
    end,
    SS1 = setelement(FileStateIdx, SS0, FS1),
    case ssh_sftpd:handle_msg(Msg, SS1) of
        {ok, SS2} ->
            {ok, S0#?MODULE{sftpd_state = SS2}};
        {stop, StopChanId, SS2} ->
            {stop, StopChanId, S0#?MODULE{sftpd_state = SS2}}
    end;

handle_msg(Msg, S0 = #?MODULE{sftpd_state = SS0}) ->
    case ssh_sftpd:handle_msg(Msg, SS0) of
        {ok, SS1} ->
            {ok, S0#?MODULE{sftpd_state = SS1}};
        {stop, StopChanId, SS1} ->
            {stop, StopChanId, S0#?MODULE{sftpd_state = SS1}}
    end.

terminate(Why, #?MODULE{sftpd_state = SS0, rec_fields = RF}) ->
    #{file_handler := FileHandlerIdx, file_state := FileStateIdx} = RF,
    FileMod = element(FileHandlerIdx, SS0),
    FS0 = element(FileStateIdx, SS0),
    FS1 = case erlang:function_exported(FileMod, logout, 1) of
        true ->
            FileMod:logout(FS0);
        _ ->
            FS0
    end,
    SS1 = setelement(FileStateIdx, SS0, FS1),
    ssh_sftpd:terminate(Why, SS1).
