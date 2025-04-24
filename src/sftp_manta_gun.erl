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

-module(sftp_manta_gun).

-export([await_body/3]).

-type stream_ref() :: reference().

-type await_body_result() :: {ok, binary()}
    | {ok, binary(), gun:resp_headers()}
    | {error, {stream_error | connection_error | down, any()} | timeout}.

-spec await_body(pid(), stream_ref(), timeout() | reference()) -> await_body_result().
await_body(ServerPid, StreamRef, MRef) when is_reference(MRef) ->
    await_body(ServerPid, StreamRef, 5000, MRef, <<>>);
await_body(ServerPid, StreamRef, Timeout) ->
    MRef = monitor(process, ServerPid),
    Res = await_body(ServerPid, StreamRef, Timeout, MRef, <<>>),
    demonitor(MRef, [flush]),
    Res.

await_body(ServerPid, StreamRef, Timeout, MRef, Acc) ->
    receive
        {gun_data, ServerPid, StreamRef, nofin, Data} ->
            ok = gun:update_flow(ServerPid, StreamRef, 1),
            await_body(ServerPid, StreamRef, Timeout, MRef,
                << Acc/binary, Data/binary >>);
        {gun_data, ServerPid, StreamRef, fin, Data} ->
            ok = gun:update_flow(ServerPid, StreamRef, 1),
            {ok, << Acc/binary, Data/binary >>};
        %% It's OK to return trailers here because the client
        %% specifically requested them.
        {gun_trailers, ServerPid, StreamRef, Trailers} ->
            {ok, Acc, Trailers};
        {gun_error, ServerPid, StreamRef, Reason} ->
            {error, {stream_error, Reason}};
        {gun_error, ServerPid, Reason} ->
            {error, {connection_error, Reason}};
        {'DOWN', MRef, process, ServerPid, Reason} ->
            {error, {down, Reason}}
    after Timeout ->
        {error, timeout}
    end.
