-- =========================================================================
--
--   RFC5322/RFC654 compliant originator fields header parser 
--   (for OpenDKIM lua script)
--
-- =========================================================================

-- Copyright (c) 2023-2025, Yasuhito FUTASUKI
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS"
-- AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
-- THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
-- PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
-- CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
-- EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, 
-- PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
-- OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
-- WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
-- OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
-- ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

-- -------------------------------------------------------------------------
--   RFC5322/RFC6854 Mail header specification BNF
-- -------------------------------------------------------------------------
-- BNF from RFC5234
-- CR             =  %x0D
-- LF             =  %x0A
-- HTAB           =  %x09
-- SP             =  %x20
-- DQUOTE         =  %x22
-- VCHAR          =  %x21-7E
--                        ; visible (printing) characters
-- CRLF           =  CR LF
-- WSP            =  SP / HTAB
--                        ; white space

-- BNF from RFC5322
-- FWS             =   ([*WSP CRLF] 1*WSP) /  obs-FWS
--                                        ; Folding white space
-- obs-FWS         =   1*WSP *(CRLF 1*WSP)
-- obs-NO-WS-CTL   =   %d1-8 /            ; US-ASCII control
--                     %d11 /             ;  characters that do not
--                     %d12 /             ;  include the carriage
--                     %d14-31 /          ;  return, line feed, and
--                     %d127              ;  white space characters
-- atext           =   ALPHA / DIGIT /    ; Printable US-ASCII
--                     "!" / "#" /        ;  characters not including
--                     "$" / "%" /        ;  specials.  Used for atoms.
--                     "&" / "'" /
--                     "*" / "+" /
--                     "-" / "/" /
--                     "=" / "?" /
--                     "^" / "_" /
--                     "`" / "{" /
--                     "|" / "}" /
--                     "~"
-- quoted-pair     =   ("\" (VCHAR / WSP)) / obs-qp
-- obs-qp          =   "\" (%d0 / obs-NO-WS-CTL / LF / CR)
-- atom            =   [CFWS] 1*atext [CFWS]
-- dot-atom-text   =   1*atext *("." 1*atext)
-- dot-atom        =   [CFWS] dot-atom-text [CFWS]
-- qtext           =   %d33 /             ; Printable US-ASCII
--                     %d35-91 /          ;  characters not including
--                     %d93-126 /         ;  "\" or the quote character
--                     obs-qtext
-- obs-qtext       =   obs-NO-WS-CTL
-- qcontent        =   qtext / quoted-pair
-- quoted-string   =   [CFWS]
--                     DQUOTE *([FWS] qcontent) [FWS] DQUOTE
--                     [CFWS]
-- word            =   atom / quoted-string
-- phrase          =   1*word / obs-phrase
-- obs-phrase      =   word *(word / "." / CFWS)
-- ctext           =   %d33-39 /          ; Printable US-ASCII
--                     %d42-91 /          ;  characters not including
--                     %d93-126 /         ;  "(", ")", or "\"
--                     obs-ctext
-- obs-ctext       =   obs-NO-WS-CTL
-- ccontent        =   ctext / quoted-pair / comment
-- comment         =   "(" *([FWS] ccontent) [FWS] ")"
-- CFWS            =   (1*([FWS] comment) [FWS]) / FWS
-- RFC5322
-- -- from            =   "From:" mailbox-list CRLF
-- -- sender          =   "Sender:" mailbox CRLF
-- from: updated by RFC6854
-- from            =   "From:" (mailbox-list / address-list) CRLF
-- sender: updated by RFC6854
-- sender          =   "Sender:" (mailbox / address) CRLF
--
-- address         =   mailbox / group
-- mailbox         =   name-addr / addr-spec
-- name-addr       =   [display-name] angle-addr
-- angle-addr      =   [CFWS] "<" addr-spec ">" [CFWS] /
--                     obs-angle-addr
-- obs-angle-addr  =   [CFWS] "<" obs-route addr-spec ">" [CFWS]
-- group           =   display-name ":" [group-list] ";" [CFWS]
-- display-name    =   phrase
-- mailbox-list    =   (mailbox *("," mailbox)) / obs-mbox-list
-- obs-mbox-list   =   *([CFWS] ",") mailbox *("," [mailbox / CFWS])
-- address-list    =   (address *("," address)) / obs-addr-list
-- obs-addr-list   =   *([CFWS] ",") address *("," [address / CFWS])
-- group-list      =   mailbox-list / CFWS / obs-group-list
-- obs-group-list  =   1*([CFWS] ",") [CFWS]
-- obs-route       =   obs-domain-list ":"
-- obs-domain-list =   *(CFWS / ",") "@" domain
--                     *("," [CFWS] ["@" domain])
-- addr-spec       =   local-part "@" domain
-- local-part      =   dot-atom / quoted-string / obs-local-part
-- obs-local-part  =   word *("." word)
-- domain          =   dot-atom / domain-literal / obs-domain
-- obs-domain      =   atom *("." atom)
-- domain-literal  =   [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
-- dtext           =   %d33-90 /          ; Printable US-ASCII
--                     %d94-126 /         ;  characters not including
--                     obs-dtext          ;  "[", "]", or "\"
-- obs-dtext       =   obs-NO-WS-CTL / quoted-pair

-- =========================================================================
--
--   logging (mainly for debug)
--
-- =========================================================================

-- default logger function is 'print'
local logger = print

-- logger for debugging
local enable_parse_log = true

-- -------------------------------------------------------------------------
--   set_logger -- set the logging function used by parser functions 
--
--   Parameters:
--       fn -- new logging function. If it is nil, turn off the logging
--
--   Return value:
--       nil
-- -------------------------------------------------------------------------

local function set_logger(fn)
    if fn == nil then
        enable_parse_log = false
    else
        enable_parse_log = true
        logger = fn
    end
    return nil
end


local function parse_log(msg, field)
    if enable_parse_log then
        logger(msg .. ": field=\034" .. field .. "\034")
    end
    return nil
end

-- =========================================================================
--
--   RFC5322/RFC6854 Mail header parser functions
--
-- =========================================================================

local wsp = "[\t ]"
local ctext = "[\001-\008\011\012\014-\031!-\'%*%+,-Z%[%]%^_-\127]"
local quoted_pair = "\\[\000-\127]"
local atext = "[%a%d!#-\'%*%+%-/=%?%^_`{|}~]"
local qtext = "[\001-\008\011\012\014-\031!#-Z%[%]%^_-\127]"
-- dtext also allows quoted-pair
local dtext = "[\001-\008\011\012\014-\031!-Z%^_-%127]"

-- On odkim, it seems CRLF is already replaced to single LF.
-- So we assume both cases that end of line is CRLF, and it is LF.

-- first character of FWS
local fc_fws = "[\t\r\n ]"

-- Skip FWS and return the rest of the field
local function skip_fws(field)
    local pos
    local rest = field
    local fc = string.sub(rest, 1, 1)
    if not string.match(fc, fc_fws) then
        return rest
    end
    if string.match(fc, wsp) then
        -- old-fws: it allows more than one line in the pattern
        rest = string.match(rest, "^[\t ]+(.*)")
        while string.sub(rest, 1, 1) == "\n" or string.sub(rest, 1, 2) == "\r\n" do
            rest = string.match(rest, "^\r?\n[\t ]+(.*)")
            if rest == nil then
                -- Fool proof. This can't, because if the next character
                -- after "\n" is not WSP, it indicates the end of the
                -- field, but in the case, "\n" is already trimed.
                parse_log("Error at skip_fws: fool proof in old-fws", field)
                return nil
            end
        end
    else
        -- fws without old-fws: at most one continuation line in the
        -- pattern
        rest = string.match(rest, "^\r?\n[\t ]+(.*)")
        if rest == nil then
            parse_log("Error at skip_fws: fool proof in non old-fws", field)
            return nil
        end
    end
    return rest
end

-- patterns to skip comment contents.
-- quoted-pair and (optional) trailing sequence of ctext
local qp_ct_seq = "^" .. quoted_pair .. ctext .. "*(.*)"
-- ctext sequence
local ct_seq = "^" .. ctext .. "+(.*)"

-- Skip comment and return the rest of the field
local function skip_comment(field)
    local rest = field
    local fc = string.sub(rest, 1, 1)
    local nl = 1
    if fc ~= "(" then
        parse_log("Error at skip_comment: internal error. First character is not a left paren", field)
        return nil
    end
    rest = string.sub(rest, 2)
    fc = string.sub(rest, 1, 1)
    while true do
        if fc == ")" then
            nl = nl - 1
            rest = string.sub(rest, 2)
            if nl == 0 then
                return rest
            end
        elseif fc == "\\" then
            rest = string.match(rest, qp_ct_seq)
        elseif fc == "(" then
            nl = nl + 1
            rest = string.sub(rest, 2)
        elseif string.match(fc, fc_fws) then
            rest = skip_fws(rest)
        elseif string.match(fc, ctext) then
            rest = string.match(rest, ct_seq)
        else
            parse_log("Error at skip_comment: unexpected pattern in comment: rest=\034" .. rest .. "\034", field)
            return nil
        end
        if rest == nil then
            parse_log("Error at skip_comment: unexpected pattern in comment: fc=\034" .. fc .. "\034", field)
            return nil
        elseif rest == "" then
            parse_log("Error at skip_comment: right paren is not found: fc=\034" .. fc .. "\034", field)
            return nil
        end
        fc = string.sub(rest, 1, 1)
    end
    -- unreached
    return nil
end

-- first character of cfws
local fc_cfws = "[\t\n %(]"

-- Skip CFWS and return the rest of field
local function skip_cfws(field)
    local rest = field
    local fc = string.sub(rest, 1, 1)
    while string.match(fc, fc_cfws) do
        if string.match(fc, fc_fws) then
            rest = skip_fws(rest)
        elseif fc == "(" then
            rest = skip_comment(rest)
        else
            -- internal error
            parse_log("Error at skip_cfws: internal error. Unexpected fc: fc=\034" .. fc .. "\034", field)
            return nil
        end
        if rest == nil then
            parse_log("Error at skip_cfws: fail on calling sub pattern: fc=\034" .. fc .. "\034", field)
            return nil
        end
        fc = string.sub(rest, 1, 1)
    end
    return rest
end

-- pattern to capture a atom
local at_pat = "^(" .. atext .. "+)(.*)"

-- Parse atom then return its content and rest of the field.
-- Assuming preceding CFWS is already striped. Strip trailing CFWS
-- if is_strip_cfws is true.
local function capture_atom(field, is_strip_cfws)
    local rest = field
    local token = nil
    token, rest = string.match(rest, at_pat)
    if token == nil then
        parse_log("Error on capture_atom: First character is not atext", field)
    end
    if is_strip_cfws then
        rest = skip_cfws(rest)
        if rest == nil then
            parse_log("Error on capture_atom: fail to strip trailing CFWS", field)
            return nil
        end
    end
    return token, rest
end

-- Patterns to capture the content of qstring
-- characters which is allowed for the first of qstring, i.e. "\" or qtext.
local fc_qstring = "[\001-\008\011\012\014-\031!#-\127]"
-- quoted-pair and optional trailing sequence of qtext.
local qp_qt_pat =  "^\\([\000-\127]" .. qtext .. "*)(.*)"
-- a sequence of qtext (at least one qtext)
local qt_pat = "^(" .. qtext .. "+)(.*)"

-- Parse qstring then return its content and rest of the field.
-- Assuming preceding CFWS is already striped. Strip trailing CFWS
-- if is_strip_cfws is true
local function capture_qstring(field, is_strip_cfws)
    local rest = field
    local symbol = ""
    local token
    local fc = string.sub(rest, 1, 1)
    if fc ~= "\034" then
        parse_log("Error on capture_qstring: The first character fc = \034" .. fc "\034 is not double quote", field)
        return nil
    end
    rest = string.sub(rest, 2)
    fc = string.sub(rest, 1, 1)
    while string.match(fc, "[\001-!#-\127]") do
        if string.match(fc, fc_fws) then
             rest = skip_fws(rest)
             if rest == nil then
                parse_log("Error at capture_qstring: error from skip_fws (1)",
                          field)
                 return nil
             end
             symbol = symbol .. " "
             fc = string.sub(rest, 1, 1)
        end
        while string.match(fc, fc_qstring) do
            -- qtext or quoted pair
            if fc == "\\" then
                token, rest = string.match(rest, qp_qt_pat)
            else
                token, rest = string.match(rest, qt_pat)
            end
            if token == nil then
                parse_log("Error at capture_qstring: unexpected pattern in qstring", field)
                return nil
            end
            symbol = symbol .. token
            fc = string.sub(rest, 1, 1)
        end
    end
    if fc ~= "\034" then
        parse_log("Error at capture_qstring: unexpected character fc =\034" .. fc .. "\034 in qstring or end of the pattern", field)
        return nil
    end
    rest = string.sub(rest, 2)
    if is_strip_cfws then
        rest = skip_cfws(rest)
        if rest == nil then
            parse_log("Error on capture_qstring: fail to strip trailing CFWS", field)
            return nil
        end
    end
    return symbol, rest
end

-- Patterns to capture the content of domain-literal
-- quoted-pair and optional trailing sequence of dtext.
local qp_dt_pat =  "^\\([\000-\127]" .. dtext .. "*)(.*)"
-- a sequence of dtext (at least one dtext)
local dt_pat = "^(" .. dtext .. "+)(.*)"

-- Parse domain and return it.
local function capture_domain(field)
    local fc, token, symbol
    local rest = field
    symbol = ""
    fc = string.sub(rest, 1, 1)
    if string.match(fc, fc_cfws) then
        rest = skip_cfws(rest)
        if rest == nil then
            parse_log("Error on capture_domain: fail to strip preceding CFWS", field)
            return nil
        end
        fc = string.sub(rest, 1, 1)
    end
    if fc == "[" then
        -- domain-literal
        rest = string.sub(rest, 2)
        fc = string.sub(rest, 1, 1)
        while true do
            if string.match(fc, fc_fws) then
                rest = skip_fws(rest)
                if rest == nil then
                    parse_log("Error on capture_domain: fail to skip FWS in domain-literal", field)
                    return nil
                end
                fc = string.sub(rest, 1, 1)
            end
            if fc == "]" then
                rest = skip_cfws(string.sub(rest, 2))
                if rest == nil then
                    parse_log("Error on capture_domain: fail to skip CFWS trailing after domain-literal", field)
                    return nil
                end
                break
            elseif fc == "\\" then
                token, rest = string.match(rest, qp_dt_pat)
            elseif string.match(fc, dtext) then
                token, rest = string.match(rest, dt_pat)
            else
                parse_log("Error on capture_domain: Unexpected character \034" .. fc .. "\034 in domain-literal", field)
                return nil
            end
            if token == nil then
                parse_log("Error on capture_domain: internal error in domain-literal", field)
                return nil
            end
            symbol = symbol .. token
            fc = string.sub(rest, 1, 1)
        end
        rest = string.sub(rest, 2)
    elseif string.match(fc, atext) then
        while true do
            token, rest = capture_atom(rest, true)
            if token == nil then
                parse_log("Error on capture_domain: Error on calling capture_atom", field)
                return nil
            end
            symbol = symbol .. token
            fc = string.sub(rest, 1, 1)
            if fc ~= "." then
                break
            end
            symbol = symbol .. "."
            rest = skip_cfws(string.sub(rest, 2))
            if rest == nil then
                parse_log("Error on capture_domain: Error on skipping CFWS after \034.\034", field)
                return nil
            end
        end
    else
        parse_log("Error on capture_domain: Unexpected character \034" .. fc .. "\034 at the top of domain pattern", field)
        return nil
    end
    return symbol, rest
end

local function parse_local_part(field)
    local fc, token, local_part
    local rest = field
    local_part = ""
    fc = string.sub(rest, 1, 1)
    if string.match(fc, fc_cfws) then
        rest = skip_cfws(rest)
        if rest == nil then
            parse_log("Error on parse_local_part: fail to strip preceding CFWS", field)
            return nil
        end
        string.sub(rest, 1, 1)
    end
    while true do
        if fc == "\034" then
            token, rest = capture_qstring(rest, false)
        elseif string.match(fc, atext) then
            token, rest = capture_atom(rest, false)
        else
            -- syntax error: only atom or quoted-string is allowed
            parse_log("Error on parse_local_part: Unexpected character \034" .. fc .. "\034 in local-part", field)
            return nil
        end
        if token == nil then
            parse_log("Error on parse_local_part: Error on calling sub pattern", field)
            return nil
        end
        local_part = local_part .. token
        fc = string.sub(rest, 1, 1)
        if string.match(fc, fc_cfws) then
            has_cfws = true
            rest = skip_cfws(rest)
            if rest == nil then
                parse_log("Error on parse_local_part: Fail to strip CFWS between words", field)
                return nil
            end
            fc = string.sub(rest, 1, 1)
        else
            has_cfws = false
        end
        if fc ~= "." then
            break
        end
        rest = skip_cfws(string.sub(rest, 2))
        if rest == nil then
            parse_log("Error on parse_local_part: Fail to skip CFWS after dot", field)
            return nil
        end
        local_part = local_part .. "."
        fc = string.sub(rest, 1, 1)
    end
    if has_cfws then
        -- local-part with trailing CFWS is syntactically allowed, but
        -- semantically not allowed. However, as it can be still valid
        -- as a part of phrase, return rest of the field to continue
        -- parsing
        return nil, rest
    end
    return local_part, rest
end

-- Parse addr-spec and return a mail address
local function parse_addr_spec(field)
    local fc, symbol
    local rest = field
    symbol, rest = parse_local_part(rest)
    if symbol == nil then
        parse_log("Error on parse_addr_spec: Error on parsing local-part", field)
        return nil
    end
    if string.sub(rest, 1, 1) ~= "@" then
        parse_log("Error on parse_addr_spec: \034@\034 is expected but not found in \034" .. rest .. "\034", field)
        return nil
    end
    if string.match(string.sub(rest, 2, 2), fc_cfws) then
        -- CFWS here is syntactically allowed, but semantically
        -- not allowed
        parse_log("Error on parse_addr_spec: CFWS after \034@\034 is semantically not allowed in \034" .. rest .. "\034", field)
        return nil
    end
    domain, rest = capture_domain(string.sub(rest, 2))
    if domain == nil then
        parse_log("Error on parse_addr_spec: Error on parsing domain", field)
        return nil
    end
    return { local_part = symbol, domain = domain }, rest
end

-- first character of obs-route CFWS or "@"
local fc_obs_route = "[\t\r\n %(@]"

-- Parse angle-addr and return a mail address.
local function parse_angle_addr(field)
    local fc, local_part, domain, addr
    local rest = field
    if string.sub(rest, 1, 1) ~= "<" then
        parse_log("Error on parse_angle_addr: \034<\034 is expected on the top of the field, but not found", field)
        return nil
    end
    if string.match(string.sub(rest, 2, 2), fc_cfws) then
        rest = skip_cfws(string.sub(rest, 2))
        if rest == nil then
            parse_log("Error on parse_angle_addr: Fail to skip CFWS after \034<\034", field)
            return nil
        end
    else
        rest = string.sub(rest, 2)
    end
    if string.sub(rest, 1, 1) == "@" then
        -- skip obs-route
        domain = nil
        while true do
            if fc == "@" then
                domain, rest = capture_domain(string.sub(rest, 2))
                if domain == nil then
                    parse_log("Error on parse_angle_addr: Fail to parse a domain in obs-route", field)
                    return nil
                end
                fc = string.sub(rest, 1, 1)
                if fc == ":" then
                    break
                elseif fc ~= "," then
                    parse_log("Error on parse_angle_addr: Unexpected character \034" .. fc .. "\034 after domain in obs-route", field)
                    return nil
                end
                rest = string.sub(rest, 2)
            elseif fc == "," then
                rest = string.sub(rest, 2)
            elseif fc == ":" then
                break
            elseif string.match(fc, fc_cfws) then
                rest = skip_cfws(rest)
                if rest == nil then
                    parse_log("Error on parse_angle_addr: Fail to skip CFWS in obs-route", field)
                    return nil
                end
            else
                parse_log("Error on parse_angle_addr: Unexpected character \034" .. fc .. "\034 on top the of domain in obs-route", field)
                return nil
            end
            fc = string.sub(rest, 1, 1)
        end
        if domain == nil then
            parse_log("Error on parse_angle_addr: No domains in obs-route", field)
            return nil
        end
    end
    addr, rest = parse_addr_spec(rest)
    if addr == nil then
        parse_log("Error on parse_angle_addr: Error on parsing addr-spec", field)
        return nil
    end
    if string.sub(rest, 1, 1) ~= ">" then
        parse_log("Error on parse_angle_addr: ">" is not found after addr-spec", field)
        return nil
    end
    rest = skip_cfws(string.sub(rest, 2))
    if addr == nil then
        parse_log("Error on parse_angle_addr: Fail to skip trailing CFWS", field)
        return nil
    end
    return addr, rest
end

-- atext or doublequote
local fc_atext_or_doublequote = "[%a%d!-\'%*%+%-/=%?%^_`{|}~]"
-- Characters which can be a first character of address;
-- atext or doublequote or "<"
local fc_address = "[%a%d!-\'%*%+%-/<=%?\\%^_`{|}~]"

-- Parse address, which is a single mailbox or a single group, and
-- return its mail address list and rest of the field.
local function parse_address(field)
    local fc, token, addr, symbol, domain
    local rest = field
    fc = string.sub(rest, 1, 1)
    if string.match(fc, fc_cfws) then
        rest = skip_cfws(rest)
        if rest == nil then
            parse_log("Error on parse_address: Fail to skip preceding CFWS", field)
            return nil
        end
        fc = string.sub(rest, 1, 1)
    end
    if fc == "<" then
        return parse_angle_addr(rest)
    elseif string.match(fc, fc_atext_or_doublequote) then
        -- we need to detect which next non CFWS token is.
        -- candidate
        --   (a) local-part -> addr-spec -> mailbox -> address
        --       -> address-list
        --   (b) display-name -> name-addr -> mailbox -> address
        --   (c) display-name -> group -> address
        -- first of all parse as local-part
        symbol, rest = parse_local_part(rest)
        if rest == nil then
            parse_log("Error on parse_address: error on parsing local-part/display-name at the top of address", field)
            return nil
        end
        fc = string.sub(rest, 1, 1)
        if symbol ~= nil and fc == "@" then
            if string.match(string.sub(rest, 2, 2), fc_cfws) then
                -- CFWS here is syntactically allowed, but semantically
                -- not allowed
                parse_log("Error on parse_address: CFWS after \034@\034 is semantically not allowed on \034" .. rest .. "\034", field)
                return nil
            end
            domain, rest = capture_domain(string.sub(rest, 2))
            if domain == nil then
                parse_log("Error on parse_address: fail to parse domain as a part of (bare) addr-spec", field)
                return nil
            end
            if string.match(string.sub(rest, 1, 1), fc_cfws) then
                rest = skip_cfws(rest)
                if rest == nil then
                    parse_log("Error on parse_address: fail to skip CFWS after addr-spec", field)
                    return nil
                end
            end
            return { local_part = symbol, domain = domain }, rest
        elseif string.match(fc, fc_atext_or_doublequote) then
            -- atext or doublequote
            -- continue to parse as a phrase; since phrase is never
            -- a part of address spec, we can dicard its content.
            while true do
                if fc == "." then
                    rest = skip_cfws(string.sub(rest, 2))
                elseif fc == "\034" then
                    token, rest = capture_qstring(rest, true)
                elseif string.match(fc, atext) then
                    token, rest = capture_atom(rest, true)
                elseif string.match(fc, fc_cfws) then
                    rest = skip_cfws(rest)
                else
                    break
                end
                if rest == nil then
                    parse_log("Error on parse_address: fail to parse a sub pattern in display-name", field)
                    return nil
                end
                fc = string.sub(rest, 1, 1)
            end
        end
        if fc == "<" then
            -- a part of name-addr
            return parse_angle_addr(rest)
        elseif fc == ":" then
            -- a part of group; the symbol was a display-name
            rest = string.sub(rest, 2)
            if string.sub(rest, 1, 1) ~= ";" then
                addrs, rest = parse_group_list(rest, 2)
                if addrs == nil then
                    parse_log("Error on parse_address: fail to parse a group-list", field)
                    return nil
                end
            end
            if string.sub(rest, 1, 1) ~= ";" then
                parse_log("Error on parse_address: \034;\034 is expected but not found in group on \034" .. rest .. "\034", field)
                return nil
            end
            rest = string.sub(rest, 2)
            if string.match(string.sub(rest, 1, 1), fc_cfws) then
                rest = skip_cfws(rest)
                if rest == nil then
                    parse_log("Error on parse_address: Fail to skip CFWS trailing after group", field)
                    return nil
                end
            end
            return addrs, rest
        end
    end
    parse_log("Error on parse_address: Unexpected character \034" .. fc .. "\034 in \034" .. rest .. "\034", field)
    return nil
end

-- Parse address-list and return its mail address list and rest of the field
-- This allows empty list. If mbox_only is true and group is found in the
-- list, return nil.
local function parse_address_list(field, mbox_only)
    local rest = field
    local addrs = { }
    local cnt = 0
    local fc, addr, paddrs, pcnt
    local has_cfws
    fc = string.sub(rest, 1, 1)
    while rest ~= "" do
        if string.match(fc, fc_cfws) then
            rest = skip_cfws(rest)
            if rest == nil then
                parse_log("Error on parse_address_list: Fail to skip CFWS on the top of each address", field)
                return nil
            end
            fc = string.sub(rest, 1, 1)
        end
        if fc ~= "," then
            if string.match(fc, fc_address) then
                paddrs, rest = parse_address(rest)
                if paddrs == nil then
                    parse_log("Error on parse_address_list: Fail to parse address", field)
                    return nil
                end
                if paddrs.local_part == nil then
                    if mbox_only then
                        parse_log("Error on parse_address_list: mbox_only is set but a group found", field)
                        return nil
                    end
                    pcnt = 1
                    addr = paddrs[pcnt]
                    while addr do
                        cnt = cnt + 1
                        addrs[cnt] = addr
                        pcnt = pcnt + 1
                        addr = paddrs[pcnt]
                    end
                else
                    cnt = cnt + 1
                    addrs[cnt] = paddrs
                end
            else
                parse_log("Error on parse_address_list: Unexpected character \034" .. fc .. "\034 at \034" .. rest .. "\034", field)
                return nil
            end
        end
        if string.sub(rest, 1, 1) ~= "," then
            break
        end
        rest = string.sub(rest, 2)
        fc = string.sub(rest, 1, 1)
    end
    if rest == nil then
        -- fool proof
        parse_log("Error on parse_address_list: internal error. 'rest' is broken unexpectedly", field)
        return nil
    end
    return addrs, rest
end

-- Parse group-list, which allows empty, and collect mail addresses.
-- Return list of mail addresses and the rest of field
local function parse_group_list(field)
    return parse_address_list(field, true)
end

-- Parse mailbox-list and collect mail addresses. Unlike group-list,
-- mailbox-list should contain at least one mailbox. Return list of
-- mail addresses and the rest of field
local function parse_mailbox_list(field)
    local addrs
    addrs, field = parse_address_list(field, true)
    if addrs[1] == nil then
        parse_log("Error on parse_mailbox_list: Error on calling parse_address_list", field)
        return nil
    end
    return addrs, field
end

-- -------------------------------------------------------------------------
--   parse_sender_header -- Parse a content of Sender: header and return
--                          an array of the addresses in it.
--
--   Parameters:
--       field -- a Header field to be parsed (string)
--
--   Return value:
--       an array of E-mail address table (constructed by the attributes
--       'local_part' and 'domain') 
-- -------------------------------------------------------------------------
local function parse_sender_header(field)
    local addrs
    local rest = field
    addrs, rest = parse_address(rest)
    if addrs == nil then
        parse_log("Error on parse_sender_header: Error on calling parse_address", field)
        return nil
    end
    if rest ~= "" then
        parse_log("Error on parse_sender_header: Extra character(s) after parse an address: rest=\034" .. rest .. "\034", field)
        return nil
    end
    return addrs
end

-- -------------------------------------------------------------------------
--   parse_from_header -- Parse a content of From: header and return
--                          an array of the addresses in it.
--
--   Parameters:
--       field -- a Header field to be parsed (string)
--
--   Return value: 
--       an array of E-mail address table (constructed by the attributes
--       'local_part' and 'domain') 
-- -------------------------------------------------------------------------
local function parse_from_header(field)
    local addrs
    local rest = field
    addrs, rest = parse_address_list(rest, false)
    if addrs == nil then
        parse_log("Error on parse_from_header: Error on calling parse_address_list", field)
        return nil
    end
    if rest ~= "" then
        parse_log("Error on parse_from_header: Extra character(s) after parse an address: rest=\034" .. rest .. "\034", field)
    end
    return addrs
end

-- atext or dot
local atext_or_dot = "[%a%d!#-\'%*%+%-/%.=%?%^_`{|}~]"
-- pattern matches single atom
local atom_pat = "^" .. atext .. "+$"
-- pattern matches dot-atom other than only single atom
local dot_atom_pat = "^" .. atext .. atext_or_dot .. "+" .. atext .. "$"

local function normalize_local_part(local_part)
    local sym, part, rest, new_rest
    if string.match(local_part, atom_pat) or string.match(local_part, dot_atom_pat) then
        return local_part
    end
    sym = "\034"
    rest = local_part
    while rest ~= "" do
        part, new_rest = string.match(rest, qt_pat)
        if part ~= nil then
            sym = sym .. part
            rest = new_rest
        else
            sym = sym .. "\\" .. string.sub(rest, 1, 1)
            rest = string.sub(rest, 2)
        end
    end
    return sym .. "\034"
end

-- -------------------------------------------------------------------------
--   addr_to_string -- Parse a content of From: header and return
--                          an array of the addresses in it.
--
--   Parameters:
--       addr -- an E-mail address represended by a table (constructed by
--               the attributes 'local_part' and 'domain'
--
--   Return value: 
--       an E-mail address represented in string
-- -------------------------------------------------------------------------
-- Unparse E-Mail address representation in table into string
local function addr_to_string(addr)
    if addr.local_part == nil or addr.domain == nil then
        return nil
    end
    return addr.local_part .. "@" .. addr.domain
end


-- =========================================================================
--   Symbols to be exposed
-- =========================================================================

return {
    set_logger = set_logger,
    parse_sender_header = parse_sender_header,
    parse_from_header = parse_from_header,
    normalize_local_part = normalize_local_part,
    addr_to_string = addr_to_string,
}
