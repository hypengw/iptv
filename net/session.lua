local http = require('socket.http')
local ltn12 = require('ltn12')
local socket = require('socket')
local url = require('net.url')
local cookie = require('net.cookie')

-- @module net.session
-- @alias  M

local M = {}
M.type = M

function M.new()
    local s = {}
    s.cookie_jar = {}
    setmetatable(s, {
        __index = M
    })
    return s
end

---@class Param
---@field url string
---@field headers table
---@field response_table table
---@field redirects? integer

---@class GetParam : Param

---@class PostParam : Param
---@field data table


local function processRspHeaders(cookie_table, headers, req)
    for k, v in pairs(headers) do
        if k == 'set-cookie' then
            cookie.split_set_cookie(v, cookie_table)
        end
        if k == 'location' then
            req.url = v
        end
    end
end

local function doRequest(host, m, redirects, t)
    local r, c, h, s
    if redirects == nil then
        redirects = 0
    elseif redirects < 0 then
        redirects = 0
    end

    for i=0,redirects do
        r, c, h, s = http.request(t)
        m.cookie_jar[host] = m.cookie_jar[host] or {}
        processRspHeaders(m.cookie_jar[host], h, t)
    end
    return r, c, h, s
end

---@param p GetParam
function M:get(p)
    local u = url.parse(p.url)
    local cookie_table = self.cookie_jar[u.host]

    local headers = { unpack(p.headers) }
    if cookie_table then
        headers['Cookie'] = cookie.build_cookies(cookie_table)
    end

    return doRequest(u.host, self, p.redirects, {
        url = p.url,
        method = 'GET',
        headers = headers,
        sink = ltn12.sink.table(p.response_table),
        redirect = false
    })
end

---@param p PostParam
function M:post(p)
    local u = url.parse(p.url)
    local cookie_table = self.cookie_jar[u.host]

    local function encode_data(data)
        local encoded = {}
        for k, v in pairs(data) do
            table.insert(encoded, string.format("%s=%s",
                socket.url.escape(k), socket.url.escape(v)))
        end
        ---@type string
        return table.concat(encoded, "&")
    end
    local data = encode_data(p.data)

    local headers = { unpack(p.headers) }
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    headers['Content-Length'] = tostring(#data)
    if cookie_table then
        headers['Cookie'] = cookie.build_cookies(cookie_table)
    end

    return doRequest(u.host, self, p.redirects, {
        url = p.url,
        method = 'POST',
        headers = headers,
        source = ltn12.source.string(data),
        sink = ltn12.sink.table(p.response_table),
        redirect = false
    })
end

return M
