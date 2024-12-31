local openssl = require('openssl')
local cjson = require('cjson')
local socket = require('socket')
local url = require('net.url')
local cookie = require('net.cookie')
local session = require('net.session')


local entry_point = 'yxidt.scrmt.org.cn:8001'
local ctc_conf = {
    authenticator = '',
    mpassword = '',
    userid = '',
    stbid = '',
    stbtype = '',
    stbversion = '',
    mac = '',
    softwareversion = '',
    conntype = 'dhcp',
    supporthd = '1',
    productpackageid = '-1',
    userfield = '0',

    -- other
    useragent = '',
    netdevice = 'eth0'
}
local headers = {
    Accept = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    ['Accept-Language'] = 'zh-cn',
    ['Accept-Charset'] = 'utf-8, *;q=0.7',
    ['User-Agent'] = ''
}

local cookie_table = {}

local function bool2Number(value)
    return value and 1 or 0
end


local function getLocalIpAddress(device)
    local handle = io.popen('ip addr show ' .. device)
    local output = handle:read('*a')
    handle:close()

    local ip_address = output:match('inet (%d+%.%d+%.%d+%.%d+)')
    return ip_address
end

-- Function to extract the user token from the response text
local function getUserToken(rep, ctc_conf)
    local token = rep:match('Token = "([0-9A-Za-z]+?)"')
    return token
end


---@class AuthInfo
---@field random string
---@field encry_token string
---@field user_id string
---@field stb_id string
---@field ip string
---@field mac string
---@field password string

---@param key string
---@param num integer
---@param fill string | nil
---@return string
local function pad_key(key, num, fill)
    fill = fill or '0'
    if #key > num then
        return key:sub(1, num)
    elseif #key < num then
        return key .. string.rep(fill, num - #key)
    else
        return key
    end
end

--https://github.com/dog-god/iptv/blob/0274ee97832cc8e60342533e12d55d0791e2ece9/java/src/com/armite/webkit/plug/CTCAuthHelper.java#L4
---@param auth_info AuthInfo
---@return ..., string
local function generateAuthInfo(auth_info)
    --Reserved
    local reserved = ''
    local data = auth_info.random .. '$' .. auth_info.encry_token .. '$' .. auth_info.user_id ..
        '$' .. auth_info.stb_id .. '$' .. auth_info.ip .. '$' .. auth_info.mac .. '$' ..
        reserved .. '$' .. 'CTC'
    local key = pad_key(auth_info.password, 24)
    data = pad_key(data, 128, '\01')

    -- Perform 3DES encryption
    local cipher = openssl.cipher.get('des-ede3-ecb') -- Triple DES ECB mode
    local iv = string.rep('\0', 8)                    -- 8-byte initialization vector (0 padding)
    local encrypted_data, err = cipher:encrypt(data, key, iv, false)

    if not encrypted_data then
        return nil, err
    end

    return openssl.hex(encrypted_data)
end

local function ctcGetAuthInfo(encryptToken)
    -- 3DES(Random+“$”+EncryToken+”$”+UserID +”$”+STBID+”$”+IP+”$”+MAC+”$”+
    -- Reserved+ ”$”+ “CTC”)
    local random_8 = pad_key(tostring(math.abs(math.random(0, 10000000 - 1))), 8)
    local ip = getLocalIpAddress(ctc_conf.netdevice)
    local enc = generateAuthInfo {
        random = random_8,
        encry_token = encryptToken,
        ip = ip,
        mac = ctc_conf.mac,
        user_id = ctc_conf.userid,
        password = ctc_conf.mpassword,
        stb_id = ctc_conf.stbid,
    }
    return enc
end


local function loadCtcConf(path)
    local file = io.open(path, 'r')
    local json_string = file:read('*a')
    file:close()
    for key, value in pairs(cjson.decode(json_string)) do
        ctc_conf[key] = value
    end
    headers['User-Agent'] = ctc_conf.useragent
end

local function getAuthAction(val)
    if val then
        return 'Login'
    else
        return 'Logout'
    end
end

local UICloudAuthClient = {}
UICloudAuthClient.base_url = 'http://' .. entry_point .. '/UICloudAuthClient'

---@param user_id string
---@param s session
function UICloudAuthClient.new(user_id, s)
    local comp = {}
    ---@type string
    comp.user_id = user_id
    ---@type string
    comp.epgip_port = nil
    comp.session = s
    setmetatable(comp, {
        __index = UICloudAuthClient
    })
    return comp
end

---@param is_login boolean
---@return nil
function UICloudAuthClient:authentication(is_login)
    local u = url.parse(self.base_url) / 'api' / 'authentication'

    local q = {
        UserID = self.user_id,
        Action = getAuthAction(is_login)
    }
    u:setQuery(q)
    print(u)

    local res_body = {}
    local res, code, response_headers, status = self.session:get {
        url = u:build(),
        headers = headers,
        response_table = res_body,
    }
    local text = table.concat(res_body)
    if is_login then
        local encrypt_token = string.match(text, "CTCGetAuthInfo%(['\"]([a-f0-9]+)['\"]%)")
        local auth = ctcGetAuthInfo(encrypt_token)
        return auth
    else
        if code == 200 then
            print('logout')
        end
    end
end

---@param authenticator string
function UICloudAuthClient:authurl(authenticator)
    local u = url.parse(self.base_url) / 'api' / 'authurl'
    print(u)

    local data = {
        UserID = self.user_id,
        authenticator = authenticator
    }
    local res_body = {}
    local res, code, response_headers, status = self.session:post {
        url = u:build(),
        headers = headers,
        data = data,
        response_table = res_body,
    }
    local text = table.concat(res_body)
    local next_url = string.match(text, 'document%.location%s*=%s*"([^"]+)"')

    if next_url then
        print(next_url)
        res_body = {}
        res, code = self.session:get {
            url = next_url,
            headers = headers,
            response_table = res_body,
            redirects = 1
        }
        text = table.concat(res_body)
        self.epgip_port = cookie.value(self.session.cookie_jar, url.parse(next_url).host, 'EPGIP_PORT')
        print('EPGIP_PORT: ' .. tostring(self.epgip_port))
        return true
    else
        print(text)
        return false
    end
end

local EPG = {}

---@param s session
---@param epgip_port string
function EPG.new(s, epgip_port, user_id)
    local comp = {}
    comp.user_id = user_id
    comp.session = s
    ---@type string
    comp.epgip_port = epgip_port
    comp.base_url = 'http://' .. epgip_port .. '/EPG'
    setmetatable(comp, {
        __index = EPG
    })
    return comp
end

function EPG:authLoginHWCTC()
    local u = url.parse(self.base_url) / 'jsp' / 'authLoginHWCTC.jsp'
    print(u)

    local data = {
        UserID = self.user_id,
        VIP = ''
    }

    local res_body = {}
    local res, code = self.session:post {
        url = u:build(),
        headers = headers,
        data = data,
        response_table = res_body,
    }
    local text = table.concat(res_body)
    local encrypt_token = string.match(text, 'EncryptToken%s+=%s+"(.-)";')
    local user_token = string.match(text, 'authform%.userToken%.value%s*=%s*"(.-)";')
    return encrypt_token, user_token
end

---@param encrypt_token string
---@param user_token string
---@return table
function EPG:validAuthenticationHWCTC(encrypt_token, user_token)
    local u = url.parse(self.base_url) / 'jsp' / 'ValidAuthenticationHWCTC.jsp'
    print(u)

    local data = {
        UserID = self.user_id,
        Lang = '',
        SupportHD = ctc_conf.supporthd,
        Authenticator = ctcGetAuthInfo(encrypt_token),
        STBType = ctc_conf.stbtype,
        STBVersion = ctc_conf.stbversion,
        STBID = ctc_conf.stbid,
        templateName = '',
        areaId = '',
        conntype = ctc_conf.conntype,
        userToken = user_token,
        productPackageId = ctc_conf.productpackageid,
        mac = ctc_conf.mac,
        UserField = ctc_conf.userfield,
        SoftwareVersion = ctc_conf.softwareversion,
        IsSmartStb = '',
        desktopId = '',
        stbmaker = '',
        XMPPCapability = '',
        ChipID = '',
        VIP = ''
    }

    local res_body = {}
    local res, code = self.session:post {
        url = u:build(),
        headers = headers,
        data = data,
        response_table = res_body,
    }
    local text = table.concat(res_body)
    return self:extractInputs(text)
end

---@param html string
---@return table
function EPG:extractInputs(html)
    local pattern = '<input%s+type="hidden"%s+name="(.-)"%s+value="(.-)"%s*>'
    local data = {}
    for name, value in string.gmatch(html, pattern) do
        data[name] = value
    end
    return data
end

function EPG:getchannellistHWCTC(form)
    local u = url.parse(self.base_url) / 'jsp' / 'getchannellistHWCTC.jsp'
    print(u)

    local res_body = {}
    local res, code = self.session:post {
        url = u:build(),
        headers = headers,
        data = form,
        response_table = res_body,
    }
    local text = table.concat(res_body)
    return self:extractChannels(text)
end

function EPG:extractChannels(text)
    local results = {}
    for params_str in text:gmatch(".CTCSetConfig%('Channel','(.-)'%)") do
        local result = {}
        for key, value in params_str:gmatch('([%w_]+)="(.-)"') do
            result[key] = value
        end
        table.insert(results, result)
    end
    return results
end

--ChannelLogURL
--TimeShiftLength
--ChannelFECPort
--PositionY
--ChannelLocked   0
--BeginTime       0
--ChannelFCCIP
--UserChannelID   1
--ChannelURL      igmp://
--TimeShift       1
--IsHDChannel     2
--FCCEnable       2
--Lasting
--Interval
--PreviewEnable   0
--ChannelFCCPort  8027
--TimeShiftURL    rtsp://
--ChannelType     1
--PositionX
--ChannelName     CCTV-1
--ChannelSDP      igmp://
--ActionType      1
--ChannelID
--ChannelPurchased        1

local function generateM3u(channels, http_addr)
    local out = '#EXTM3U\n'
    for _, v in pairs(channels) do
        local ip, port = v.ChannelURL:match("igmp://([%d%.]+):(%d+)")
        out = out .. '#EXTINF:-1 tvg-name="' .. v.ChannelName .. '"\n'
        if http_addr then
            local line = 'http://' .. http_addr .. '/rtp/' .. ip .. ':' .. port
            if v.ChannelFCCIP ~= '' then
                line = line .. '?fcc=' .. v.ChannelFCCIP .. ':' .. v.ChannelFCCPort
            end
            out = out .. line .. '\n'
        else
            out = out .. 'udp://' .. ip .. ':' .. port .. '\n'
        end
    end
    return out
end

local config_path = 'ctc_conf.json'
local http_addr = nil
local output = 'iptv.m3u'
for i, a in ipairs(arg) do
    if a == '-h' or a == '--help' then
        print('Usage: lua ' .. arg[0] .. ' [options]')
        print('Options:')
        print('  -h, --help      Show this help message')
        print('  --network       Set the network device')
        print('  --config        Set the configuration path')
        print('  --output        Set the m3u output path')
        print('  --http          Set http [ip:port] for rtp/udp to http')
        os.exit()
    elseif a == '--network' then
        ctc_conf.netdevice = arg[i + 1]
    elseif a == '--config' then
        config_path = arg[i + 1]
    elseif a == '--output' then
        output = arg[i + 1]
    elseif a == '--http' then
        http_addr = arg[i + 1]
    end
end

math.randomseed(os.time())

loadCtcConf(config_path)

local s = session.new()
local ui_cloud_client = UICloudAuthClient.new(ctc_conf.userid, s)
local auth = ui_cloud_client:authentication(true)
ui_cloud_client:authurl(auth)

local form = {}
local epg = EPG.new(s, ui_cloud_client.epgip_port, ctc_conf.userid)
local encrypt_token, user_token = epg:authLoginHWCTC()
form = epg:validAuthenticationHWCTC(encrypt_token, user_token)
local channels = epg:getchannellistHWCTC(form)
local out = generateM3u(channels, http_addr)


local file, err = io.open(output, "w+")
if not file then
    error("Could not open file: " .. err)
end
file:write(out)
file:close()

ui_cloud_client:authentication(false)
