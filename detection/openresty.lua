-- Lab-only OpenResty check. Blocks upload_progress in multipart bodies.
local _M = {}

function _M.check()
    if ngx.req.get_method() ~= "POST" then
        return
    end
    ngx.req.read_body()
    local body = ngx.req.get_body_data() or ""
    if body:find("PHP_SESSION_UPLOAD_PROGRESS", 1, true) then
        ngx.log(ngx.WARN, "php2shell upload_progress field blocked")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

return _M
