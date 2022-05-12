local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ls = require "ls"

description = [[
Attempts to read files from AFP volumes..
]]



author = "keeee"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
dependencies = {"afp-brute"}

-- portrule = shortport.port_or_service(548, {"afp"})
portrule = shortport.portnumber({548, 32884})

action = function(host, port)

  local afpHelper = afp.Helper:new()
  local args = nmap.registry.args
  local users = nmap.registry.afp or { ['nil'] = 'nil' }
  local maxfiles = ls.config("maxfiles")
  local output = ls.new_listing()

  if ( args['afp.username'] ) then
    users = {}
    users[args['afp.username']] = args['afp.password']
  end

  for username, password in pairs(users) do

    local status, response = afpHelper:OpenSession(host, port)
    if ( not status ) then
      stdnse.debug1("%s", response)
      return
    end

    -- if we have a username attempt to authenticate as the user
    -- Attempt to use No User Authentication?
    if ( username ~= 'nil' ) then
      status, response = afpHelper:Login(username, password)
    else
      status, response = afpHelper:Login()
    end

    if ( not status ) then
      stdnse.debug1("Login failed")
      stdnse.debug3("Login error: %s", response)
      return
    end


    ------------------ 上面是登录。

   
    -- 不想通过参数传递，这里直接用赋值也可以。
    -- local str_path = "test/exp"

    local rpath = args["rpath"]
    if(not(rpath)) then
      return false,"need rpath arg"
    end

    local flag = args["flag"]
    if( flag ~= "0" and flag ~= "1") then
      return false,"need flag arg, 0 for normal file ,  1 for adouble file"
    end

    local content
    if flag=="1" then 
      status, content = afpHelper:ReadFile2(rpath)  -- for adouble file
    elseif flag=="0" then
      status, content = afpHelper:ReadFile(rpath)   -- for normal file
    end

    

    status, response = afpHelper:Logout()
    status, response = afpHelper:CloseSession()
    return  content

  end
  return "read"
end
