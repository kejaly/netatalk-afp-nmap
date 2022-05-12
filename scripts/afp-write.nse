local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ls = require "ls"

description = [[
Attempts to get useful information about files from AFP volumes.
The output is intended to resemble the output of <code>ls</code>.
]]

-- Version 0.2
-- Created 04/03/2011 - v0.1 - created by Patrik Karlsson
-- Modified 08/02/2020 - v0.2 - replaced individual date/size/ownership calls
--                              with direct sourcing from the output of
--                              afp.Helper.Dir


author = "Patrik Karlsson"
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
    local localfile = args['localfile']
    local rpath = args["rpath"]
    print(rpath)
    if not(localfile) or not(rpath) then 
      return false,"need localfile and rpath args"
    end
    
    local handle = io.open(localfile, "r")
    if(not(handle)) then
      return false, string.format("Couldn't find the file to upload (%s)", localfile)
    end

    local fdata = handle:read("a")


    afpHelper:WriteFile(rpath,fdata)




    status, response = afpHelper:Logout()
    status, response = afpHelper:CloseSession()

  end
  return 'write'
end
