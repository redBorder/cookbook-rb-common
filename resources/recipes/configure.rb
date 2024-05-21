#
# Cookbook Name:: common
# Recipe:: configure
#
# Copyright 2024, redborder
#
# AFFERO GENERAL PUBLIC LICENSE V3
#

# Services configuration


# nofile settings
template "/etc/security/limits.d/10-nofile.conf" do
  source "10-nofile.conf.erb"
  cookbook "rb-common"
  owner "root"
  owner "root"
  mode 0644
  retries 2
end

  
