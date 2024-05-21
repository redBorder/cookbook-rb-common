
# Cookbook Name:: rb-common
#
# Provider:: config
#

action :configure do
  # nofile settings
  template "/etc/security/limits.d/10-nofile.conf" do
    source "10-nofile.conf.erb"
    cookbook "rb-common"
    owner "root"
    owner "root"
    mode 0644
    retries 2
    variables(:soft => node[:redborder][:nofile][:soft], 
              :hard => node[:redborder][:nofile][:hard])
  end
end
