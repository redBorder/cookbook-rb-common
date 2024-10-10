# Cookbook:: rb-common
# Provider:: config

action :configure do
  # nofile settings

  # hard
  execute "ulimit -Hn #{node.default['redborder']['nofile']['hard']}" do
    not_if "ulimit -Hn | grep #{node.default['redborder']['nofile']['hard']}"
  end

  # soft
  execute "ulimit -Sn #{node.default['redborder']['nofile']['soft']}" do
    not_if "ulimit -Sn | grep #{node.default['redborder']['nofile']['soft']}"
  end

  template '/etc/security/limits.d/10-nofile.conf' do
    source '10-nofile.conf.erb'
    cookbook 'rb-common'
    owner 'root'
    owner 'root'
    mode '644'
    retries 2
    variables(soft: node.default['redborder']['nofile']['soft'],
              hard: node.default['redborder']['nofile']['hard'])
  end
end
