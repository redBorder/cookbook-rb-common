# Cookbook:: rb-common
# Provider:: config

action :configure do
  # nofile settings
  hard = new_resource.hard
  soft = new_resource.soft

  # hard
  execute "ulimit -Hn #{hard}" do
    not_if "ulimit -Hn | grep #{hard}"
  end

  # soft
  execute "ulimit -Sn #{soft}" do
    not_if "ulimit -Sn | grep #{soft}"
  end

  template '/etc/security/limits.d/10-nofile.conf' do
    source '10-nofile.conf.erb'
    cookbook 'rb-common'
    owner 'root'
    owner 'root'
    mode '644'
    retries 2
    variables(soft: soft,
              hard: hard)
  end
end
