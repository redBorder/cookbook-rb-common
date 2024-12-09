# Cookbook:: rb-common
# Provider:: config

action :configure do
  # nofile settings
  hard = new_resource.hard
  soft = new_resource.soft
  sensor_role = new_resource.sensor_role

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

  if sensor_role
    sensor_id = node["redborder"]["sensor_id"]
    if sensor_id.nil?
      sensor_id = 0
    else
      sensor_id = sensor_id.to_i
    end
    
    template '/etc/rb-id' do
      source 'variable.erb'
      cookbook 'rb-common'
      owner 'root'
      group 'root'
      mode '600'
      retries 2
      backup false
      variables(variable: sensor_id)
    end

    template '/etc/chef/role.json' do
      source 'role.json.erb'
      cookbook 'rb-common'
      owner 'root'
      group 'root'
      mode '644'
      retries 2
      variables(sensor_role: sensor_role, sensor_id: sensor_id)
    end
    
    template '/etc/chef/role-once.json' do
      source 'role-once.json.erb'
      cookbook 'rb-common'
      owner 'root'
      group 'root'
      mode '644'
      retries 2
      variables(sensor_role: sensor_role, sensor_id: sensor_id)
    end
  end
end
