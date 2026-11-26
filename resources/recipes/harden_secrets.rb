# Cookbook:: rb-common
# Recipe:: harden_secrets
#
# Security hardening for managers and sensors, for the requirement that no credentials or keys are stored in
# plaintext on persistent storage (LINCE/CCN). Services hold their passwords and keys in memory; this recipe makes
# sure memory contents are not written to disk either: encrypted swap, no hibernation image, no memory dumps
# (kdump, core dumps), no Chef backup copies or diffs of configuration files, and restrictive permissions on the
# Chef keys that remain on disk.

#################
# Encrypted swap
#################
# Swap is encrypted with dm-crypt and a random key generated at every boot, so pages written to swap cannot be read
# after a power-off. The device is listed in /etc/crypttab and activated by rb-swap.service instead of /etc/fstab:
# with fstab, systemd sometimes does not detect /dev/mapper/swap in time and the system boots without swap.
# The swap device is taken from /etc/fstab and confirmed by its signature, because the crypttab "swap" option
# reformats the device at every boot.
swap_dev = nil
if ::File.exist?('/etc/fstab')
  ::File.readlines('/etc/fstab').each do |line|
    f = line.split
    next if f.empty? || f[0].start_with?('#') || f[2] != 'swap' || f[0] == '/dev/mapper/swap'
    dev = f[0]
    swap_dev = dev if shell_out("blkid -o value -s TYPE #{dev}").stdout.strip == 'swap'
    break
  end
end
crypt_swap = proc { ::File.exist?('/etc/crypttab') && ::File.readlines('/etc/crypttab').any? { |l| l.split.first == 'swap' } }

if swap_dev
  dnf_package 'cryptsetup' do
    action :install
  end

  file '/etc/crypttab' do
    content(lazy do
      old = ::File.exist?('/etc/crypttab') ? ::File.read('/etc/crypttab').lines.reject { |l| l.split.first == 'swap' }.join : ''
      old + "swap #{swap_dev} /dev/urandom swap,cipher=aes-xts-plain64,size=512,sector-size=4096\n"
    end)
    owner 'root'
    group 'root'
    mode '0600'
  end
end

ruby_block 'No swap lines in fstab (rb-swap.service activates the encrypted swap)' do
  block do
    fstab = ::File.read('/etc/fstab').lines.reject do |l|
      f = l.split
      !f.empty? && f[2] == 'swap' && (f[0] == '/dev/mapper/swap' || f[0] == swap_dev)
    end
    ::File.write('/etc/fstab', fstab.join)
  end
  only_if do
    crypt_swap.call && ::File.readlines('/etc/fstab').any? do |l|
      f = l.split
      !f.empty? && f[2] == 'swap' && (f[0] == '/dev/mapper/swap' || f[0] == swap_dev)
    end
  end
  notifies :run, 'execute[systemctl daemon-reload (swap)]', :immediately
end

file '/etc/systemd/system/rb-swap.service' do
  content <<~UNIT
    [Unit]
    Description=Encrypted swap (new random key every boot)
    Requires=systemd-cryptsetup@swap.service
    After=systemd-cryptsetup@swap.service
    Before=swap.target

    [Service]
    Type=oneshot
    RemainAfterExit=yes
    ExecStart=/usr/sbin/swapon /dev/mapper/swap
    ExecStop=/usr/sbin/swapoff /dev/mapper/swap

    [Install]
    WantedBy=swap.target
  UNIT
  mode '0644'
  only_if { crypt_swap.call }
  notifies :run, 'execute[systemctl daemon-reload (swap)]', :immediately
end

execute 'systemctl daemon-reload (swap)' do
  command 'systemctl daemon-reload'
  action :nothing
end

service 'rb-swap' do
  action :enable
  only_if { crypt_swap.call }
end

if swap_dev
  # Switching moves the current swap contents into RAM: without enough free memory the switch happens at the next boot
  mem = ::File.read('/proc/meminfo').scan(/^(\w+):\s+(\d+)/).to_h.transform_values(&:to_i)
  swap_used_kb = mem['SwapTotal'].to_i - mem['SwapFree'].to_i
  if mem['MemAvailable'].to_i > swap_used_kb + 1_048_576
    execute 'Switch to encrypted swap now' do
      command "swapoff #{swap_dev} && blkdiscard -z #{swap_dev} && systemctl start rb-swap.service"
    end
  else
    Chef::Log.warn("harden_secrets: #{swap_used_kb} kB in swap, not enough free RAM to switch now; encrypted swap starts at next boot")
  end
end

execute 'Start the encrypted swap' do
  command 'systemctl start rb-swap.service'
  only_if { crypt_swap.call && ::File.read('/proc/swaps').lines.size <= 1 }
end

##############################
# No hibernation, no kdump
##############################
# Hibernation would write the full memory to disk.
execute 'Remove resume= from the kernel command line' do
  command 'grubby --update-kernel=ALL --remove-args=resume'
  only_if 'grubby --info=ALL | grep -q resume='
end

execute 'Mask hibernation' do
  command 'systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target'
  not_if 'systemctl is-enabled hibernate.target 2>/dev/null | grep -q masked'
end

# A full memory dump (vmcore) would contain every secret in memory: kdump saves only the kernel log
kdump_dmesg_only = 'core_collector makedumpfile --dump-dmesg'
execute 'kdump saves only the kernel log' do
  command "sed -i '/^core_collector /d' /etc/kdump.conf && echo '#{kdump_dmesg_only}' >> /etc/kdump.conf"
  only_if { ::File.exist?('/etc/kdump.conf') }
  not_if "grep -qx '#{kdump_dmesg_only}' /etc/kdump.conf && [ $(grep -c '^core_collector ' /etc/kdump.conf) -eq 1 ]"
  notifies :restart, 'service[kdump]', :delayed
end

service 'kdump' do
  action [:enable, :start]
  only_if 'systemctl list-unit-files kdump.service | grep -q kdump'
  ignore_failure true # no crashkernel memory (small VM): kdump cannot start
end

#############
# No coredumps
#############
# A core dump contains the memory of the crashed process, including the secrets it holds.
directory '/etc/systemd/coredump.conf.d' do
  owner 'root'
  group 'root'
  mode '0755'
end

file '/etc/systemd/coredump.conf.d/50-redborder.conf' do
  content "# Generated by chef (cookbook-rb-common)\n[Coredump]\nStorage=none\nProcessSizeMax=0\n"
  owner 'root'
  group 'root'
  mode '0644'
end

file '/etc/sysctl.d/50-redborder-coredump.conf' do
  content "fs.suid_dumpable = 0\n"
  owner 'root'
  group 'root'
  mode '0644'
  notifies :run, 'execute[sysctl-coredump]', :immediately
end

execute 'sysctl-coredump' do
  command 'sysctl -p /etc/sysctl.d/50-redborder-coredump.conf'
  action :nothing
end

# Core dumps written before this configuration was applied
execute 'Wipe old core dumps' do
  command 'find /var/lib/systemd/coredump -type f -exec shred -u {} +'
  only_if 'find /var/lib/systemd/coredump -type f 2>/dev/null | grep -q .'
end

###############
# Chef backups
###############
# chef-client keeps a copy of every configuration file it replaces (/var/chef/backup) and prints file diffs to its
# log; both can contain passwords. Backups go to /run (memory only) and diffs are disabled.
chef_client_settings = { 'file_backup_path' => '"/run/chef-backup"', 'diff_disabled' => 'true' }
ruby_block 'Chef: backups in /run, no diffs in logs' do
  block do
    rb = ::File.read('/etc/chef/client.rb')
    chef_client_settings.each_key { |k| rb = rb.gsub(/^#{k}\s.*\n/, '') }
    ::File.write('/etc/chef/client.rb', rb + chef_client_settings.map { |k, v| "#{k} #{v}\n" }.join)
  end
  only_if { ::File.exist?('/etc/chef/client.rb') }
  not_if do
    rb = ::File.read('/etc/chef/client.rb')
    chef_client_settings.all? { |k, v| rb.include?("#{k} #{v}\n") }
  end
end

execute 'Wipe Chef file backups on disk' do
  command 'find /var/chef/backup -type f -exec shred -u {} + ; find /var/chef/backup -mindepth 1 -type d -empty -delete'
  only_if 'find /var/chef/backup -type f 2>/dev/null | grep -q .'
end

################################
# Chef keys: restrictive permissions
################################
# Installations before this change made these keys readable by every user. They are now readable by root only; on
# managers the webui group also reads the node key and the data bag key. Keys provided by OpenBao (symlinks to
# /run) are not changed. The webui group exists only once the webui package is installed.
webui_group = (::Etc.getgrnam('webui') rescue nil) ? 'webui' : 'root'
{ '/etc/chef/admin.pem' => %w(root 0600), '/etc/chef/redborder-validator.pem' => %w(root 0600),
  '/etc/cinc-project/admin.pem' => %w(root 0600), '/etc/cinc-project/redborder-validator.pem' => %w(root 0600),
  '/etc/chef/client.pem' => [webui_group, '0640'], '/etc/chef/encrypted_data_bag_secret' => [webui_group, '0640'] }.each do |f, (grp, mode)|
  file f do
    owner 'root'
    group grp
    mode mode
    only_if { ::File.file?(f) && !::File.symlink?(f) }
  end
end
