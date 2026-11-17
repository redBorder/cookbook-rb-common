# Cookbook:: rb-common
# Recipe:: harden_secrets
#
# Keeps memory (where services hold their secrets) off persistent storage, on managers and sensors:
# encrypted swap, no hibernation image, kdump only keeps the kernel log (no RAM image), no core dumps,
# no Chef backups/diffs on disk.

#################
# Encrypted swap
#################
# The current swap device: in fstab as swap and still carrying a swap signature.
# Checking both matters: crypttab's "swap" option formats the device.
swap_dev = nil
# nofail + a device timeout: systemd-cryptsetup can race with udev after it formats the device, and the crypttab
# generator gives /dev/mapper/swap no timeout, so a boot could wait forever. Then the box boots without swap instead
# (nothing reaches the disk either way).
SWAP_FSTAB_LINE = '/dev/mapper/swap none swap defaults,nofail,x-systemd.device-timeout=60s 0 0'.freeze unless defined?(SWAP_FSTAB_LINE)
if ::File.exist?('/etc/fstab')
  ::File.readlines('/etc/fstab').each do |line|
    f = line.split
    next if f.empty? || f[0].start_with?('#') || f[2] != 'swap' || f[0] == '/dev/mapper/swap'
    dev = f[0]
    swap_dev = dev if shell_out("blkid -o value -s TYPE #{dev}").stdout.strip == 'swap'
    break
  end
end

if swap_dev
  # only needed with a swap device (sensors are often installed without swap)
  dnf_package 'cryptsetup' do
    action :install
  end

  # Plain dm-crypt, new random key every boot: nothing in swap survives a reboot
  file '/etc/crypttab' do
    content(lazy do
      old = ::File.exist?('/etc/crypttab') ? ::File.read('/etc/crypttab').lines.reject { |l| l.split.first == 'swap' }.join : ''
      old + "swap #{swap_dev} /dev/urandom swap,cipher=aes-xts-plain64,size=512,sector-size=4096\n"
    end)
    owner 'root'
    group 'root'
    mode '0600'
  end

  ruby_block 'Use /dev/mapper/swap in fstab' do
    block do
      fstab = ::File.read('/etc/fstab').lines.map do |l|
        f = l.split
        !f.empty? && f[0] == swap_dev && f[2] == 'swap' ? "#{SWAP_FSTAB_LINE}\n" : l
      end
      ::File.write('/etc/fstab', fstab.join)
    end
  end

  # Switch now only if RAM can take what is in swap; otherwise the next boot switches.
  mem = ::File.read('/proc/meminfo').scan(/^(\w+):\s+(\d+)/).to_h.transform_values(&:to_i)
  swap_used_kb = mem['SwapTotal'].to_i - mem['SwapFree'].to_i
  if mem['MemAvailable'].to_i > swap_used_kb + 1_048_576
    execute 'Switch to encrypted swap now' do
      # blkdiscard -z zeroes the old plaintext swap before it is reused
      command "swapoff #{swap_dev} && blkdiscard -z #{swap_dev} && systemctl daemon-reload && " \
              'systemctl start systemd-cryptsetup@swap.service && swapon /dev/mapper/swap'
    end
  else
    Chef::Log.warn("harden_secrets: #{swap_used_kb} kB in swap, not enough free RAM to switch now; encrypted swap starts at next boot")
  end
end

ruby_block 'Encrypted swap never blocks the boot' do
  block do
    fstab = ::File.read('/etc/fstab').lines.map do |l|
      f = l.split
      !f.empty? && f[0] == '/dev/mapper/swap' && f[2] == 'swap' ? "#{SWAP_FSTAB_LINE}\n" : l
    end
    ::File.write('/etc/fstab', fstab.join)
  end
  only_if do
    ::File.exist?('/etc/fstab') && ::File.readlines('/etc/fstab').any? do |l|
      f = l.split
      !f.empty? && f[0] == '/dev/mapper/swap' && f[2] == 'swap' && !f[3].to_s.include?('x-systemd.device-timeout')
    end
  end
  notifies :run, 'execute[systemctl daemon-reload (fstab)]', :immediately
end

execute 'systemctl daemon-reload (fstab)' do
  command 'systemctl daemon-reload'
  action :nothing
end

##############################
# No hibernation, no kdump
##############################
execute 'Remove resume= from the kernel command line' do
  command 'grubby --update-kernel=ALL --remove-args=resume'
  only_if 'grubby --info=ALL | grep -q resume='
end

execute 'Mask hibernation' do
  command 'systemctl mask hibernate.target hybrid-sleep.target suspend-then-hibernate.target'
  not_if 'systemctl is-enabled hibernate.target 2>/dev/null | grep -q masked'
end

# kdump stays (crash analysis), but saves only the kernel log of a crash (vmcore-dmesg.txt). A memory image
# (vmcore) would put every secret held in RAM into /var/crash.
kdump_dmesg_only = 'core_collector makedumpfile --dump-dmesg'
execute 'kdump saves only the kernel log' do
  command "sed -i '/^core_collector /d' /etc/kdump.conf && echo '#{kdump_dmesg_only}' >> /etc/kdump.conf"
  only_if { ::File.exist?('/etc/kdump.conf') }
  not_if "grep -qx '#{kdump_dmesg_only}' /etc/kdump.conf && [ $(grep -c '^core_collector ' /etc/kdump.conf) -eq 1 ]"
  notifies :restart, 'service[kdump]', :delayed # rebuilds the kdump initramfs with the new collector
end

service 'kdump' do
  action [:enable, :start]
  only_if 'systemctl list-unit-files kdump.service | grep -q kdump'
  ignore_failure true # no crashkernel memory reserved (e.g. small VM): kdump cannot start, nothing to dump
end

#############
# No coredumps
#############
directory '/etc/systemd/coredump.conf.d' do
  owner 'root'
  group 'root'
  mode '0755'
end

file '/etc/systemd/coredump.conf.d/50-redborder.conf' do
  content "# Generated by chef: a core dump is process memory, secrets included\n[Coredump]\nStorage=none\nProcessSizeMax=0\n"
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

# Core dumps written before Storage=none
execute 'Wipe old core dumps' do
  command 'find /var/lib/systemd/coredump -type f -exec shred -u {} +'
  only_if 'find /var/lib/systemd/coredump -type f 2>/dev/null | grep -q .'
end

###############
# Chef backups
###############
# Chef keeps a copy of every file it overwrites (old configs with passwords): keep them in memory.
# Chef also prints a diff of every changed file, secrets included, into logs and the journal: off.
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
# Chef keys: no longer world-readable
################################
# admin/validator (managers only) are copies of the Chef server's own keys (the originals stay in /etc/opscode): root only.
# On managers client.pem and the data bag key are read by the webui (user webui) too. Symlinks (OpenBao mode) are left alone.
# The webui group only exists once the webui package is installed (a later step on a new manager, never on sensors)
webui_group = (::Etc.getgrnam('webui') rescue nil) ? 'webui' : 'root'
{ '/etc/chef/admin.pem' => %w(root 0600), '/etc/chef/redborder-validator.pem' => %w(root 0600),
  '/etc/opscode/admin.pem' => %w(root 0600), '/etc/opscode/redborder-validator.pem' => %w(root 0600),
  '/etc/chef/client.pem' => [webui_group, '0640'], '/etc/chef/encrypted_data_bag_secret' => [webui_group, '0640'] }.each do |f, (grp, mode)|
  file f do
    owner 'root'
    group grp
    mode mode
    only_if { ::File.file?(f) && !::File.symlink?(f) }
  end
end
