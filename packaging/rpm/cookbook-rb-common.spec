Name: cookbook-rb-common
Version: %{__version}
Release: %{__release}%{?dist}
BuildArch: noarch
Summary: redborder common cookbook to configure redborder system settings

License: AGPL 3.0
URL: https://github.com/redBorder/cookbook-rb-common
Source0: %{name}-%{version}.tar.gz

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build

%install
mkdir -p %{buildroot}/var/chef/cookbooks/rb-common
cp -f -r  resources/* %{buildroot}/var/chef/cookbooks/rb-common/
chmod -R 0755 %{buildroot}/var/chef/cookbooks/rb-common
install -D -m 0644 README.md %{buildroot}/var/chef/cookbooks/rb-common/README.md

%pre
if [ -d /var/chef/cookbooks/rb-common ]; then
    rm -rf /var/chef/cookbooks/rb-common
fi

%post
case "$1" in
  1)
    # This is an initial install.
    :
  ;;
  2)
    # This is an upgrade.
    su - -s /bin/bash -c 'source /etc/profile && rvm gemset use default && env knife cookbook upload rb-common'
  ;;
esac

%postun
# Deletes directory when uninstall the package
if [ "$1" = 0 ] && [ -d /var/chef/cookbooks/rb-common ]; then
  rm -rf /var/chef/cookbooks/rb-common
fi

%files
%defattr(0755,root,root)
/var/chef/cookbooks/rb-common
%defattr(0644,root,root)
/var/chef/cookbooks/rb-common/README.md

%doc

%changelog
* Thu Oct 10 2024 Miguel Negrón <manegron@redborder.com>
- Add pre and postun

* Thu May 21 2024 Miguel Negrón <manegron@redborder.com>
- Inital version
