# Cookbook:: rb-common
# Resource:: config

actions :configure
default_action :configure

attribute :soft, kind_of: Integer, default: 65535
attribute :hard, kind_of: Integer, default: 65535
