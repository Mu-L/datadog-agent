# Unless explicitly stated otherwise all files in this repository are licensed
# under the Apache License Version 2.0.
# This product includes software developed at Datadog (https:#www.datadoghq.com/).
# Copyright 2016-present Datadog, Inc.

require './lib/ostools.rb'
require 'pathname'

name 'installer'

source path: '..',
       options: {
         exclude: ["**/testdata/**/*"],
       }
relative_path 'src/github.com/DataDog/datadog-agent'

build do
  license :project_license

  # set GOPATH on the omnibus source dir for this software
  gopath = Pathname.new(project_dir) + '../../../..'
  etc_dir = "/etc/datadog-agent"
  gomodcache = Pathname.new("/modcache")
  env = {
    'GOPATH' => gopath.to_path,
    'PATH' => "#{gopath.to_path}/bin:#{ENV['PATH']}",
  }

  unless ENV["OMNIBUS_GOMODCACHE"].nil? || ENV["OMNIBUS_GOMODCACHE"].empty?
    gomodcache = Pathname.new(ENV["OMNIBUS_GOMODCACHE"])
    env["GOMODCACHE"] = gomodcache.to_path
  end

  # include embedded path (mostly for `pkg-config` binary)
  env = with_embedded_path(env)

  if linux_target?
    command "invoke installer.build --no-cgo --run-path=/opt/datadog-packages/run --install-path=#{install_dir}", env: env
    mkdir "#{install_dir}/bin"
    copy 'bin/installer', "#{install_dir}/bin/"
  elsif windows_target?
    command "dda inv -- -e installer.build --install-path=#{install_dir}", env: env
    copy 'bin/installer/installer.exe', "#{install_dir}/datadog-installer.exe"
  end

  # Remove empty/unneeded folders
  delete "#{install_dir}/embedded/bin"
  delete "#{install_dir}/embedded/lib"
  delete "#{install_dir}/embedded/"
end
