# Puppet Iptables Module
#
# Copyright (C) 2011 Bob.sh Limited
# Copyright (C) 2008 Camptocamp Association
# Copyright (C) 2007 Dmitri Priimak
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'find'

desc "Run puppet tests."
task :test, :path do |t, args|
  args.with_defaults(:path => ".")

  paths = []

  Find.find(args.path) do |path|
    if path =~ /tests\/\d+.+\.pp/
      paths << path
    end
  end

  paths.sort.each do |path|
    print("Processing " + path + ": ")
    result = `puppet --noop --modulepath=. #{path} 2>&1`
    if $?.exitstatus == 0
      puts("\tSuccess")
    else
      puts("\tFailed")
      puts(result)
    end
  end
end
