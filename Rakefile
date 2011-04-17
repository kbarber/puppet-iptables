# Puppet Iptables Module
#
# Copyright (C) 2011 Bob.sh Limited
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

require 'rake'
require 'rake/testtask'
require 'rake/rdoctask'

task :default => [:test]

desc "Run basic tests"
Rake::TestTask.new(:test) { |t|
  t.libs << "test"
  t.pattern = 'test/tc_*.rb'
  t.verbose = true
  t.warning = true
}

Rake::RDocTask.new(:rdoc) { |rd|
  rd.main = "README.rdoc"
  rd.rdoc_files.include("README.rdoc", "lib/**/*.rb")
  rd.options << "--all"
}
