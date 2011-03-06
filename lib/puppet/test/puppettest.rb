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

require 'open3'

module Puppettest 

  # location where iptables binaries are to be found
  @@iptables_dir = "/sbin"

  #############################################
  # Convenience methods and custom assertions #
  #############################################
  def assert_rule_present(rule)
    assert_rule(rule, true)
  end

  def assert_rule_not_present(rule)
    assert_rule(rule, false)
  end

  def assert_rule(rule, negative = true)
    present = false

    assert_nothing_raised do
      `#{@@iptables_dir}/iptables-save`.each { |l|
        l.strip!
        if( l == rule )
          present = true
          break
        end
      }

      if negative
        raise "Rule not present" unless present
      else
        raise "Rule present" unless !present
      end
    end

  end

  def run_dsl(dsl)
    cmd = 'puppet apply --debug --libdir=../../ --color=false'

    stdin, stdout, stderr = Open3.popen3(cmd)
    stdin.puts(dsl)
    stdin.close

    out = ""
    while ln = stdout.gets do
      out << ln
    end

    err = ""
    while ln = stderr.gets do
      err << ln
    end

    return out,err
  end
end
