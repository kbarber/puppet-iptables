#!/usr/bin/env ruby

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

$:.unshift("../../lib") if __FILE__ =~ /\.rb$/

require 'test/unit'
require 'open3'

class TestIPTables < Test::Unit::TestCase

  # def setup
  # end

  # def teardown
  # end

  # location where iptables binaries are to be found
  @@iptables_dir = "/sbin"

  #########
  # Tests #
  #########
  def test_iptables_state_new
    out,err = run_dsl('iptables {name: proto => "tcp", state => "NEW" }')
    assert_match(/iptables -t filter -A INPUT -p tcp -m tcp -m state --state NEW -m comment --comment "name" -j ACCEPT/, out)
  end

  def test_iptables_set_established
    out,err = run_dsl('iptables {name: proto => "tcp", state => "ESTABLISHED"}')
    assert_match(/iptables -t filter -A INPUT -p tcp -m tcp -m state --state ESTABLISHED -m comment --comment "name" -j ACCEPT/, out)
  end

  def test_iptables_set_different_port
    out,err = run_dsl('iptables {name: proto => "tcp", dport => "8000", state => "ESTABLISHED"}')
    assert_match(/iptables -t filter -A INPUT -p tcp -m tcp --dport 8000 -m state --state ESTABLISHED -m comment --comment "name" -j ACCEPT/, out)
  end

  def test_iptables_udp_source_destination
    out,err = run_dsl('iptables {name: proto => "udp", dport => "1234", source => "127.0.0.1", state => "ESTABLISHED"}')
    assert_match(/iptables -t filter -A INPUT -s 127.0.0.1\/32 -p udp -m udp --dport 1234 -m state --state ESTABLISHED -m comment --comment "name" -j ACCEPT/, out)
  end

  def test_iptables_udp_nat_prerouting
    out,err = run_dsl('iptables {name: proto => "tcp", dport => "1234", source => "127.0.0.1", destination => "127.0.0.1", state => "ESTABLISHED", table => "nat", chain => "PREROUTING"}')
    assert_match(/iptables -t nat -A PREROUTING -s 127.0.0.1\/32 -d 127.0.0.1\/32 -p tcp -m tcp --dport 1234 -m state --state ESTABLISHED -m comment --comment "name" -j ACCEPT/, out)
  end

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
