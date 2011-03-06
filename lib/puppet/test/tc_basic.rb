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

require 'test/unit'
require 'puppettest'

class TestIPTables < Test::Unit::TestCase
  require 'puppettest'
  include Puppettest

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

  def test_source_dest
    out,err = run_dsl('iptables { "test rule": source => "0.0.0.0",	destination => "0.0.0.0" }')
    assert_match(/iptables -t filter -A INPUT -s 0.0.0.0\/32 -d 0.0.0.0\/32 -p tcp -m tcp -m comment --comment \"test rule\" -j ACCEPT/, out)
  end  

  def test_sport_dport
    out,err = run_dsl('iptables { "sport and dport": source => "0.0.0.0", sport => "14", destination => "0.0.0.0", dport => "15" }')
    assert_match(/iptables -t filter -A INPUT -s 0.0.0.0\/32 -d 0.0.0.0\/32 -p tcp -m tcp --sport 14 --dport 15 -m comment --comment \"sport and dport\" -j ACCEPT/, out)
  end
end
