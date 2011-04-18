#!/usr/bin/env ruby

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

require 'test/unit'
require 'puppettest'

class TestIPTables < Test::Unit::TestCase
  require 'puppettest'
  include Puppettest

  def flush_rules
    `iptables -F -t filter`
    `iptables -F -t nat`
    `iptables -F -t mangle`
    `iptables -F -t raw`
  end

  def setup
    flush_rules
  end

  def teardown
    flush_rules
  end

  #########
  # Tests #
  #########
  def test_iptables_state_new
    out,err = run_dsl('iptables {name: proto => "tcp", state => "NEW" }')
    assert_match(/iptables -I INPUT 1 -t filter -p tcp -m state --state NEW --jump ACCEPT -m comment --comment name/, out, err)
  end

  def test_iptables_set_established
    out,err = run_dsl('iptables {name: proto => "tcp", state => "ESTABLISHED"}')
    assert_match(/iptables -I INPUT 1 -t filter -p tcp -m state --state ESTABLISHED --jump ACCEPT -m comment --comment name/, out, err)
  end

  def test_iptables_set_different_port
    out,err = run_dsl('iptables {name: proto => "tcp", dport => "8000", state => "ESTABLISHED"}')
    assert_match(/-I INPUT 1 -t filter -p tcp --dport 8000 -m state --state ESTABLISHED --jump ACCEPT -m comment --comment name/, out, err)
  end

  def test_iptables_udp_source_destination
    out,err = run_dsl('iptables {name: proto => "udp", dport => "1234", source => "127.0.0.1", state => "ESTABLISHED"}')
    assert_match(/iptables -I INPUT 1 -t filter -p udp -s 127.0.0.1 --dport 1234 -m state --state ESTABLISHED --jump ACCEPT -m comment --comment name/, out, err)
  end

  def test_iptables_udp_nat_prerouting
    out,err = run_dsl('iptables {name: proto => "tcp", dport => "1234", source => "127.0.0.1", destination => "127.0.0.1", state => "ESTABLISHED", table => "nat", chain => "PREROUTING"}')
    assert_match(/iptables -I PREROUTING 1 -t nat -p tcp -s 127.0.0.1 -d 127.0.0.1 --dport 1234 -m state --state ESTABLISHED --jump ACCEPT -m comment --comment name/, out, err)
  end

  def test_source_dest
    out,err = run_dsl('iptables { "test rule": source => "0.0.0.0",	destination => "0.0.0.0" }')
    assert_match(/iptables -I INPUT 1 -t filter -p tcp -s 0.0.0.0 -d 0.0.0.0 --jump ACCEPT -m comment --comment test rule/, out, err)
  end  

  def test_sport_dport
    out,err = run_dsl('iptables { "sport and dport": source => "0.0.0.0", sport => "14", destination => "0.0.0.0", dport => "15" }')
    assert_match(/iptables -I INPUT 1 -t filter -p tcp -s 0.0.0.0 --sport 14 -d 0.0.0.0 --dport 15 --jump ACCEPT -m comment --comment sport and dport/, out, err)
  end
end
