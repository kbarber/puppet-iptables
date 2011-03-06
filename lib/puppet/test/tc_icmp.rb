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

class TestIPTablesIcmp < Test::Unit::TestCase
  require 'puppettest'
  include Puppettest

  #########
  # Tests #
  #########
  def test_icmp_type
    out,err = run_dsl('iptables {"icmp_type":	source => "0.0.0.0", destination => "0.0.0.0", proto => "icmp",	icmp => "echo-reply" }')
    assert_match(/iptables -t filter -A INPUT -s 0.0.0.0\/32 -d 0.0.0.0\/32 -p icmp -m icmp --icmp-type 0 -m comment --comment "icmp_type" -j ACCEPT/, out)
  end

  def test_icmp_type_invalid
    out,err = run_dsl('iptables {"icmp_type_invalid":	source => "0.0.0.0",	destination => "0.0.0.0",	proto => "icmp",	icmp => "foo" }')
    assert_match(/Value for 'icmp' is invalid\/unknown. Ignoring rule./, out)
  end

  def test_icmp_type_any
    out,err = run_dsl('iptables {"icmp_type_any": source => "0.0.0.0", destination => "0.0.0.0", proto => "icmp" }')
    assert_match(/iptables -t filter -A INPUT -s 0.0.0.0\/32 -d 0.0.0.0\/32 -p icmp -m icmp --icmp-type any -m comment --comment \"icmp_type_any\" -j ACCEPT/, out)
  end

end
