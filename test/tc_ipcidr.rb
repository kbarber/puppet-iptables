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
require 'puppet/util/ipcidr'

class TestIPTablesIcmp < Test::Unit::TestCase

  #########
  # Tests #
  #########
  def test_cidr_1
    ip = Puppet::Util::IpCidr.new("127.0.0.1/255.255.255.0")
    assert_equal("127.0.0.0/24", ip.cidr)
  end

  def test_cidr_2
    ip = Puppet::Util::IpCidr.new("10.2.4.0/255.255.128.0")
    assert_equal("10.2.0.0/17", ip.cidr)
  end

  def test_cidr6_1
    ip = Puppet::Util::IpCidr.new("2001:470:1f08:ef0:aeb2:09fb::3/64")
    assert_equal("2001:470:1f08:ef0::/64", ip.cidr)
  end

  def test_prefixlen_1
    ip = Puppet::Util::IpCidr.new("127.0.0.1/255.128.0.0")
    assert_equal(9, ip.prefixlen)
  end

  def test_prefixlen6_1
    ip = Puppet::Util::IpCidr.new("dead:beef:00c0::/67")
    assert_equal(67, ip.prefixlen)
  end

  def test_netmask_1
    ip = Puppet::Util::IpCidr.new("127.0.0.1/19")
    assert_equal("255.255.224.0", ip.netmask)
  end

  def test_netmask6_1
    ip = Puppet::Util::IpCidr.new("dead:beef::/64")
    assert_equal("ffff:ffff:ffff:ffff:0000:0000:0000:0000", ip.netmask)
  end
end
