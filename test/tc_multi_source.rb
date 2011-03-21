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

class TestIPTablesMultiSource < Test::Unit::TestCase
  require 'puppettest'
  include Puppettest

  #########
  # Tests #
  #########
  def test_multi_source
    out,err = run_dsl('iptables {"multiple sources 1": source => ["1.2.3.4/32","4.3.2.1/32"],	dport => 15, jump => "ACCEPT" }')
    assert_match(/iptables -t filter -A INPUT -s 1.2.3.4\/32 -p tcp -m tcp --dport 15 -m comment --comment \"multiple sources 1\" -j ACCEPT/, out, err)
    assert_match(/iptables -t filter -A INPUT -s 4.3.2.1\/32 -p tcp -m tcp --dport 15 -m comment --comment \"multiple sources 1\" -j ACCEPT/, out, err)    
  end

end
