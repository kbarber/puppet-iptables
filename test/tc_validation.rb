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

class TestIPTablesValidation < Test::Unit::TestCase
  require 'puppettest'
  include Puppettest

  # Check to make sure names cannot have quotes
  def test_invalid_name
    out,err = run_dsl('iptables {"asdf\'": proto => "tcp", state => "NEW" }')
    assert_match(/Parameter name failed/, err)
  end

  # Check to make sure you can't define chains that fall outside of the 
  # built-ins
  def test_chain_name
    out,err = run_dsl('iptables {name: chain => "foobar" }')
    assert_match(/Parameter chain failed/, err)
  end

  # Make sure you can't use tables that don't exist
  def test_table_name
    out,err = run_dsl('iptables {name: table => "foobar" }')
    assert_match(/Parameter table failed/, err)
  end

end
