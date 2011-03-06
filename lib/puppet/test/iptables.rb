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

    # location where iptables binaries are to be found
    @@iptables_dir = "/sbin"

    # Bellow is a set of relatively rudimentary tests for iptables type.
    # Please *NOTE* that it relies on files pre.iptables and
    # post.iptables in /etc/puppet/iptables/ to be either empty or absent.
    def test_iptables_set_close
        text = 'iptables {name: proto => "tcp", state => "NEW" }'
        stdin, stdout, stderr = Open3.popen3("puppet apply --debug --libdir=../../ --color=false")
        stdin.puts(text)
        stdin.close

        out = ""
        while lnout = stdout.gets do
          out << lnout
        end
        puts out

        err = ""
        while lnerr = stderr.gets do
          err << lnerr
        end
        puts err
    end

    def test_iptables_set_open
        rules = Puppet.type(:iptables).create :name => '80', :proto => 'tcp', :state => :open
        assert_apply(rules)
        assert_rule_present     "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"
        assert_rule_not_present "-A INPUT -p tcp -m tcp --dport 80 -j DROP"
    end

    def test_iptables_set_different_port
        rules = Puppet.type(:iptables).create :name => '8080', :proto => 'tcp', :state => :open
        assert_apply(rules)
        assert_rule_present     "-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT"
        assert_rule_not_present "-A INPUT -p tcp -m tcp --dport 80 -j ACCEPT"
        assert_rule_not_present "-A INPUT -p tcp -m tcp --dport 80 -j DROP"
    end

    def test_iptables_udp_source_destination
        rules = Puppet.type(:iptables).create :name => '9124', :proto => 'udp', :state => :close, :source => '127.0.0.1'
        assert_apply(rules)
        assert_rule_present     "-A INPUT -s 127.0.0.1 -p udp -m udp --dport 9124 -j DROP"
        assert_rule_not_present "-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT"
    end

    def test_iptables_udp_nat_prerouting
        rules = Puppet.type(:iptables).create :name => '22', :proto => 'tcp',
            :state => :close, :source => '18.7.22.83', :destination => '127.0.0.1',
            :table =>  'nat', :chain => 'PREROUTING'
        assert_apply(rules)
        assert_rule_present     "-A PREROUTING -s 18.7.22.83 -d 127.0.0.1 -p tcp -m tcp --dport 22 -j DROP"
        assert_rule_not_present "-A INPUT -s 127.0.0.1 -p udp -m udp --dport 9124 -j DROP"
    end

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
end
