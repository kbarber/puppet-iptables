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

require "ipaddr"
require 'resolv'
require 'puppet/util/iptables'
require 'puppet/util/ipcidr'

module Puppet
  newtype(:iptables) do
    include Puppet::Util::Iptables

    @doc = "Manipulate iptables rules"

    ensurable do
      desc "Create or remove this rule."

      newvalue(:present) do
        provider.create
      end

      newvalue(:absent) do
        provider.delete
      end

      defaultto :present
    end

    newparam(:name) do
      desc "The name of the rule."
      isnamevar

      # Keep rule names simple
      validate do |value|
        if value !~ /^[a-zA-Z0-9 \-_]+$/ then
          self.fail "Not a valid rule name. Make sure it contains ASCII " \
            "alphanumeric, spaces, hyphens or underscoares." 
        end
      end
    end

    newparam(:chain) do
      desc "holds value of iptables -A parameter.
        Possible values are: 'INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 
        'POSTROUTING'. Default value is 'INPUT'"
      newvalues(:INPUT, :FORWARD, :OUTPUT, :PREROUTING, :POSTROUTING)
      defaultto "INPUT"
    end

    newparam(:table) do
      desc "The value for the iptables -t parameter. Can be one of the 
        following tables: 'nat', 'mangle', 'filter' and 'raw'. Default one is 
        'filter'"
      newvalues(:nat, :mangle, :filter, :raw)
      defaultto "filter"
    end

    newparam(:proto) do
      desc "holds value of iptables --protocol parameter.
                  Possible values are: 'tcp', 'udp', 'icmp', 'esp', 'ah', 'vrrp', 'igmp', 'all'.
                  Default value is 'tcp'"
      newvalues(:tcp, :udp, :icmp, :esp, :ah, :vrrp, :igmp, :all)
      defaultto "tcp"
    end

    newparam(:jump) do
      desc "holds value of iptables --jump target
                  Possible values are: 'ACCEPT', 'DROP', 'REJECT', 'DNAT', 'SNAT', 'LOG', 'MASQUERADE', 'REDIRECT'.
                  Default value is 'ACCEPT'. While this is not the accepted norm, this is the more commonly used jump target.
                  Users should ensure they do an explicit DROP for all packets after all the ACCEPT rules are specified."
      newvalues(:ACCEPT, :DROP, :REJECT, :DNAT, :SNAT, :LOG, :MASQUERADE, :REDIRECT)
      defaultto "ACCEPT"
    end

    newparam(:source) do
      desc "value for iptables --source parameter.
                  Accepts a single string or array."
    end

    newparam(:destination) do
      desc "value for iptables --destination parameter"
    end

    newparam(:sport) do
      desc "holds value of iptables [..] --source-port parameter.
                  If array is specified, values will be passed to multiport module.
                  Only applies to tcp/udp."

      validate do |value|
        if value.is_a?(Array) and value.length > 15
          self.fail "multiport module only accepts <= 15 ports"
        end
      end            
    end

    newparam(:dport) do
      desc "holds value of iptables [..] --destination-port parameter.
                  If array is specified, values will be passed to multiport module.
                  Only applies to tcp/udp."
      defaultto ""
      
      validate do |value|
        if value.is_a?(Array) and value.length > 15
          self.fail "multiport module only accepts <= 15 ports"
        end
      end
    end

    newparam(:iniface) do
      desc "value for iptables --in-interface parameter"
    end

    newparam(:outiface) do
      desc "value for iptables --out-interface parameter"
    end

    newparam(:tosource) do
      desc "value for iptables '-j SNAT --to-source' parameter"
    end

    newparam(:todest) do
      desc "value for iptables '-j DNAT --to-destination' parameter"
    end

    newparam(:toports) do
      desc "value for iptables '-j REDIRECT --to-ports' parameter"
    end

    newparam(:reject) do
      desc "value for iptables '-j REJECT --reject-with' parameter"
    end

    newparam(:log_level) do
      desc "value for iptables '-j LOG --log-level' parameter"
    end

    newparam(:log_prefix) do
      desc "value for iptables '-j LOG --log-prefix' parameter"
    end

    newparam(:icmp) do
      desc "value for iptables '-p icmp --icmp-type' parameter"
      defaultto ""
      
      munge do |value|
        num = @resource.icmp_name_to_number(value)
        if num == nil and value != ""
          self.fail("cannot work out icmp type")
        end
        num
      end
      
      validate do |value|
#        if value == ""
#          self.fail("cannot work out icmp type")
#        end
      end
    end

    newparam(:state) do
      desc "value for iptables '-m state --state' parameter.
                  Possible values are: 'INVALID', 'ESTABLISHED', 'NEW', 'RELATED'.
                  Also accepts an array of multiple values."
    end

    newparam(:limit) do
      desc "value for iptables '-m limit --limit' parameter.
                  Example values are: '50/sec', '40/min', '30/hour', '10/day'."
    end

    newparam(:burst) do
      desc "value for '--limit-burst' parameter.
                  Example values are: '5', '10'."
      
      validate do |value|
        if value.to_s !~ /^[0-9]+$/
          self.fail "burst accepts only numeric values"
        end
      end
    end

    newparam(:redirect) do
      desc "value for iptables '-j REDIRECT --to-ports' parameter."
    end

    # This is where we Validate across parameters
    validate do
      # First we make sure the chains and tables are valid combinations
      if self[:table].to_s == "filter" and ["PREROUTING", "POSTROUTING"].include?(self[:chain].to_s)
        self.fail "PREROUTING and POSTROUTING cannot be used in table 'filter'"
      elsif self[:table].to_s == "nat" and ["INPUT", "FORWARD"].include?(self[:chain].to_s)
        self.fail "INPUT and FORWARD cannot be used in table 'nat'"
      elsif self[:table].to_s == "raw" and ["INPUT", "FORWARD", "POSTROUTING"].include?(self[:chain].to_s)
        self.fail "INPUT, FORWARD and POSTROUTING cannot be used in table 'raw'"
      end
      
      if self[:iniface].to_s != ""
        unless ["INPUT", "FORWARD", "PREROUTING"].include?(self[:chain].to_s)
          self.fail "Parameter iniface only applies to chains INPUT,FORWARD,PREROUTING"
        end
      end

      if self[:outiface].to_s != ""
        unless ["OUTPUT", "FORWARD", "POSTROUTING"].include?(value(:chain).to_s)
          self.fail "Parameter outiface only applies to chains OUTPUT,FORWARD,POSTROUTING"
        end
      end
      
      if self[:dport] != "" and !["tcp", "udp", "sctp"].include?(self[:proto].to_s)
        self.fail "Parameter dport only applies to udp and tcp protocols"
      end
      
      if self[:sport] != "" and !["tcp", "udp", "sctp"].include?(self[:proto].to_s)
        self.fail "Parameter sport only applies to udp and tcp protocols"
      end
      
      if self[:jump].to_s == "DNAT"
        if self[:table].to_s != "nat"
          self.fail "Parameter jump => DNAT only applies to table => nat"
        elsif self[:todest].to_s == ""
          self.fail "Parameter jump => DNAT must have todest parameter"
        end
      elsif self[:jump].to_s == "SNAT"
        if self[:table].to_s != "nat"
          self.fail "Parameter jump => SNAT only applies to table => nat"
        elsif self[:tosource].to_s == ""
          self.fail "Parameter jump => SNAT missing mandatory tosource parameter"
        end
      elsif self[:jump].to_s == "REDIRECT"
        if self[:toports].to_s == ""
          self.fail "Parameter jump => REDIRECT missing mandatory toports parameter"
        end
      elsif self[:jump].to_s == "MASQUERADE"
        if self[:table].to_s != "nat"
          self.fail "Parameter jump => MASQUERADE only applies to table => nat"
        end
      end    
      
      if self[:burst].to_s != "" and self[:limit].to_s == ""
        self.fail "burst makes no sense without limit"
      end  
    end        
  end
end
