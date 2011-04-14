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
        provider.insert
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
    
    newproperty(:rulenum) do
      desc "A read only parameter which indicates the row number for this 
        rule."
      
      validate do
        fail "ctime is read-only"
      end
    end

    newproperty(:chain) do
      desc "holds value of iptables -A parameter.
        Possible values are: 'INPUT', 'FORWARD', 'OUTPUT', 'PREROUTING', 
        'POSTROUTING'. Default value is 'INPUT'"
      newvalues(:INPUT, :FORWARD, :OUTPUT, :PREROUTING, :POSTROUTING)
      defaultto "INPUT"
    end

    newproperty(:table) do
      desc "The value for the iptables -t parameter. Can be one of the " \
        "following tables: 'nat', 'mangle', 'filter' and 'raw'. Default one " \
        "is 'filter'"
      newvalues(:nat, :mangle, :filter, :raw)
      defaultto "filter"
    end

    newproperty(:proto) do
      desc "holds value of iptables --protocol parameter. " \
        "Possible values are: 'tcp', 'udp', 'icmp', 'esp', 'ah', 'vrrp', " \
        "'igmp', 'all'. Default value is 'tcp'"
      newvalues(:tcp, :udp, :icmp, :esp, :ah, :vrrp, :igmp, :all)
      defaultto "tcp"
    end

    newproperty(:jump) do
      desc "holds value of iptables --jump target. " \
        "Possible values are: 'ACCEPT', 'DROP', 'REJECT', 'DNAT', 'SNAT', " \
        "'LOG', 'MASQUERADE', 'REDIRECT'. Default value is 'ACCEPT'. While " \
        "this is not the accepted norm, this is the more commonly used jump " \
        "target. Users should ensure they do an explicit DROP for all " \
        "packets after all the ACCEPT rules are specified."
      newvalues(:ACCEPT, :DROP, :REJECT, :DNAT, :SNAT, :LOG, :MASQUERADE, 
        :REDIRECT)
      defaultto "ACCEPT"
    end

    newproperty(:source) do
      desc "value for iptables --source parameter.
                  Accepts a single string or array."
    end

    newproperty(:destination) do
      desc "value for iptables --destination parameter"
    end

    newproperty(:sport) do
      desc "holds value of iptables [..] --source-port parameter. If array " \
        "is specified, values will be passed to multiport module. Only " \
        "applies to tcp/udp."

      validate do |value|
        if value.is_a?(Array) and value.length > 15
          self.fail "multiport module only accepts <= 15 ports"
        end
      end            
    end

    newproperty(:dport) do
      desc "holds value of iptables [..] --destination-port parameter. If " \
        "array is specified, values will be passed to multiport module. " \
        "applies to tcp/udp."
      
      validate do |value|
        if value.is_a?(Array) and value.length > 15
          self.fail "multiport module only accepts <= 15 ports"
        end
      end
    end

    newproperty(:iniface) do
      desc "value for iptables --in-interface parameter"
    end

    newproperty(:outiface) do
      desc "value for iptables --out-interface parameter"
    end

    newproperty(:tosource) do
      desc "value for iptables '-j SNAT --to-source' parameter"
    end

    newproperty(:todest) do
      desc "value for iptables '-j DNAT --to-destination' parameter"
    end

    newproperty(:toports) do
      desc "value for iptables '-j REDIRECT --to-ports' parameter"
    end

    newproperty(:reject) do
      desc "value for iptables '-j REJECT --reject-with' parameter"
    end

    newproperty(:log_level) do
      desc "value for iptables '-j LOG --log-level' parameter"
    end

    newproperty(:log_prefix) do
      desc "value for iptables '-j LOG --log-prefix' parameter"
    end

    newproperty(:icmp) do
      desc "value for iptables '-p icmp --icmp-type' parameter"
      
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

    newproperty(:state) do
      desc "value for iptables '-m state --state' parameter. Possible " \
        "values are: 'INVALID', 'ESTABLISHED', 'NEW', 'RELATED'. Also " \
        "accepts an array of multiple values."
    end

    newproperty(:limit) do
      desc "value for iptables '-m limit --limit' parameter. Example " \
        "values are: '50/sec', '40/min', '30/hour', '10/day'."
    end

    newproperty(:burst) do
      desc "value for '--limit-burst' parameter.
                  Example values are: '5', '10'."
      
      validate do |value|
        if value.to_s !~ /^[0-9]+$/
          self.fail "burst accepts only numeric values"
        end
      end
    end

    newproperty(:redirect) do
      desc "value for iptables '-j REDIRECT --to-ports' parameter."
    end

    # This is where we Validate across parameters
    validate do
      debug("[validate]")
      
      #debug("%s" % @parameters[:name].value)
        
      # TODO: this is put here to skip validation if ensure is not set. This
      # is because there is a revalidation stage called later where the values
      # are not set correctly. I tried tracing it - but have put in this
      # workaround instead to skip. Must get to the bottom of this.
      if value(:ensure) == nil then
        return
      end
      
      # First we make sure the chains and tables are valid combinations
      if value(:table).to_s == "filter" and 
        ["PREROUTING", "POSTROUTING"].include?(value(:chain).to_s)
        self.fail "PREROUTING and POSTROUTING cannot be used in table 'filter'"
      elsif value(:table).to_s == "nat" and 
        ["INPUT", "FORWARD"].include?(value(:chain).to_s)
        self.fail "INPUT and FORWARD cannot be used in table 'nat'"
      elsif value(:table).to_s == "raw" and 
        ["INPUT", "FORWARD", "POSTROUTING"].include?(value(:chain).to_s)
        self.fail "INPUT, FORWARD and POSTROUTING cannot be used in table raw"
      end
      
      # Now we analyse the individual properties to make sure they apply to
      # the correct combinations.
      if value(:iniface).to_s != ""
        unless ["INPUT","FORWARD","PREROUTING"].include?(value(:chain).to_s)
          self.fail "Parameter iniface only applies to chains " \
            "INPUT,FORWARD,PREROUTING"
        end
      end

      if value(:outiface).to_s != ""
        unless ["OUTPUT","FORWARD","POSTROUTING"].include?(value(:chain).to_s)
          self.fail "Parameter outiface only applies to chains " \
            "OUTPUT,FORWARD,POSTROUTING"
        end
      end
      
      if value(:dport) != nil and 
        !["tcp", "udp", "sctp"].include?(value(:proto).to_s)
        self.fail("[%s] Parameter dport only applies to sctp, tcp and udp " \
          "protocols. Current protocol is [%s] and dport is [%s]" % 
          [value(:name), should(:proto), should(:dport)])
      end
      
      if value(:sport) != nil and 
        !["tcp", "udp", "sctp"].include?(value(:proto).to_s)
        self.fail "[%s] Parameter sport only applies to sctp, tcp and udp " \
          "protocols. Current protocol is [%s] and dport is [%s]" %
          [value(:name), should(:proto), should(:sport)]
      end
      
      if value(:jump).to_s == "DNAT"
        if value(:table).to_s != "nat"
          self.fail "Parameter jump => DNAT only applies to table => nat"
        elsif value(:todest).to_s == ""
          self.fail "Parameter jump => DNAT must have todest parameter"
        end
      elsif value(:jump).to_s == "SNAT"
        if value(:table).to_s != "nat"
          self.fail "Parameter jump => SNAT only applies to table => nat"
        elsif value(:tosource).to_s == ""
          self.fail "Parameter jump => SNAT missing mandatory tosource " \
            "parameter"
        end
      elsif value(:jump).to_s == "REDIRECT"
        if value(:toports).to_s == ""
          self.fail "Parameter jump => REDIRECT missing mandatory toports " \
            "parameter"
        end
      elsif value(:jump).to_s == "MASQUERADE"
        if value(:table).to_s != "nat"
          self.fail "Parameter jump => MASQUERADE only applies to table => nat"
        end
      end    
      
      if value(:burst).to_s != "" and value(:limit).to_s == ""
        self.fail "burst makes no sense without limit"
      end  
    end    
    
  end
end
