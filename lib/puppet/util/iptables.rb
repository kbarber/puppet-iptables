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

require 'facter'
require 'puppet/util/ipcidr'

module Puppet
  module Util
    module Iptables
  
      # Translate the symbolic names for icmp packet types to
      # numbers.
      def icmp_name_to_number(value_icmp)
        if value_icmp =~ /^\d{1,2}$/
          value_icmp
        else
          case value_icmp
            when "echo-reply" then "0"
            when "destination-unreachable" then "3"
            when "source-quence" then "4"
            when "redirect" then "6"
            when "echo-request" then "8"
            when "router-advertisement" then "9"
            when "router-solicitation" then "10"
            when "time-exceeded" then "11"
            when "parameter-problem" then "12"
            when "timestamp-request" then "13"
            when "timestamp-reply" then "14"
            when "address-mask-request" then "17"
            when "address-mask-reply" then "18"
            else nil
          end
        end
      end
      
      # Convert iptables-save ouput to a hash.
      def self.iptables_save_to_hash(text, numbered=false)
        table         = ''
        loaded_rules  = {}
        table_rules   = {}
        counter       = 1
    
        text.each { |l|
          if /^\*\S+/.match(l)
            # Matched table
            table = l.slice(/^\*(\S+)/, 1)
    
            # init loaded_rules hash
            loaded_rules[table] = {} unless loaded_rules[table]
            table_rules = loaded_rules[table]
    
            # reset counter
            counter = 1
    
          elsif /^-A/.match(l)
            # Parse the iptables rule looking for each component
            table = l.slice(/-t (\S+)/, 1) unless table
            table = "filter" unless table
    
            # Some distros return "carp" for `getprotobynumber(112)`.
            # Rewrite this to be synonymous of "vrrp".
            l.sub!(/(-p )carp/, '\1vrrp')
    
            source = l.slice(/-s (\S+)/, 1)
            if source
              ip = Puppet::Util::IpCidr.new(source)
              if Facter.value("iptables_ipcidr")
                source = ip.cidr
              else
                source = ip.to_s
                source += sprintf("/%s", ip.netmask) unless ip.prefixlen == 32
              end
            end
    
            destination = l.slice(/-d (\S+)/, 1)
            if destination
              ip = Puppet::Util::IpCidr.new(destination)
              if Facter.value("iptables_ipcidr")
                destination = ip.cidr
              else
                destination = ip.to_s
                destination += sprintf("/%s", ip.netmask) unless ip.prefixlen == 32
              end
            end
    
            data = {
              'chain'      => l.slice(/^-A (\S+)/, 1),
              'table'      => table,
              'proto'      => l =~ /-p (\S+)/ ? $1 : "all",
              'jump'       => l =~ /-j (\S+)/ ? $1 : "",
              'source'     => source,
              'destination'=> destination,
              'sport'      => l =~ /--sport[s]? (\S+)/ ? $1 : "",
              'dport'      => l =~ /--dport[s]? (\S+)/ ? $1 : "",
              'iniface'    => l =~ /-i (\S+)/ ? $1 : "",
              'outiface'   => l =~ /-o (\S+)/ ? $1 : "",
              'todest'     => l =~ /--to-destination (\S+)/ ? $1 : "",
              'tosource'   => l =~ /--to-source (\S+)/ ? $1 : "",
              'toports'    => l =~ /--to-ports (\S+)/ ? $1 : "",
              'reject'     => l =~ /--reject-with (\S+)/ ? $1 : "",
              'log_level'  => l =~ /--log-level (\S+)/ ? $1 : "",
              'log_prefix' => l =~ /--log-prefix (\S+)/ ? $1 : "",
              'icmp'       => l =~ /--icmp-type (\S+)/ ? $1 : "",
              'state'      => l =~ /--state (\S+)/ ? $1 : "",
              'limit'      => l =~ /--limit (\S+)/ ? $1 : "",
              'burst'      => l =~ /--limit-burst (\S+)/ ? $1 : "",
              'redirect'   => l =~ /--to-ports (\S+)/ ? $1 : "",
              'name'       => l.slice(/--comment (\S+)/, 1),
            }
    
            if( numbered )
              table_rules[counter.to_s + " " +l.strip] = data
            else
              table_rules[l.strip] = data
            end
    
            counter += 1
          end
        }
        return loaded_rules
      end
      
    end
  end
end
