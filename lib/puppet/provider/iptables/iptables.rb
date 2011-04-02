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

require 'ipaddr'
require 'resolv'
require 'puppet/util/iptables'
require 'puppet/util/ipcidr'
require 'facter'

Puppet::Type.type(:iptables).provide :iptables do
  include Puppet::Util::Iptables

  desc "Iptables provider"

  # Rack up the commands here. We are gleaning these from the facts we provide
  # as part of puppet-iptables.
  commands :iptables_cmd => Facter.value(:iptables_cmd)
  commands :iptables_save_cmd => Facter.value(:iptables_save_cmd)
  
  # Default for linux boxes in general
  defaultfor :operatingsystem => [:redhat, :debian, :fedora, :suse, :centos, 
    :sles, :oel, :ovm]

  # Confine to linux only
  confine :operatingsystem => [:redhat, :debian, :fedora, :suse, :centos, 
    :sles, :oel, :ovm]

  # Class Methods
      
  # self.instances is called very early in a purge situation to get a list of 
  # existing instances so we can target particular instances to purge.
  #
  # For iptables, we wish to return a full list of existing rules formatted
  # as a list of hashes.
  def self.instances
    debug "[instances]"

    table         = ''
    loaded_rules  = {}
    table_rules   = {}
    counter       = 1

    iptables_save_cmd.each { |l|
      if /^\*\S+/.match(l)
        # Matched table
        table = l.slice(/^\*(\S+)/, 1)

        # init loaded_rules hash
        loaded_rules[table] = {} unless loaded_rules[table]
        table_rules = loaded_rules[table]

        # New table - we should reset counter
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

        # TODO: combine the rule reading information with the resource_* stuff
        data = {
          :chain      => l.slice(/^-A (\S+)/, 1),
          :table      => table,
          :proto      => l =~ /-p (\S+)/ ? $1 : "all",
          :jump       => l =~ /-j (\S+)/ ? $1 : "",
          :source     => source,
          :destination => destination,
          :sport      => l =~ /--sport[s]? (\S+)/ ? $1 : "",
          :dport      => l =~ /--dport[s]? (\S+)/ ? $1 : "",
          :iniface    => l =~ /-i (\S+)/ ? $1 : "",
          :outiface   => l =~ /-o (\S+)/ ? $1 : "",
          :todest     => l =~ /--to-destination (\S+)/ ? $1 : "",
          :tosource   => l =~ /--to-source (\S+)/ ? $1 : "",
          :toports    => l =~ /--to-ports (\S+)/ ? $1 : "",
          :reject     => l =~ /--reject-with (\S+)/ ? $1 : "",
          :log_level  => l =~ /--log-level (\S+)/ ? $1 : "",
          :log_prefix => l =~ /--log-prefix (\S+)/ ? $1 : "",
          :icmp       => l =~ /--icmp-type (\S+)/ ? $1 : "",
          :state      => l =~ /--state (\S+)/ ? $1 : "",
          :limit      => l =~ /--limit (\S+)/ ? $1 : "",
          :burst      => l =~ /--limit-burst (\S+)/ ? $1 : "",
          :redirect   => l =~ /--to-ports (\S+)/ ? $1 : "",
          :name       => l.slice(/--comment \"(.+)\"/, 1),
          :provider   => self.name,
          :ensure     => :present,
          :rulenum    => counter,
        }

        table_rules[l.strip] = data

        counter += 1
      end
    }
    
    # Build up rules
    rules = [] 
    loaded_rules.each do |table,ruleset|
      ruleset.each do |name, rule|
        rules << new(rule)
      end
    end
    
    #require 'pp'  
    #pp rules
    
    rules
  end
  
  # Prefetch our rule list. This is ran once every time before any other 
  # action (besides initialization of each object).
  #
  def self.prefetch(resources)
    debug("[prefetch(resources)]")
    instances.each do |prov|
      if resource = resources[prov.name] || resources[prov.name.downcase]
        resource.provider = prov
      end
    end    
  end

  # Object Methods
      
  # Does this resource exist
  def exists?
    properties[:ensure] != :absent
  end

  # Create getters and setters for every available property for the resource
  mk_resource_methods
    
  # Look up the current status. This allows us to conventiently look up
  # existing status with properties[:foo].
  def properties
    if @property_hash.empty?
      @property_hash = query || {:ensure => :absent}
      @property_hash[:ensure] = :absent if @property_hash.empty?
    end
    @property_hash.dup
  end
  # Pull the current state of the list from the full list.  We're
  # getting some double entendre here....
  def query
    self.class.instances.each do |instance|
      if instance.name == self.name or instance.name.downcase == self.name
        return instance.properties
      end
    end
    nil
  end  
  # Flush the property hash once done.
  def flush
    @property_hash.clear
  end
    
  # Ensure verbs

  # Create a new rule
  def insert
    # TODO: turn this resource_* stuff into 1 large array with hashes
    
    # A hash mapping our API's parameters to real iptables command arguments
    resource_map = {
      "burst" => "--limit-burst",
      "destination" => "-d",
      "dport" => "--dport",
      "icmp" => "--icmp-type",
      "iniface" => "-i",
      "jump" => "--jump",
      "limit" => ["-m", "limit", "--limit"],
      "log_level" => "--log-level",
      "log_prefix" => "--log-prefix",
      "name" => ["-m", "comment", "--comment"],
      "outiface" => "-o",
      "proto" => "-p",
      "redirect" => "--to-ports",
      "reject" => "--reject-with",
      "source" => "-s",
      "state" => ["-m", "state", "--state"],
      "sport" => "--sport",
      "table" => "-t",
      "todest" => "--to-destination",
      "toports" => "--to-ports",
      "tosource" => "--to-source",
    }
    
    # An ordered list of our parameters so we get the arguments in the correct
    # order for iptables.
    resource_list = [
      "table", 
      "proto", 
      "icmp",
      "source", 
      "sport", 
      "destination",
      "dport", 
      "iniface",
      "outiface",
      
      # -m state --state x
      "state",
      
      # -m limit --limit x --limit-burst x
      "limit", "burst",
        
      # -j X
      "jump",
        
      # -j LOG --log-level x --log-prefix x
      "log_level",  "log_prefix",
      
      # -j REDIRECT --to-ports x
      "redirect",
           
      # -j REJECT --reject-with 
      "reject",
      "todest",  
      "toports",    
      "tosource",
      
      # Comment is the namevar
      "name",
    ]
    
    # Compare resource_list with resource_map keys to make sure we
    # haven't missed anything.  
    unless resource_map.keys.sort == resource_list.sort then
      fail("Code error: There is a mismatch between resource_map and 
        resource_list.")
    end

    # The arguments hash is used to build our list of arguments to be passed
    # to the local iptables command.
    arguments = []

    # The insert argument (-I) comes first. Here we pass a rulenum to ensure
    # the rule is inserted in the correct order.
    arguments << ["-I", resource[:chain]]
    # TODO: we need to insert at a particular point in the set of rules.
    # we should do this by:
    # - grab the list of rules
    # - sort them out into the correct tables and chains
    # - lexically order them inside each table and chain
    # - ?
    rulenum = 1
    arguments << rulenum

    # Traverse the resource list and place the switch and corresponding value
    # into our arguments hash.              
    resource_list.each do |res|
      if(resource.value(res)) then
        arguments << resource_map[res]
        arguments << resource[res]
      end
    end

    # Run the desired command with the arguments we have gathered.
    iptables_cmd arguments
  end

  # Delete a rule
  def delete
    iptables_cmd "-D", properties[:chain], properties[:rulenum]
  end

end
