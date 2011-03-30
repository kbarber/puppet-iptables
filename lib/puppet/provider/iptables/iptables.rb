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

  commands :iptables_cmd => Facter.value(:iptables_cmd)
  
  # Default for linux boxes in general
  defaultfor :operatingsystem => [:redhat, :debian, :fedora, :suse, :centos, 
    :sles, :oel, :ovm]

  # Confine to linux only
  confine :operatingsystem => [:redhat, :debian, :fedora, :suse, :centos, 
    :sles, :oel, :ovm]

  # Initialization phase
  def initialize(resource = nil)
    super(resource)
    debug "[initialize]"
  end
  
  # Prefetch our rule list, yo.
  def self.prefetch(resources)
    debug "[prefetch]"
    resources.each do |name, resource|
      result = {}
      result[:ensure] = :present
      resource.provider = new(result)
      debug "[prefetch] Name: %s" % name
      debug "[prefetch] Resource: %s" % resource.type
    end
  end

  # Does this resource exist
  def exists?
    debug "[exists?] Check if rule name '%s' exists" % (resource[:name])
    save = Facter.value('iptables_save_cmd')
    `#{save}`.each do |line|
      if line =~ /--comment "#{resource[:name]}"/ then
        return true
      end
    end
    return false
  end

  # Look up the current status.
  def properties
    debug "[properties]"
    if @property_hash.empty?
      @property_hash = query || {:ensure => :absent}
      @property_hash[:ensure] = :absent if @property_hash.empty?
    end
    @property_hash.dup
  end

  
  def flush
    debug "[flush]"
  end

  # Ensure verbs

  # Create a new rule
  def create
    debug "[create]"
    
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
    arguments << "-I"
    arguments << resource[:chain]
    # TODO: we need to insert at a particular point in the set of rules.
    # we should do this by:
    # - grab the list of rules at prefetch
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
    
    # Add commment - this is special cased because it needs quote
    # TODO: work out some nicer way of doing this?
    arguments << ["-m", "comment", "--comment"]
    arguments << "'#{resource[:name]}'"

    # Combine the rules and run the desired command
    iptables_cmd arguments
  end

  # Delete a rule
  def delete
    debug "[delete]"
  end

  # Purge
  def purge
    debug "[purge]"
  end

end
