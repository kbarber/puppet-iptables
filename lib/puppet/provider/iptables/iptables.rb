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

  # Default for linux boxes in general
  defaultfor :operatingsystem => [:redhat, :debian, :fedora, :suse, :centos, :sles, :oel, :ovm]

  # Confine to linux only
  confine :operatingsystem => [:redhat, :debian, :fedora, :suse, :centos, :sles, :oel, :ovm]

  # Return existing rules
  def self.instances
    debug "Return existing rules"
    # Pass in iptables save command gleaned from facter
    ipt_save = Facter.value(:iptables_save_cmd)
    Puppet::Util::Iptables.iptables_save_to_hash(`#{ipt_save}`, false)
  end

  # Prefetch our rule list, yo.
  def self.prefetch(rules)
    debug "Prefetch our rule list, yo"
    instances.each do |prov|
      if rule = rules[prov.name] || rules[prov.name.downcase]
        rule.provider = prov
      end
    end
  end

  # Does this resource exist
  def exists?
    debug "Check if rule name '%s' exists" % (resource[:name])
    @property_hash[:ensure] != :absent
    false
  end

  # Look up the current status.
  def properties
    debug "properties"
    if @property_hash.empty?
      @property_hash = query || {:ensure => :absent}
      @property_hash[:ensure] = :absent if @property_hash.empty?
    end
    @property_hash.dup
  end

  def flush
    debug "flush %s " % (self.hash)
  end

  # Ensure verbs

  # Create a new rule
  def create
    debug "Create rule"
  end

  # Delete a rule
  def create
    debug "Create rule"
  end

  # Purge
  def purge
    debug "Purge"
  end

  # List of table names
  @@table_names = ['filter','nat','mangle','raw']

  # pre and post rules are loaded from files
  # pre.iptables post.iptables in /etc/puppet/iptables
  @@pre_file  = "/etc/puppet/iptables/pre.iptables"
  @@post_file = "/etc/puppet/iptables/post.iptables"

  # order in which the differents chains appear in iptables-save's output. Used
  # to sort the rules the same way iptables-save does.
  @@chain_order = {
    'PREROUTING'  => 1,
    'INPUT'       => 2,
    'FORWARD'     => 3,
    'OUTPUT'      => 4,
    'POSTROUTING' => 5,
  }
      
  @@rules = {}

  @@current_rules = {}

  @@ordered_rules = {}

  @@total_rule_count = 0

  @@instance_count = 0

  @@finalized = false

  # Parse the output of iptables-save and return a hash with every parameter
  # of each rule
  def load_current_rules(numbered = false)
    ipt_save = Facter.value(:iptables_save_cmd)
    iptables_save_to_hash(`#{ipt_save}`, numbered)
  end

  # Load a file and using the passed in rules hash load the 
  # rules contained therein.
  def load_rules_from_file(rules, file_name, action)
    if File.exist?(file_name)
      counter = 0
      File.open(file_name, "r") do |infile|
        while (line = infile.gets)
          # Skip comments
          next unless /^\s*[^\s#]/.match(line.strip)

          # Get the table the rule is operating on
          table = line[/-t\s+\S+/]
          table = "-t filter" unless table
          table.sub!(/^-t\s+/, '')
          rules[table] = [] unless rules[table]

          # Build up rule hash
          rule =
            { 'table'   => table,
              'rule'    => line.strip}

          # Push or insert rule onto table entry in rules hash
          if( action == :prepend )
            rules[table].insert(counter, rule)
          else
            rules[table].push(rule)
          end

          counter += 1
        end
      end
    end
  end
  
  # finalize() gets run once every iptables resource has been declared.
  # It decides if puppet resources differ from currently active iptables
  # rules and applies the necessary changes.
  def finalize
    # sort rules by alphabetical order, grouped by chain, else they arrive in
    # random order and cause puppet to reload iptables rules.
    @@rules.each_key {|key|
      @@rules[key] = @@rules[key].sort_by { |rule| [rule["chain_prio"], rule["name"], rule["source"]] }
    }

    # load pre and post rules
    load_rules_from_file(@@rules, @@pre_file, :prepend)
    load_rules_from_file(@@rules, @@post_file, :append)

    # add numbered version to each rule
    @@table_names.each { |table|
      rules_to_set = @@rules[table]
      if rules_to_set
        counter = 1
        rules_to_set.each { |rule|
          rule['nrule'] = counter.to_s + " " + rule["rule"]
          counter += 1
        }
      end
    }

    # On the first round we delete rules which do not match what
    # we want to set. We have to do it in the loop until we
    # exhaust all rules, as some of them may appear as multiple times
    while self.delete_not_matched_rules > 0
    end

    # Now we need to take care of rules which are new or out of order.
    # The way we do it is that if we find any difference with the
    # current rules, we add all new ones and remove all old ones.
    if self.rules_are_different
      # load new new rules and benchmark the whole lot
      benchmark(:notice, self.noop ? "rules would have changed... (noop)" : "rules have changed...") do
        # load new rules
        @@table_names.each { |table|
          rules_to_set = @@rules[table]
          if rules_to_set
            rules_to_set.each { |rule_to_set|
              if self.noop
                debug("Would have run [create]: 'iptables -t #{table} #{rule_to_set['rule']}' (noop)")
                next
              else
                ipt_cmd = Facter.value(:iptables_cmd)
                debug("Running [create]: '#{ipt_cmd} -t #{table} #{rule_to_set['rule']}'")
                `#{ipt_cmd} -t #{table} #{rule_to_set['rule']}`
              end
            }
          end
        }

        # delete old rules
        @@table_names.each { |table|
          current_table_rules = @@current_rules[table]
          if current_table_rules
            current_table_rules.each { |rule, data|
              if self.noop
                debug("Would have run [delete]: 'iptables -t #{table} -D #{data['chain']} 1' (noop)")
                next
              else
                ipt_cmd = Facter.value(:iptables_cmd)
                debug("Running [delete]: '#{ipt_cmd} -t #{table} -D #{data['chain']} 1'")
                `#{ipt_cmd} -t #{table} -D #{data['chain']} 1`
              end
            }
          end
        }

        # Run iptables save to persist rules. The behaviour is to do nothing
        # if we know nothing of the operating system.
        persist_cmd = Facter.value(:iptables_persist_cmd)

        if persist_cmd != nil
          if Puppet[:noop]
            debug("Would have run [save]: #{persist_cmd} (noop)")
          else
            debug("Running [save]: #{persist_cmd}")
            system(persist_cmd)
          end
        else
          err("No save method known for your OS. Rules will not be saved!")
        end
      end

      @@rules = {}
    end

    @@finalized = true
  end

  def finalized?
    if defined? @@finalized
      return @@finalized
    else
      return false
    end
  end

  # Check if at least one rule found in iptables-save differs from what is
  # defined in puppet resources.
  def rules_are_different
    # load current rules
    @@current_rules = self.load_current_rules(true)

    @@table_names.each { |table|
      rules_to_set = @@rules[table]
      current_table_rules = @@current_rules[table]
      current_table_rules = {} unless current_table_rules
      current_table_rules.each do |rule, data|
        debug("Current tables rules: #{rule}")
      end
      if rules_to_set
        rules_to_set.each { |rule_to_set|
          debug("Looking for: #{rule_to_set['nrule']}")
          return true unless current_table_rules[rule_to_set['nrule']]
        }
      end
    }

    return false
  end

  def delete_not_matched_rules
    # load current rules
    @@current_rules = self.load_current_rules

    # count deleted rules from current active
    deleted = 0;

    # compare current rules with requested set
    @@table_names.each { |table|
      rules_to_set = @@rules[table]
      current_table_rules = @@current_rules[table]
      if rules_to_set
        if current_table_rules
          rules_to_set.each { |rule_to_set|
            rule = rule_to_set['rule']
            if current_table_rules[rule]
              current_table_rules[rule]['keep'] = 'me'
            end
          }
        end
      end

      # delete rules not marked with "keep" => "me"
      if current_table_rules
        current_table_rules.each { |rule, data|
          if data['keep']
          else
            if self.noop
              debug("Would have run [delete]: 'iptables -t #{table} #{rule.sub('-A', '-D')}' (noop)")
              next
            else
              ipt_cmd = Facter.value(:iptables_cmd)
              debug("Running [delete]: '#{ipt_cmd} -t #{table} #{rule.sub('-A', '-D')}'")
              `#{ipt_cmd} -t #{table} #{rule.sub("-A", "-D")}`
            end
            deleted += 1
          end
        }
      end
    }
    return deleted
  end

  def properties
    @@ordered_rules[self.name] = @@instance_count
    @@instance_count += 1

    if @@instance_count == @@total_rule_count
      self.finalize unless self.finalized?
    end
    return super
  end

  # Reset class variables to their initial value
  def self.clear
    @@rules = {}

    @@current_rules = {}

    @@ordered_rules = {}

    @@total_rule_count = 0

    @@instance_count = 0

    @@finalized = false
    super
  end


  def initialize_foo(args)
    super(args)

    invalidrule = false
    @@total_rule_count += 1

    table = value(:table).to_s
    @@rules[table] = [] unless @@rules[table]

    # Create a Hash with all available params defaulted to empty strings.
    strings = self.class.allattrs.inject({}) { |x,y| x[y] = ""; x }

    strings[:table] = "-A " + value(:chain).to_s

    sources = []
    if value(:source).to_s != ""
      value(:source).each { |source|
        if source !~ /\//
          source = Resolv.getaddress(source)
        end
        ip = Puppet::Util::IpCidr.new(source.to_s)
        if Facter.value("iptables_ipcidr")
          source = ip.cidr
        else
          source = ip.to_s
          source += sprintf("/%s", ip.netmask) unless ip.prefixlen == 32
        end
        sources.push({
          :host   => source,
          :string => " -s " + source
        })
      }
    else
      # Used later for a single iteration of the rule if there are no sources.
      sources.push({
        :host   => "",
        :string => ""
      })
    end

    destination = value(:destination).to_s
    if destination != ""
      if destination !~ /\//
        destination = Resolv.getaddress(destination)
      end
      ip = Puppet::Util::IpCidr.new(destination)
      if Facter.value("iptables_ipcidr")
        destination = ip.cidr
      else
        destination = ip.to_s
        destination += sprintf("/%s", ip.netmask) unless ip.prefixlen == 32
      end
      strings[:destination] = " -d " + destination
    end

    if value(:iniface)
      strings[:iniface] = " -i " + value(:iniface).to_s
    end
    if value(:outiface)
      strings[:outiface] = " -o " + value(:outiface).to_s
    end

    if value(:proto).to_s != "all"
      strings[:proto] = " -p " + value(:proto).to_s
      if not ["vrrp", "igmp"].include?(value(:proto).to_s)
        strings[:proto] += " -m " + value(:proto).to_s
      end
    end

    if value(:dport).to_s != ""
      if value(:dport).is_a?(Array)
        strings[:dport] = " -m multiport --dports " + value(:dport).join(",")
      else
        strings[:dport] = " --dport " + value(:dport).to_s
      end
    end

    if value(:sport).to_s != ""
      if value(:sport).is_a?(Array)
        strings[:sport] = " -m multiport --sports " + value(:sport).join(",")
      else
        strings[:sport] = " --sport " + value(:sport).to_s
      end
    end

    value_icmp = ""
    if value(:proto).to_s == "icmp"
      if value(:icmp).to_s == ""
        value_icmp = "any"
      else
        value_icmp = value(:icmp)
      end

      strings[:icmp] = " --icmp-type " + value_icmp
    end

    # let's specify the order of the states as iptables uses them
    state_order = ["INVALID", "NEW", "RELATED", "ESTABLISHED"]
    if value(:state).is_a?(Array)

      invalid_state = false
      value(:state).each {|v|
        invalid_state = true unless state_order.include?(v)
      }

      if value(:state).length <= state_order.length and not invalid_state

        # return only the elements that appear in both arrays.
        # This filters out bad entries (unfortunately silently), and orders the entries
        # in the same order as the 'state_order' array
        states = state_order & value(:state)

        strings[:state] = " -m state --state " + states.join(",")
      else
        invalidrule = true
        err("'state' accepts any the following states: #{state_order.join(", ")}. Ignoring rule.")
      end
    elsif value(:state).to_s != ""
      if state_order.include?(value(:state).to_s)
        strings[:state] = " -m state --state " + value(:state).to_s
      else
        invalidrule = true
        err("'state' accepts any the following states: #{state_order.join(", ")}. Ignoring rule.")
      end
    end

    if value(:name).to_s != ""
      strings[:comment] = " -m comment --comment \"" + value(:name).to_s + "\""
    end

    if value(:limit).to_s != ""
      limit_value = value(:limit).to_s
      if not limit_value.include? "/"
        invalidrule = true
        err("Please append a valid suffix (sec/min/hour/day) to the value passed to 'limit'. Ignoring rule.")
      else
        limit_value = limit_value.split("/")
        if limit_value[0] !~ /^[0-9]+$/
          invalidrule = true
          err("'limit' values must be numeric. Ignoring rule.")
        elsif ["sec", "min", "hour", "day"].include? limit_value[1]
          strings[:limit] = " -m limit --limit " + value(:limit).to_s
        else
          invalidrule = true
          err("Please use only sec/min/hour/day suffixes with 'limit'. Ignoring rule.")
        end
      end
    end

    if value(:burst).to_s != ""
      strings[:burst] = " --limit-burst " + value(:burst).to_s
    end
    
    strings[:jump] = " -j " + value(:jump).to_s

    value_reject = ""
    if value(:jump).to_s == "DNAT"
      strings[:todest] = " --to-destination " + value(:todest).to_s
    elsif value(:jump).to_s == "SNAT"
      strings[:tosource] = " --to-source " + value(:tosource).to_s
    elsif value(:jump).to_s == "REDIRECT"
      strings[:toports] = " --to-ports " + value(:toports).to_s
    elsif value(:jump).to_s == "REJECT"
      # Apply the default rejection type if none is specified.
      value_reject = value(:reject).to_s != "" ? value(:reject).to_s : "icmp-port-unreachable"
      strings[:reject] = " --reject-with " + value_reject
    elsif value(:jump).to_s == "LOG"
      if value(:log_level).to_s != ""
        strings[:log_level] = " --log-level " + value(:log_level).to_s
      end
      if value(:log_prefix).to_s != ""
        # --log-prefix has a 29 characters limitation.
        log_prefix = "\"" + value(:log_prefix).to_s[0,27] + ": \""
        strings[:log_prefix] = " --log-prefix " + log_prefix
      end
    elsif value(:jump).to_s == "REDIRECT"
      if value(:redirect).to_s != ""
        strings[:redirect] = " --to-ports " + value(:redirect).to_s
      end
    end

    chain_prio = @@chain_order[value(:chain).to_s]

    # Generate a rule entry for each source permutation.
    sources.each { |source|
      
      # Build a string of arguments in the required order.
      rule_string = "%s" * 21 % [
        strings[:table],
        source[:string],
        strings[:destination],
        strings[:iniface],
        strings[:outiface],
        strings[:proto],
        strings[:sport],
        strings[:dport],
        strings[:icmp],
        strings[:state],
        strings[:comment],
        strings[:limit],
        strings[:burst],
        strings[:jump],
        strings[:todest],
        strings[:tosource],
        strings[:toports],
        strings[:reject],
        strings[:log_level],
        strings[:log_prefix],
        strings[:redirect]
      ]
      
      debug("iptables param: #{rule_string}")
      if invalidrule != true
        @@rules[table].push({
          'name'          => value(:name).to_s,
          'chain'         => value(:chain).to_s,
          'table'         => value(:table).to_s,
          'proto'         => value(:proto).to_s,
          'jump'          => value(:jump).to_s,
          'source'        => source[:host],
          'destination'   => value(:destination).to_s,
          'sport'         => value(:sport).to_s,
          'dport'         => value(:dport).to_s,
          'iniface'       => value(:iniface).to_s,
          'outiface'      => value(:outiface).to_s,
          'todest'        => value(:todest).to_s,
          'tosource'      => value(:tosource).to_s,
          'toports'       => value(:toports).to_s,
          'reject'        => value_reject,
          'redirect'      => value(:redirect).to_s,
          'log_level'     => value(:log_level).to_s,
          'log_prefix'    => value(:log_prefix).to_s,
          'icmp'          => value_icmp,
          'state'         => value(:state).to_s,
          'limit'         => value(:limit).to_s,
          'burst'         => value(:burst).to_s,
          'chain_prio'    => chain_prio.to_s,
          'rule'          => rule_string
        })
      end
    }
  end
end
