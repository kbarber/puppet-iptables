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

Facter.add("iptables_cmd") do
  setcode do
    "/sbin/iptables"
  end
end

Facter.add("iptables_save_cmd") do
  setcode do
    "/sbin/iptables-save"
  end
end

Facter.add("iptables_version") do
  setcode do
    ipt_cmd = Facter.value(:iptables_cmd)
    `#{ipt_cmd} --version`.scan(/ v([0-9\.]+)/)[0][0]
  end
end

Facter.add("iptables_persist_cmd") do
  setcode do
    case Facter.value(:operatingsystem).downcase
      when "fedora", "redhat", "centos"
        then "/sbin/service iptables save"
      when "ubuntu", "debian"
        then "/etc/init.d/iptables-persistent save"
      when "gentoo"
        then "/etc/init.d/iptables save"
      else nil
    end
  end
end
