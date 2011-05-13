# host firewall classes
#
# usage:
# node {'node.domain':
#    include puppet-firewall::hostfw
#    include puppet-firewall::ssh
#    include puppet-firewall::http
#    include puppet-firewall::https
# }

class puppet-firewall::hostfw {

	file {'/etc/puppet/iptables': ensure => directory, mode => '700' }

	file { "/etc/puppet/iptables/pre.iptables":
		content => "# defined in $name
-P INPUT DROP
-P FORWARD DROP
-P OUTPUT ACCEPT
-A INPUT -p icmp -m icmp --icmp-type any -j ACCEPT 
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 
",
		mode    => 0400,
	}

	file { "/etc/puppet/iptables/post.iptables":
		content => "# defined in
-A INPUT -j REJECT --reject-with icmp-admin-prohibited
",
		mode    => 0400,
	}

	# $prio ensure rules remain in correct order
	# $name in rule eases the process of tracking rules on the node
	$prio = '000'
        # allow localhost traffic - rfc3330
        iptables {"$prio $name 01":
                chain => 'INPUT',
                state => 'NEW',
                proto => 'tcp',
                source => '127.0.0.0/8',
                destination => '127.0.0.0/8',
                jump => 'ACCEPT',
        }

	# handle rule persistence 
	case $operatingsystem {
		'centos', 'redhat', 'fedora': {
			service {'iptables': 
				enable => true
			}
		}

		'ubuntu', 'debian': {
			file {'/etc/init.d/puppet-iptables':
				owner => root, mode => 555,
				content => '#!/bin/sh
### BEGIN INIT INFO
# Provides:          puppet-iptables
# Required-Start:    mountkernfs $local_fs
# Required-Stop:     $local_fs
# Default-Start:     S
# Default-Stop:      
# Short-Description: Set up iptables rules distributed via puppet
### END INIT INFO

case "$1" in
start)
    if [ -f /etc/iptables.rules ]; then
        iptables-restore < /etc/iptables.rules
    fi
    ;;
stop|force-stop|restart|force-reload|status)
    exit 0
    ;;
*)
    echo "Usage: $0 {start|stop|force-stop|restart|force-reload|status}" >&2
    exit 1
    ;;
esac
'			}
			service {'puppet-iptables':
				enable => true,
				require => File['/etc/init.d/puppet-iptables']
			}
			file {'/etc/iptables.rules':
				owner => root, mode => 440
			}
		}
	}
}

class puppet-firewall::ssh {
	$prio = '100'

        iptables {"$prio $name":
                chain => 'INPUT',
                state => 'NEW',
                proto => 'tcp',
                dport => '22',
                jump => 'ACCEPT',
        }
}

class firewall::puppetmaster {
	$prio = '100'

        iptables {"$prio $name":
                chain => 'INPUT',
                state => 'NEW',
                proto => 'tcp',
                dport => '8140',
                jump => 'ACCEPT',
        }
}

class firewall::snmp {
	$prio = '100'

        iptables {"$prio $name":
                chain => 'INPUT',
                state => 'NEW',
                proto => 'udp',
                dport => '161',
                jump => 'ACCEPT',
        }
}

class firewall::http {
	$prio = '100'

        iptables {"$prio $name":
                chain => 'INPUT', state => 'NEW', jump => 'ACCEPT',
                proto => 'tcp', dport => '80',
        }
}

class firewall::https {
	$prio = '100'

        iptables {"$prio $name":
                chain => 'INPUT', state => 'NEW', jump => 'ACCEPT',
                proto => 'tcp', dport => '443',
        }
}


class firewall::samba {
	$prio = '100'

        iptables {"$prio $name 01":
                chain => 'INPUT', state => 'NEW', jump => 'ACCEPT',
                proto => 'udp', dport => '137:138',
        }
        iptables {"$prio $name 02":
                chain => 'INPUT', state => 'NEW', jump => 'ACCEPT',
                proto => 'tcp', dport => ['139','445'],
        }
}


