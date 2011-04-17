  iptables { '000 allow packets with valid state':
    state       => ['RELATED,ESTABLISHED'],
    jump        => 'ACCEPT',
  }
  iptables { '001 allow icmp':
    proto       => 'icmp',
    jump        => 'ACCEPT',
  }
  iptables { '002 allow all to lo interface':
    iniface       => 'lo',
    jump        => 'ACCEPT',
  }
  iptables { '100 allow http':
    proto       => 'tcp',
    dport       => '80',
    jump        => 'ACCEPT',
  }
  iptables { '100 allow ssh':
    proto       => 'tcp',
    dport       => '22',
    jump        => 'ACCEPT',
  }
  iptables { '100 allow mysql from internal':
    proto       => 'tcp',
    dport       => '3036',
    source      => '10.5.5.0/24',
    jump        => 'ACCEPT',
  }
  iptables { '999 drop everything else':
    jump        => 'DROP',
  }

  resources { 'iptables':
    purge => true,
  }
