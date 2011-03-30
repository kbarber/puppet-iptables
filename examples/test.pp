iptables { '000 allow foo':
  dport => "7070",
  jump => "ACCEPT",
}
iptables { '001 allow boo':
  jump => "ACCEPT",
  iniface => "eth0",
  sport => "123",
  dport => "123",
  proto => "tcp",
  destination => "1.1.1.1/24",
  source => "2.2.2.2/24",
  ensure => absent,
}
iptables { '002 foo':
  dport => "1233",
  jump => "DROP",
}

resources { 'iptables':
  purge => true
}

