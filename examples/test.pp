iptables { '000 allow foo':
  dport => "7061",
  jump => "ACCEPT",
  proto => "tcp",
}
iptables { '001 allow boo':
  jump => "ACCEPT",
  iniface => "eth0",
  sport => "123",
  dport => "123",
  proto => "tcp",
  destination => "1.1.1.1/24",
  source => "2.2.2.2/24",
}
iptables { '002 foo':
  dport => "1233",
  proto => "tcp",
  jump => "DROP",
}
iptables { '999 bar':
  dport => "1233",
  proto => "tcp",
  jump => "DROP",
}

resources { 'iptables':
  purge => true
}

