#iptables {"000 allow foo":
#  dport => "7070",
#  jump => "ACCEPT",
#  log_level => "WARN",
#}
iptables {"001 allow boo":
  jump => "ACCEPT",
  iniface => "eth0",
  sport => "123",
  dport => "123",
  proto => "tcp",
  destination => "1.1.1.1/24",
  source => "2.2.2.2/24",
}

