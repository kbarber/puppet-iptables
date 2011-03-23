iptables {"000 allow foo":
  dport => "7070",
  jump => "ACCEPT",
}
iptables {"001 allow boo":
  dport => "7071",
  jump => "ACCEPT",
}

