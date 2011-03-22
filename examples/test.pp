iptables {"000 allow foo":
  dport => "7070",
  jump => "ACCEPT",
}
