/**
 * IANA IP protocol numbers for the Flows protocol filter — a comprehensive,
 * practical set. Searchable by name or number via SearchableSelect. `value` is
 * the protocol number as a string ("" = any).
 */
export interface ProtocolOption {
  value: string;
  label: string;
}

export const PROTOCOLS: ProtocolOption[] = [
  { value: "", label: "Any protocol" },
  { value: "0", label: "HOPOPT (0)" },
  { value: "1", label: "ICMP (1)" },
  { value: "2", label: "IGMP (2)" },
  { value: "3", label: "GGP (3)" },
  { value: "4", label: "IPv4 encapsulation (4)" },
  { value: "5", label: "ST (5)" },
  { value: "6", label: "TCP (6)" },
  { value: "8", label: "EGP (8)" },
  { value: "9", label: "IGP (9)" },
  { value: "17", label: "UDP (17)" },
  { value: "27", label: "RDP (27)" },
  { value: "33", label: "DCCP (33)" },
  { value: "41", label: "IPv6 encapsulation (41)" },
  { value: "43", label: "IPv6-Route (43)" },
  { value: "44", label: "IPv6-Frag (44)" },
  { value: "46", label: "RSVP (46)" },
  { value: "47", label: "GRE (47)" },
  { value: "50", label: "ESP (50)" },
  { value: "51", label: "AH (51)" },
  { value: "58", label: "ICMPv6 (58)" },
  { value: "59", label: "IPv6-NoNxt (59)" },
  { value: "60", label: "IPv6-Opts (60)" },
  { value: "88", label: "EIGRP (88)" },
  { value: "89", label: "OSPF (89)" },
  { value: "94", label: "IP-in-IP (94)" },
  { value: "97", label: "EtherIP (97)" },
  { value: "103", label: "PIM (103)" },
  { value: "108", label: "IPComp (108)" },
  { value: "112", label: "VRRP (112)" },
  { value: "115", label: "L2TP (115)" },
  { value: "124", label: "IS-IS (124)" },
  { value: "132", label: "SCTP (132)" },
  { value: "133", label: "Fibre Channel (133)" },
  { value: "136", label: "UDP-Lite (136)" },
  { value: "137", label: "MPLS-in-IP (137)" },
  { value: "139", label: "HIP (139)" },
  { value: "140", label: "Shim6 (140)" },
  { value: "143", label: "Ethernet (143)" },
];
