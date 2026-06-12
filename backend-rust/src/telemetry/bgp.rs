//! BGP feed view: current announcement state per protected prefix
//! (announced/withdrawn, next-hop, communities). This is what reroute
//! verification reads to confirm a blackhole/withdraw/divert took effect.
//! See ../skills/bgp-reroute-safety.md.

// TODO(milestone 1): maintain a prefix -> announcement-state map from the speaker.
