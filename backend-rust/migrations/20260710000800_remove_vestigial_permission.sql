-- The old provider-era approval flow was removed from every API and from the
-- typed Permission enum. Remove the inert seed so the database vocabulary no
-- longer suggests a security gate that does not exist.

DELETE FROM permissions WHERE name = 'approve_dangerous_reroute';
