// 04: credential-file forward-trace (data-flow detection primitive)
//
// "Did any process read a credential-shaped path?" If yes, what's
// the rest of that process's behavior? This is the canonical
// detection query the richer graph enables — without File vertices
// it would be a multi-step manual scan.
//
// Strategy: identify candidate credential paths, find readers, then
// for each reader collect all later writes and network activity.
// Empty result = no credential touches in this graph (good).

MATCH (f:File)-[:read]-(p:Process)
WHERE f.path =~ '.*\\.aws/.*'
   OR f.path =~ '.*\\.ssh/.*'
   OR f.path =~ '.*\\.gnupg/.*'
   OR f.path =~ '.*\\.netrc.*'
   OR f.path =~ '.*\\.pgpass.*'
   OR f.path =~ '.*credentials.*'
   OR f.path =~ '.*id_rsa.*'
   OR f.path =~ '.*\\.kube/.*'
WITH p, collect(DISTINCT f.path) AS read_creds
OPTIONAL MATCH (p)-[:write]->(f2:File)
WITH p, read_creds, collect(DISTINCT f2.path) AS later_writes
OPTIONAL MATCH (p)-[:connect]->(sk:Socket)
WITH p, read_creds, later_writes,
     collect(DISTINCT sk.daddr) AS connected_to
OPTIONAL MATCH (p)-[:send]->(sk2:Socket)
RETURN p.pid           AS pid,
       p.first_comm    AS comm,
       read_creds,
       later_writes,
       connected_to,
       collect(DISTINCT sk2.daddr) AS sent_to;
