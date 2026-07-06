# Philosophy
The durable thing is the signed append-only event history (the event log) and the blob store. The event log and the blob store together is what I call the archive. Everything else should be rebuildable projections.
# Supported operatiosn for the event log
`create_node`
`create_edge`  

# Architecture
1. The data is stored as content-addressed binary blobs. 
2. Each data associated to either a node or an edge is called a blob and has an ID that is exactly its sha256 hash
3. The metadata is a signed append-only event log, which provides the ability to reconstruct the whole graph. Each event is signed.
4. Each node and edge in that graph has a UUID7 ID (this is not the blob hash)



# Modules import hierarchy
Module A
  Module B
means that A imports B

events
  blob
    signing
      models
    models
  signing
    models
  models

