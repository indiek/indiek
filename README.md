# Philosophy
The durable thing is the signed append-only event history. Everything else should be rebuildable projections.
# Supported operatiosn for the event log
`create_node`
`create_edge`  
`supersede_node`  
`supersede_edge`  

# Architecture
1. The data is stored as content-addressed binary blobs. 
2. Each leaf data (blob) has an ID that is exactly its sha256 hash
3. The metadata is a signed append-only event log, which provides the ability to reconstruct the whole graph. Each event is signed.
4. Each node and edge in that graph has a UUID7 ID



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

