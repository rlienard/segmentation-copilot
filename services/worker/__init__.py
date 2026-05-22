"""Worker service — scheduler tick + flow-unknown consumer.

Single binary with two roles:

  worker      consumes events.flow.unknown → classifies → creates a
              proposal → publishes events.proposal.created. Horizontally
              scalable.
  scheduler   periodic baseline scan. Leader-elected via Redis so
              multiple replicas don't double-fire. Falls back to single
              process when the bus is in-memory.

Run:
  python -m services.worker.main --role worker
  python -m services.worker.main --role scheduler
"""
