import unittest
from test_acceptance import PublishProtocol
suite=unittest.TestSuite(PublishProtocol(n) for n in ['test_short_reads_and_ack_order','test_cancel_write_pending_ack','test_cancel_close_pending_ack','test_response_lost_after_replace'])
r=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(not r.wasSuccessful())
