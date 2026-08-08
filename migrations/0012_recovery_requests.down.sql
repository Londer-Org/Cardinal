-- Reverses 0012_recovery_requests.sql.
--
-- Open recovery requests and the approvals against them are lost. Dual control
-- means a request in flight had one approval and needed another (ADR 0015), so
-- the cost is starting it again rather than anything being weakened.
DROP TABLE IF EXISTS recovery_approvals;
DROP TABLE IF EXISTS recovery_requests;
