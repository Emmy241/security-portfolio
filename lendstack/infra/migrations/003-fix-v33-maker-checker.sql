-- 003-fix-v33-maker-checker.sql
-- Fixes V-33: no maker-checker on transfer approval.
--
-- Before adding the CHECK constraint, existing self-approved transfers must
-- be remediated — otherwise the constraint fails to add.

BEGIN;

-- 1. Record the remediation in the audit log (preserve the fact of self-approval)
INSERT INTO audit_log (id, tenant_id, actor_id, action, target_type, target_id, metadata)
SELECT
  gen_random_uuid(),
  t.tenant_id,
  t.approved_by,
  'self_approval_remediated',
  'transfer',
  t.id,
  jsonb_build_object(
    'created_by', t.created_by,
    'approved_by', t.approved_by,
    'original_status', t.status,
    'reason', 'V-33 remediation — maker-checker constraint being applied'
  )
FROM transfers t
WHERE t.approved_by IS NOT NULL AND t.approved_by = t.created_by;

-- 2. Revert the self-approved transfers to a safe state
UPDATE transfers
SET approved_by = NULL,
    status = 'pending'
WHERE approved_by IS NOT NULL AND approved_by = created_by;

-- 3. Now the constraint can be safely added
ALTER TABLE transfers
  ADD CONSTRAINT transfers_no_self_approval
  CHECK (approved_by IS NULL OR approved_by != created_by);

COMMIT;
