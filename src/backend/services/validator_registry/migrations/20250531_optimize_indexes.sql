-- Add indexes for performance optimization

-- Index for faster lookups by validator_id in subnet_assignments
CREATE INDEX IF NOT EXISTS idx_subnet_assignments_validator_set_gin ON subnet_assignments USING GIN (validator_set);

-- Index for faster lookups by subnet_id in subnet_assignments
CREATE INDEX IF NOT EXISTS idx_subnet_assignments_subnet_id ON subnet_assignments (subnet_id);

-- Composite index for common query patterns
CREATE INDEX IF NOT EXISTS idx_subnet_assignments_epoch_subnet_id ON subnet_assignments (epoch, subnet_id);

-- Index for faster lookups in subnet_rotations by epoch
CREATE INDEX IF NOT EXISTS idx_subnet_rotations_epoch ON subnet_rotations (epoch);

-- Add index for validator_rewards by epoch and distributed status for faster reward processing
CREATE INDEX IF NOT EXISTS idx_validator_rewards_epoch_distributed ON validator_rewards (epoch, distributed);
