-- Create validators table
CREATE TABLE validators (
    validator_id BYTEA PRIMARY KEY,
    public_key BYTEA NOT NULL,
    escrow_address BYTEA NOT NULL,
    timelock_height INTEGER NOT NULL,
    status JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create subnet_assignments table
CREATE TABLE subnet_assignments (
    subnet_id INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    validator_set JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subnet_id, epoch)
);

-- Create subnet_rotations table
CREATE TABLE subnet_rotations (
    epoch INTEGER PRIMARY KEY,
    rotation_seed BYTEA NOT NULL,
    previous_assignments JSONB NOT NULL,
    new_assignments JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create validator_rewards table
CREATE TABLE validator_rewards (
    validator_id BYTEA NOT NULL,
    epoch INTEGER NOT NULL,
    amount BIGINT NOT NULL,
    performance_score INTEGER NOT NULL,
    distributed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (validator_id, epoch)
);

-- Create reward_distributions table
CREATE TABLE reward_distributions (
    epoch INTEGER PRIMARY KEY,
    total_reward BIGINT NOT NULL,
    distributions JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_validators_status ON validators USING GIN (status);
CREATE INDEX idx_subnet_assignments_epoch ON subnet_assignments (epoch);
CREATE INDEX idx_validator_rewards_distributed ON validator_rewards (distributed) WHERE NOT distributed;

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add updated_at triggers
CREATE TRIGGER update_validators_updated_at
    BEFORE UPDATE ON validators
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
