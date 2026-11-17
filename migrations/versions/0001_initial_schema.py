"""Create control-plane vault, epoch, recovery, trace, risk and audit tables."""

import sqlalchemy as sa
from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vaults",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active_epoch_id", sa.String(length=36), nullable=True),
    )
    op.create_table(
        "epochs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("vault_id", sa.String(length=36), sa.ForeignKey("vaults.id"), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("threshold", sa.Integer(), nullable=False),
        sa.Column("n", sa.Integer(), nullable=False),
        sa.Column("m0", sa.Text(), nullable=False),
        sa.Column("moduli_json", sa.Text(), nullable=False),
        sa.Column("a1", sa.Text(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("filename", sa.String(length=255), nullable=False),
        sa.Column("encryption_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_epochs_vault_id", "epochs", ["vault_id"])
    op.create_table(
        "recovery_requests",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("vault_id", sa.String(length=36), sa.ForeignKey("vaults.id"), nullable=False),
        sa.Column("epoch_id", sa.String(length=36), nullable=False),
        sa.Column("requested_by", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("required_shares", sa.Integer(), nullable=False),
        sa.Column("received_shares", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_recovery_requests_vault_id", "recovery_requests", ["vault_id"])
    op.create_table(
        "trace_cases",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("vault_id", sa.String(length=36), sa.ForeignKey("vaults.id"), nullable=False),
        sa.Column("epoch_id", sa.String(length=36), nullable=False),
        sa.Column("leaked_nodes_json", sa.Text(), nullable=False),
        sa.Column("identified_nodes_json", sa.Text(), nullable=False),
        sa.Column("proof_integer", sa.Text(), nullable=False),
        sa.Column("verified", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_trace_cases_vault_id", "trace_cases", ["vault_id"])
    op.create_table(
        "risk_events",
        sa.Column("event_id", sa.String(length=36), primary_key=True),
        sa.Column("node_id", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=50), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("critical", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_risk_events_node_id", "risk_events", ["node_id"])
    op.create_table(
        "audit_events",
        sa.Column("sequence", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(length=100), nullable=False),
        sa.Column("actor", sa.String(length=100), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(length=64), nullable=False),
        sa.Column("record_hash", sa.String(length=64), nullable=False, unique=True),
    )


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_index("ix_risk_events_node_id", table_name="risk_events")
    op.drop_table("risk_events")
    op.drop_index("ix_trace_cases_vault_id", table_name="trace_cases")
    op.drop_table("trace_cases")
    op.drop_index("ix_recovery_requests_vault_id", table_name="recovery_requests")
    op.drop_table("recovery_requests")
    op.drop_index("ix_epochs_vault_id", table_name="epochs")
    op.drop_table("epochs")
    op.drop_table("vaults")
