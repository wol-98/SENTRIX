
"""Expand SENTRIX incident management model.

Revision ID: 66e69db07b9e
Revises: 5d7a7fe36c15
"""

import uuid

from alembic import op
import sqlalchemy as sa


revision = "66e69db07b9e"
down_revision = "5d7a7fe36c15"
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns as nullable initially.
    with op.batch_alter_table("incidentlog") as batch_op:
        batch_op.add_column(
            sa.Column("incident_ref", sa.String(36), nullable=True)
        )
        batch_op.add_column(
            sa.Column("severity", sa.String(20), nullable=True)
        )
        batch_op.add_column(
            sa.Column("description", sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("updated_at", sa.DateTime(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("resolved_at", sa.DateTime(), nullable=True)
        )

    # Preserve historical severity and populate new fields.
    connection = op.get_bind()

    records = connection.execute(
        sa.text(
            "SELECT id, timestamp, status FROM incidentlog"
        )
    ).mappings().all()

    valid_severities = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    }

    for record in records:
        old_severity = (record["status"] or "MEDIUM").upper()

        if old_severity not in valid_severities:
            old_severity = "MEDIUM"

        connection.execute(
            sa.text("""
                UPDATE incidentlog
                SET incident_ref = :incident_ref,
                    severity = :severity,
                    status = 'OPEN',
                    updated_at = :updated_at
                WHERE id = :id
            """),
            {
                "incident_ref": str(uuid.uuid4()),
                "severity": old_severity,
                "updated_at": record["timestamp"],
                "id": record["id"]
            }
        )

    # Enforce constraints after historical records are populated.
    with op.batch_alter_table("incidentlog") as batch_op:
        batch_op.alter_column(
            "incident_ref",
            existing_type=sa.String(36),
            nullable=False
        )

        batch_op.alter_column(
            "severity",
            existing_type=sa.String(20),
            nullable=False
        )

        batch_op.alter_column(
            "updated_at",
            existing_type=sa.DateTime(),
            nullable=False
        )

        batch_op.create_unique_constraint(
            "uq_incidentlog_incident_ref",
            ["incident_ref"]
        )


def downgrade():
    with op.batch_alter_table("incidentlog") as batch_op:
        batch_op.drop_constraint(
            "uq_incidentlog_incident_ref",
            type_="unique"
        )

        batch_op.drop_column("resolved_at")
        batch_op.drop_column("updated_at")
        batch_op.drop_column("description")
        batch_op.drop_column("severity")
        batch_op.drop_column("incident_ref")
