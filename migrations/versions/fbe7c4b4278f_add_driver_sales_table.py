"""Add DriverSale table

Revision ID: fbe7c4b4278f
Revises: 7a9e3b5c2d1f
Create Date: 2025-11-28 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'fbe7c4b4278f'
down_revision = '7a9e3b5c2d1f'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'DRIVER_SALES',
        sa.Column('SALE_ID', sa.Integer(), primary_key=True, autoincrement=True, nullable=False),
        sa.Column('DRIVER_ID', sa.Integer(), nullable=False),
        sa.Column('ORG_ID', sa.Integer(), nullable=False),
        sa.Column('POINTS_SPENT', sa.Integer(), nullable=False),
        sa.Column('ITEM_COUNT', sa.Integer(), nullable=False),
        sa.Column('DETAILS', sa.Text(), nullable=True),
        sa.Column('CREATED_AT', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['DRIVER_ID'], ['USERS.USER_CODE']),
        sa.ForeignKeyConstraint(['ORG_ID'], ['ORGANIZATIONS.ORG_ID'])
    )
    op.create_index('ix_driver_sales_driver_id', 'DRIVER_SALES', ['DRIVER_ID'])
    op.create_index('ix_driver_sales_org_id', 'DRIVER_SALES', ['ORG_ID'])
    op.create_index('ix_driver_sales_created_at', 'DRIVER_SALES', ['CREATED_AT'])


def downgrade():
    op.drop_index('ix_driver_sales_created_at', table_name='DRIVER_SALES')
    op.drop_index('ix_driver_sales_org_id', table_name='DRIVER_SALES')
    op.drop_index('ix_driver_sales_driver_id', table_name='DRIVER_SALES')
    op.drop_table('DRIVER_SALES')
