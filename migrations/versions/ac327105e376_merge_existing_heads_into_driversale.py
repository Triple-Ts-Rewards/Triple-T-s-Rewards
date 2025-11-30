"""merge existing heads into DriverSale

Revision ID: ac327105e376
Revises: 9dab76c76015, bc4e2b6d78fe, fbe7c4b4278f
Create Date: 2025-11-28 22:06:53.273086

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ac327105e376'
down_revision = ('9dab76c76015', 'bc4e2b6d78fe', 'fbe7c4b4278f')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
