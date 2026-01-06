"""
Shared utility functions for the PACT API.
"""

from typing import Type, TypeVar, Optional
from sqlalchemy import select
from sqlalchemy.sql import Select

T = TypeVar("T")


def build_id_query(
    model: Type[T],
    id_value: str,
    slug_field: str = "system_id",
    include_deleted: bool = False,
) -> Select:
    """
    Build a SQLAlchemy query for lookup by numeric ID or string slug.
    
    Supports looking up entities by either:
    - Numeric database ID (e.g., "123")
    - String slug/identifier (e.g., "payment-gateway-prod")
    
    Args:
        model: SQLAlchemy model class
        id_value: The ID value (can be numeric string or slug)
        slug_field: The name of the slug field on the model
        include_deleted: If False, excludes soft-deleted records
        
    Returns:
        SQLAlchemy Select query
        
    Example:
        query = build_id_query(System, "payment-gateway-prod", "system_id")
        result = await db.execute(query)
        system = result.scalar_one_or_none()
    """
    query = select(model)
    
    # Exclude soft-deleted records unless explicitly requested
    if not include_deleted and hasattr(model, 'deleted_at'):
        query = query.where(model.deleted_at.is_(None))
    
    # Check if the ID is numeric (database primary key) or string slug
    if id_value.isdigit():
        query = query.where(model.id == int(id_value))
    else:
        query = query.where(getattr(model, slug_field) == id_value)
    
    return query


def apply_search_filter(query, count_query, search: Optional[str], *fields):
    """
    Apply ilike search filter to multiple fields.
    
    Args:
        query: The main SQLAlchemy query
        count_query: The count query for pagination
        search: The search term (can be None)
        *fields: SQLAlchemy column objects to search
        
    Returns:
        Tuple of (filtered_query, filtered_count_query)
        
    Example:
        query, count_query = apply_search_filter(
            query, count_query, search,
            User.email, User.full_name
        )
    """
    if not search or not fields:
        return query, count_query
    
    search_filter = f"%{search.lower()}%"
    
    # Build OR condition for all fields
    conditions = [field.ilike(search_filter) for field in fields]
    combined = conditions[0]
    for condition in conditions[1:]:
        combined = combined | condition
    
    return query.where(combined), count_query.where(combined)

