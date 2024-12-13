-- Gruppen-Tabelle
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Gruppen-Hierarchie
CREATE TABLE group_hierarchy (
    parent_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    child_group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (parent_group_id, child_group_id),
    CHECK (parent_group_id != child_group_id)
);

-- Gruppen-Rollen
CREATE TABLE group_roles (
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    role VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, role)
);

-- Benutzer-Gruppen-Zuordnung
CREATE TABLE user_groups (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, group_id)
);

-- Indizes für Performance
CREATE INDEX idx_group_hierarchy_child ON group_hierarchy(child_group_id);
CREATE INDEX idx_user_groups_group_id ON user_groups(group_id);
CREATE INDEX idx_group_roles_role ON group_roles(role);

-- Materialized View für schnellen Zugriff auf alle Gruppen-Hierarchien
CREATE MATERIALIZED VIEW group_hierarchy_complete AS
WITH RECURSIVE group_tree AS (
    -- Base case: direct relationships
    SELECT parent_group_id, child_group_id, 1 as depth
    FROM group_hierarchy
    
    UNION ALL
    
    -- Recursive case: find all descendants
    SELECT t.parent_group_id, h.child_group_id, t.depth + 1
    FROM group_tree t
    JOIN group_hierarchy h ON t.child_group_id = h.parent_group_id
)
SELECT DISTINCT parent_group_id, child_group_id, min(depth) as min_depth
FROM group_tree
GROUP BY parent_group_id, child_group_id;

-- Index auf die Materialized View
CREATE UNIQUE INDEX idx_group_hierarchy_complete 
ON group_hierarchy_complete(parent_group_id, child_group_id);

-- Funktion zum Aktualisieren der Materialized View
CREATE OR REPLACE FUNCTION refresh_group_hierarchy_complete()
RETURNS TRIGGER AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY group_hierarchy_complete;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger für automatische Aktualisierung
CREATE TRIGGER refresh_group_hierarchy
AFTER INSERT OR UPDATE OR DELETE ON group_hierarchy
FOR EACH STATEMENT
EXECUTE FUNCTION refresh_group_hierarchy_complete(); 