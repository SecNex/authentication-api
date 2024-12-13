package database

import (
	"database/sql"
	"log"
	"time"

	"github.com/secnex/authentication-api/models"
)

// Cache für Gruppen-Rollen mit TTL
type groupRoleCache struct {
    roles     map[string][]string // groupID -> roles
    timestamp time.Time
}

var (
    roleCache     = make(map[string]*groupRoleCache)
    cacheDuration = 5 * time.Minute
)

func init() {
    // Start cache cleanup routine
    go func() {
        ticker := time.NewTicker(10 * time.Minute)
        for range ticker.C {
            cleanupExpiredCache()
        }
    }()
}

func GetUserWithGroupRoles(db *sql.DB, userID string) (*models.User, error) {
    log.Printf("[DEBUG] Getting user with group roles for userID: %s", userID)
    
    var user models.User
    
    // Basis-User-Informationen abrufen
    err := db.QueryRow(`
        SELECT id, username, roles, created_at
        FROM users
        WHERE id = $1
    `, userID).Scan(&user.ID, &user.Username, &user.Roles, &user.CreatedAt)
    
    if err != nil {
        log.Printf("[ERROR] Failed to get base user info for userID %s: %v", userID, err)
        return nil, err
    }
    log.Printf("[DEBUG] Found base user: %s", user.Username)

    // Gruppen und deren Rollen aus dem Cache oder der DB laden
    roles, err := getUserGroupRoles(db, userID)
    if err != nil {
        log.Printf("[ERROR] Failed to get group roles for userID %s: %v", userID, err)
        return nil, err
    }
    log.Printf("[DEBUG] Retrieved %d group roles for user %s", len(roles), user.Username)

    // Rollen zusammenführen
    user.Roles = mergeRoles(user.Roles, roles)
    log.Printf("[INFO] User %s has total of %d roles after merging", user.Username, len(user.Roles))
    
    return &user, nil
}

func getUserGroupRoles(db *sql.DB, userID string) ([]string, error) {
    log.Printf("[DEBUG] Getting group roles for userID: %s", userID)

    // Prüfen ob Cache gültig
    if cache, exists := roleCache[userID]; exists {
        if time.Since(cache.timestamp) < cacheDuration {
            log.Printf("[DEBUG] Using cached roles for userID %s", userID)
            return flattenRoles(cache.roles), nil
        }
        log.Printf("[DEBUG] Cache expired for userID %s", userID)
    }

    // Alle Gruppen des Users inkl. übergeordneter Gruppen laden
    rows, err := db.Query(`
        WITH user_groups_complete AS (
            -- Direkte Gruppen des Users
            SELECT DISTINCT g.id, g.name
            FROM groups g
            JOIN user_groups ug ON g.id = ug.group_id
            WHERE ug.user_id = $1
            
            UNION
            
            -- Übergeordnete Gruppen über die Hierarchie
            SELECT DISTINCT g.id, g.name
            FROM groups g
            JOIN group_hierarchy_complete ghc ON g.id = ghc.parent_group_id
            JOIN user_groups ug ON ghc.child_group_id = ug.group_id
            WHERE ug.user_id = $1
        )
        SELECT ugc.id, gr.role
        FROM user_groups_complete ugc
        LEFT JOIN group_roles gr ON ugc.id = gr.group_id
    `, userID)
    
    if err != nil {
        log.Printf("[ERROR] Failed to query group roles: %v", err)
        return nil, err
    }
    defer rows.Close()

    // Rollen nach Gruppen gruppieren
    groupRoles := make(map[string][]string)
    groupCount := 0
    roleCount := 0
    
    for rows.Next() {
        var groupID, role string
        if err := rows.Scan(&groupID, &role); err != nil {
            log.Printf("[ERROR] Failed to scan group role row: %v", err)
            return nil, err
        }
        groupRoles[groupID] = append(groupRoles[groupID], role)
        groupCount++
        roleCount++
    }

    log.Printf("[INFO] Found %d roles from %d groups for userID %s", roleCount, groupCount, userID)

    // Cache aktualisieren
    roleCache[userID] = &groupRoleCache{
        roles:     groupRoles,
        timestamp: time.Now(),
    }
    log.Printf("[DEBUG] Updated role cache for userID %s", userID)

    return flattenRoles(groupRoles), nil
}

// Hilfsfunktionen
func mergeRoles(userRoles, groupRoles []string) []string {
    log.Printf("[DEBUG] Merging %d user roles with %d group roles", len(userRoles), len(groupRoles))
    
    roleMap := make(map[string]bool)
    duplicateCount := 0
    
    // Direkte Rollen hinzufügen
    for _, role := range userRoles {
        roleMap[role] = true
    }
    
    // Gruppen-Rollen hinzufügen
    for _, role := range groupRoles {
        if _, exists := roleMap[role]; exists {
            duplicateCount++
        }
        roleMap[role] = true
    }
    
    // Zu Array konvertieren
    result := make([]string, 0, len(roleMap))
    for role := range roleMap {
        result = append(result, role)
    }
    
    log.Printf("[DEBUG] Merged roles: total=%d, duplicates=%d", len(result), duplicateCount)
    return result
}

func flattenRoles(groupRoles map[string][]string) []string {
	log.Printf("[DEBUG] Flattening roles from %d groups", len(groupRoles))

    roleMap := make(map[string]bool)
    totalRoles := 0
    
    for groupID, roles := range groupRoles {
        log.Printf("[DEBUG] Processing %d roles from group %s", len(roles), groupID)
        for _, role := range roles {
            roleMap[role] = true
            totalRoles++
        }
    }
    
    result := make([]string, 0, len(roleMap))
    for role := range roleMap {
        result = append(result, role)
    }
    
    log.Printf("[DEBUG] Flattened %d total roles to %d unique roles", totalRoles, len(result))
    return result
}

// Cache cleanup function
func cleanupExpiredCache() {
    log.Printf("[DEBUG] Starting cache cleanup")
    count := 0
    
    for userID, cache := range roleCache {
        if time.Since(cache.timestamp) > cacheDuration {
            delete(roleCache, userID)
            count++
        }
    }
    
    log.Printf("[INFO] Cleaned up %d expired cache entries", count)
} 