package models

import (
	"time"
)

type Group struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    Roles       []string  `json:"roles"`
    CreatedAt   time.Time `json:"created_at"`
}

type GroupHierarchy struct {
    ParentGroupID string `json:"parent_group_id"`
    ChildGroupID  string `json:"child_group_id"`
    MinDepth      int    `json:"min_depth"`
} 