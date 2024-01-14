package dao

import (
	"context"
)

type Object interface{}

// Getter represents a resource getter.
type Getter interface {
	// Get return a given resource.
	Get(ctx context.Context, path string) (Object, error)
}

// Lister represents a resource lister.
type Lister interface {
	// List returns a resource collection.
	List(ctx context.Context) ([]Object, error)
}

type Accessor interface {
	Lister
	Getter
}
type Describer interface {
	// Describe describes a resource.
	Describe(path string) (string, error)
	Init(ctx context.Context)
	// ToYAML dumps a resource to YAML.
	// ToYAML(path string, showManaged bool) (string, error)
}
