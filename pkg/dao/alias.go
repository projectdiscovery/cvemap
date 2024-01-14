package dao

import (
	"context"
	"fmt"
	"sort"

	"github.com/projectdiscovery/cvemap/pkg/config"
	"github.com/projectdiscovery/cvemap/pkg/constant"
	"github.com/projectdiscovery/cvemap/pkg/render"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var _ Accessor = (*Alias)(nil)

// Alias tracks standard and custom command aliases.
type Alias struct {
	*config.Aliases
}

// NewAlias returns a new set of aliases.
func NewAlias() *Alias {
	a := Alias{Aliases: config.NewAliases()}

	return &a
}

// Check verifies an alias is defined for this command.
func (a *Alias) Check(cmd string) bool {
	_, ok := a.Aliases.Get(cmd)
	return ok
}

// List returns a collection of aliases.
func (a *Alias) List(ctx context.Context) ([]Object, error) {
	aa, ok := ctx.Value(constant.KeyAliases).(*Alias)
	if !ok {
		return nil, fmt.Errorf("expecting *Alias but got %T", ctx.Value(constant.KeyAliases))
	}
	m := aa.ShortNames()
	oo := make([]Object, 0, len(m))
	for res, aliases := range m {
		sort.StringSlice(aliases).Sort()
		oo = append(oo, render.AliasRes{Resource: res, Aliases: aliases})
	}

	return oo, nil
}

// AsResource returns a matching resource if it exists.
func (a *Alias) AsResource(cmd string) (string, bool) {
	res, ok := a.Aliases.Get(cmd)
	if ok {
		return res, true
	}
	return "", false
}

// Get fetch a resource.
func (a *Alias) Get(_ context.Context, _ string) (Object, error) {
	return nil, errorutil.New("NYI!!")
}

// Ensure makes sure alias are loaded.
func (a *Alias) Ensure(cloud string) (config.Alias, error) {

	return a.Alias, a.load(cloud)
}

func (a *Alias) load(cloud string) error {
	return a.Load(cloud)
}
