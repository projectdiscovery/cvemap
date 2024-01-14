package model

import (
	"github.com/projectdiscovery/cvemap/pkg/constant"
	"github.com/projectdiscovery/cvemap/pkg/dao"
	"github.com/projectdiscovery/cvemap/pkg/render"
)

var Registry = map[string]ResourceMeta{
	constant.LowercaseCvemap: {
		DAO:      &dao.Cvemap{},
		Renderer: &render.Cvemap{},
	},
}
